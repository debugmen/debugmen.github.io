---
layout: post
author: Etch
title:  "Enabot Hacking: Part 2"
date:   2022-02-18 1:01:37 -0500
categories: Hardware-series
ctf-category: PWN
tags: etch hardware IoT re enabot
---
# Enabot Hacking: Part 1 -> Vulnerability Research
- [Enabot Hacking: Part 1 -> Vulnerability Research](#enabot-hacking-part-1---vulnerability-research)
  - [Introduction](#introduction)
- [Packet Analysis](#packet-analysis)
  - [Software debugging](#software-debugging)
  - [Bypassing the watchdog](#bypassing-the-watchdog)

## Introduction
Last post I covered the teardown and firmware extraction of the enabot. In this post I plan to begin the vulnerability research where I look for ways to break in. Hopefully this post ends with me beginning to develop an exploit.

# Packet Analysis
I'm hoping that there is a vulnerability in the basic ways this thing communicates with its raw api. Maybe there is a parsing bug or buffer overflow if we send some ridiculous packet.

I opened up wireshark and began looking at the stream of packets as I moved the ebo around. I was only seeing UDP packets and they all seemed to be encrypted in some way.

After looking at the data of some of the packets, I noticed this one.

![charlie](/assets/enabot_part2/charlie_capture.png)

At the end of the packet it say "Charlie is". There is no way this is some coincidence of randomly generated data. There is probably some XOR encryption going on and those bytes were null bytes. I opened up the firmware in wireshark and checked if there were any strings with "Charlie is".

![charlie_p2p](/assets/enabot_part2/charlie_is_the_designer_of_p2p.png)

There it is. "Charlie is the designer of P2P!!". I figured whoever made this firmware probably didn't write that string, so I looked around to see if people had run into it before. 

I was able to find these posts
https://www.thirtythreeforty.net/posts/2020/05/hacking-reolink-cameras-for-fun-and-profit/
https://www.ul.com/resources/privacy-risk-iot-cctv-camera-security

After reading through them it turns out the function is XORing the packet with the charlie string, and then scrambling it, although it doesn't appear to be scrambled in the packet I just saw. I tried the same thing they mention in the 2nd post where they found the .so file and used the function in it to descramble it, but the packet still just looked like random garbage.

<details open>
<summary>Code that uses the descramble function</summary>

```C
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>



int main(){
    unsigned char input[115] = {
        "Packet bytes go here"
    };
    int output[150] = {0};
    char *input_ptr = malloc(sizeof(input));
    char *output_ptr = malloc(sizeof(output));
    for (int i=0; i<sizeof(input); i++){
        *(input_ptr+i) = input[i];
    }
    int *imglib;
    int (*ReverseTransCodePartial)(void *input, void *output, unsigned short length_bytes, unsigned short max_length_bytes);
    int imghandle;
    imglib = dlopen("./libIOTCAPIs.so", RTLD_LAZY);
    printf("Opened imglib: %x\n", *imglib);
    if (imglib != NULL) {
        *(void **)(&ReverseTransCodePartial) = dlsym(imglib, "ReverseTransCodePartial");
        ReverseTransCodePartial(input_ptr, output_ptr, 115, 115);
        printf("Ran decoding function\n");
    } else {
        printf("Didn't work\n");
    }
    const char filename[] = "decoded.bin";
    const char filename2[] = "encoded.bin";
    FILE *decoded;
    FILE *encoded;

    decoded = fopen(filename, "w");
    fwrite(&output_ptr, 1, sizeof(output), decoded);
    encoded = fopen(filename2, "w");
    fwrite(&input_ptr, 1, sizeof(input), encoded);

    free(input_ptr);
    free(output_ptr);

}
```

</details>

## Software debugging

In the last post I mentioned hardware debugging, but Lain3d reminded me there was also another option which is software debugging. We have a shell so if we can find a binary of gdbserver that runs on the device, we can attach the firmware to it and debug it. Then we can simply break at the start of the charlie_scramble function and check argument 1 to see the packet before it gets XORed and/or scrambled.

Playoff-rondo sent me a repo of statically compiled gdbservers, and I found that the ```gdbserver-7.7.1-armel-eabi5-v1-sysv``` worked on the device since it was armv5t.

I netcated the file to the device. Most of the device was readonly so we couldn't move the file, but because there is a place for the SD card, we can put the file there.

On enabot ssh shell
 * nc -l -p 1234 > gdbserver

On my PC
 * nc -w 3 X.X.X.X 1234 < gdbserver-7.7.1-armel-eabi5-v1-sysv

Now that we have the file, we can attach it to the FW_ENABOT_C process and start debugging. The process ID was 541

```
./gdbserver --attach X.X.X.X:5555 541
```

Then in gdb-multiarch, I can simply do 

```
target remote X.X.X.X 5555
```

It loads some symbols and other stuff, but after a bit, we are in the debugger! Or at least for a few seconds....

## Bypassing the watchdog

It turns out this firmware uses a watchdog, and the timer is set to about 10 seconds. Every few seconds the firmware will reach out to the watchdog and say that it's doing okay, but when I'm debugging it, the process is halted. Because the watchdog doesn't get it's okay message, it restarts the device.

I spent a lot of time trying to get around this. I tried disabling the kernel watchdogs with ```sysctl```, I tried writing "V" to /dev/watchdog, but the file was busy, and a few other things that came up in google searches, but none of it worked.

I figured since the firmware would open the file and store the file pointer in memory somewhere. If I could just use that file pointer in another process, maybe I could write the "V" character which supposedly disables the watchdog timer.

In ghidra I found where it opened the watchdog file
![activate_watchdog](/assets/enabot_part2/actiavate_watchdog.png)

I see it stores the pointer at 0x00499dcc. When I look at the XREFs of that pointer, I came across another function.

![set_timeout](/assets/enabot_part2/set_timeout.png)

Looks like I can just use this function. If we act quickly enough into the debugger, we can save all the registers, set the argument of this function to some really large number, execute it, and then restore the registers to go back to normal execution.

I did some more research and figured out the ioctl function is what really writes to the file. Looking at the kernel watchdog code and comparing it to the enabot value it sends to IOCTL, it looks like the last digit of the 0xc0045706 controls what functionality it does (the activate and write values in the other functions also lined up).

https://www.kernel.org/doc/Documentation/watchdog/watchdog-api.txt
![watchdog_header](/assets/enabot_part2/watchdog_header.png)
 "6" is for setting the watchdog timeout. I tried modifying that value to "4" for the set options functionality and then using the disable card option to disable the watchdog timer, but couldn't get it to work. The device was still restarting.

Setting the registers every time I wanted to debug was tedious, so wrote a gdb script to automate the entire process of attching the debugger, setting the registers, and returning back.

<details>
<summary>Python gdb script</summary>

```python
import os
import signal
import time
import paramiko
import gdb
import argparse
import sys

SET_WATCHDOG_TIMEOUT_START=0x000f3e6c
SET_WATCHDOG_TIMEOUT_END=0x000f3e94
WATCHDOG_VALUE_POINTER=0x000710f8 #Set to 0xFFFFFFFF

def attach_gdb_server(remote_ip, host_ip, ssh_pass):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("Waiting for target's SSH to go up")
    ssh.connect(hostname=remote_ip, port=22, username='root', password=ssh_pass)
    print("Connected to target over ssh")
    stdin, stdout, stderr = ssh.exec_command('ps')
    lines = stdout.readlines()
    for line in lines:
        if "FW_EBO_C" in line:
            pid = line.split()[0]
            print(f'Found FW_EBO_C pid: {pid}')
    print(f"Attaching FW_EBO_C({pid}) to gdbserver")
    ssh.exec_command(f"/var/avi/mmc0/DICM/gdbserver --attach {host_ip}:5555 {pid}")
    ssh.exec_command('sysctl -w "kernel.watchdog=0"')
    ssh.exec_command('sysctl -w "kernel.nmi_watchdog=0"')
    ssh.exec_command('sysctl -w "kernel.soft_watchdog=0"')
    line = stderr.readline()
    if "Address already in use" in line:
        print("GDB already set on device")
    ssh.close()
    print("Debugger attached")
    return 

def bypass_watchdog(remote_ip):
    print("Connecting to remote target")
    value = gdb.execute(f"target remote {remote_ip}:5555")
    registers = dict.fromkeys(["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"], None)
    print(registers)
    print("Continuing execution")
    for register in registers:
        value = gdb.parse_and_eval(f"${register}")
        registers[register] = value
        print(f'Saved register {register} with value {value}')
    
    # TESTING DISABLE ################
    # Can't get this to work. Maybe they didn't include it?
    # print("Disabling the watchdog timer")
    # gdb.execute(f'set $pc = {SET_WATCHDOG_TIMEOUT_START}')
    # gdb.execute('set $r0 = 0x1')
    # gdb.execute('set $r1 = 0x80045704')
    # gdb.execute('set $r2 = 0x00347914')
    # gdb.execute('break *0x000f3e8e')

    # THIS WORKS #################
    print('Calling "watchdog_set_timeout(0xFFFFFFFF)"')
    gdb.execute(f'set $r0 = {WATCHDOG_VALUE_POINTER}')
    gdb.execute(f'set $pc = {SET_WATCHDOG_TIMEOUT_START}')
    gdb.execute(f'break *{SET_WATCHDOG_TIMEOUT_END}')
    ################
    gdb.execute('c')
    print("Restoring context")
    for register in registers:
        gdb.execute(f'set ${register} = {registers[register]}')
        print(f"Restoring register {register} with value {hex(registers[register])}")
    print("Breaking at charlie_scramble()")
    gdb.execute("break *0x00149b0c")
    gdb.execute("c")

def main():
    remote_ip = arg0
    host_ip = arg1
    ssh_pass = arg2

    attach_gdb_server(remote_ip, host_ip, ssh_pass)
    bypass_watchdog(remote_ip)

if __name__ == '__main__':
    main()
```

</details>
<br>
This is used in conjunction with a bash script because sending arguments to a gdb script inside of gdb isn't a thing apparently.

<details>
<summary>Bash script for debugging</summary>

```bash
#!/usr/bin/env bash
doc="
./debug.sh gdb_debug_script.py 'target_ip' 'host_ip' 'ssh_password'
"

py="$1"
shift
cli=''
temp=''
i=0
for arg in "$@"; do
  temp="$arg"
  cli="$cli -ex 'py arg$i = \"$temp\"'"
  echo $cli
  echo $i
  i=$(($i+1))
done
echo "Calling gdb"
echo "gdb $cli -x '$py FW_EBO_C'"
eval gdb-multiarch  $cli -x "$py " "FW_EBO_C"
```
</details>
<br>

Now if I run the bash script, it'll do the following
1. SSH into device and attach gdbserver to the FW_EBO_C PID shown in the ```ps``` command to my host ip on port
2. Close the SSH connection
3. Open gdb and target remote to the device
4. Save all the registers at the breakpoint
5. Set r0 to an address where the value is 0xFFFFFFFF
6. Set a breakpoint at the end of the set_watchdog_timeout function and then set the PC register to the starting address of it
7. Continue until it hits that breakpoint
8. Restore the registers, and then break at the first instance of the charlie_scramble function

After doing this it works! Mostly... The device will still restart after about 5-10 minutes, but it's a long enough window to comfortably debug something as simple as this. If it really becomes an issue I could look more into the disable watchdog command or make a script to automatically ping the watchdog every so often.

Back to the packet analysis. So after hitting the breakpoint at the beginning of the charlie scramble function, I dumped out the bytes of the input packet to be scrambled, set a breakpoint at the end of the function, and dumped the bytes of the scrambled output bytes when it got there. Then I continued and watched the packet appear in wireshark after setting the filter to be only udp packets.

>Before scramble
![before_scramble](/assets/enabot_part2/scramble_start.png)
>After scramble
![after_scramble](/assets/enabot_part2/scramble_after.png)
>Wireshark scramble capture
![wireshark_scramble](/assets/enabot_part2/wireshark_capture_scramble.png)

If you compare the bytes at the bottom of the after scramble image and the wireshark image, you'll see that they match. This means we can successfully capture the packet before it gets encrypted. Now the only issue is the decrypted bytes still don't mean anything. I was hoping they'd be in some simple format like JSON or something, but they're completely random bytes. Maybe this is only for raw video data and if I capture a packet of the device moving forward, it'll be in a better format.