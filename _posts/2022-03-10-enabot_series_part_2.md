---
layout: post
author: Etch
title:  "Enabot Hacking: Part 2"
date:   2022-02-18 1:01:37 -0500
categories: Hardware-series
ctf-category: PWN
tags: etch  lain3d hardware IoT re enabot
---
# Enabot Hacking: Part 1 -> Vulnerability Research
- [Enabot Hacking: Part 1 -> Vulnerability Research](#enabot-hacking-part-1---vulnerability-research)
  - [Introduction](#introduction)
- [Packet Analysis](#packet-analysis)
  - [Software debugging](#software-debugging)
  - [Bypassing the watchdog](#bypassing-the-watchdog)
- [Video Packets](#video-packets)
- [Audio Packets](#audio-packets)
- [Mic Packets](#mic-packets)
- [](#)

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


```
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
<pre>
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
</pre>

</details>
<br>
This is used in conjunction with a bash script because sending arguments to a gdb script inside of gdb isn't a thing apparently.

<details>
<summary>Bash script for debugging</summary>

<pre>
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

</pre>

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

Before scramble
![before_scramble](/assets/enabot_part2/scramble_start.png)
After scramble
![after_scramble](/assets/enabot_part2/scramble_after.png)
Wireshark scramble capture
![wireshark_scramble](/assets/enabot_part2/wireshark_capture_scramble.png)

If you compare the bytes at the bottom of the after scramble image and the wireshark image, you'll see that they match. This means we can successfully capture the packet before it gets encrypted. Now the only issue is the decrypted bytes still don't mean anything. I was hoping they'd be in some simple format like JSON or something, but they're completely random bytes. Maybe this is only for raw video data and if I capture a packet of the device moving forward, it'll be in a better format.

# Probably don't wanna keep all of the gdb stuff above, but some of it for the process

# Packet Reversing

Reversing what these packets were doing was very tedious, but we managed to do it. Every type of packet has its own components which track sequences numbers, branches in the code, tokens, etc. This was figured out by staring at wireshark and the decompilation. Explaining these all at once doesn't seem possible, so the best way is probably to just go through a branch of the ebo protocol and explain each field. Then the important parts of meaningful packets can be explained.



Note: Since we don't actually know what each branch was when we started reversing. Alot of these types may not have the best names, but they aren't really worth changing till we're sure what they are if that ever happens.



Every packet going to or from the device started with a message header. 
## Ebo Message Header

![MsgHdr](/assets/enabot_part2/ebo_msg_hdr.png)

<img src="/assets/enabot_part2/ebo_packet_type.png" alt="Ebo Packet Type" style="height: 100px; width:320px;"/>


1. The first two bytes are always `0x0402`
2. The second two bytes determine whether it's a connection, control , or status packet. Control packets allow the device it's communicating with to actually control the state of the device so control packets are sent from the host device. Connection packets are for devices connecting to the ebo. Status packets are sent from the ebo to connected devices to update the status of itself or send data.
    * The `ConditionalField`'s determine what the next portion of the packet would be compared to the values in the `EboPacketType` enum
3. Length1 is the length ebo protocol portion of the packet minus 16
    * Example: Motor packets are total length 115, their ebo protocol portion (UDP data portion) is 73. 73 - 16 = 0x39 so the value in the packet would be 0x3900 (little endian)
    * Note: All the fields are little endian, but we didn't mark them all as such because it didn't matter for a lot of them.

## Ebo Control Packets

Almost all packets are control packets whether sent from the ebo or from the host.

![EboControl](/assets/enabot_part2/ebo_control_packets.png)

1. `seq_no`: The first two bytes are the sequence number of the control packets. As each control packet is sent to the device, this value is incremented by 1.
2. `fixed0 + fixed1`: The next two values are always fixed as `0x07042100`
3. `session_token`: Just a value sent by the host device initially that is included all the packets as some form of validation. After the connection is made the ebo will only accept packets with that same value. We always use the same value when we connect.
4. `unk_bitfield`: An unknown field that is always either `0x0000` if sent from the ebo or `0x0100` if sent from the host
5. `fixed2`: Another fixed value that's always `0x0c000000`
6. `session_token2`: Another instance of the agreed upon value
7. `fixed3`: Another fixed value of `0x0002`
8. `handshake`: This value is similar to the `session_token` value. It's just an agreed upon value that is sent from the host as validation that the packet originates from the same place after the connection is established. All control packets have to have the correct handshake to be accepted by the ebo after the connection is made.
9. `branch1`: This is the first big branch in the packet types. It gets split up into different various things 

## More of the Same

That really covers the basics of how these packets are layed out. Every path taken will just have more of the same with random fixed values, branch values, sequence numbers, etc. Now that there is a basic understanding of what these packets are doing, it'll be easier to explain the packets we actually care about. First we'll talk about the tooling we developed so that it can be referenced and understood as the packets below are explained. Keep in mind we developed these tools as we went.
# Motor Packets

Below are two motor packet which will be referenced in this section for comparison

![Motor1](/assets/enabot_part2/motor1.png)


![Motor2](/assets/enabot_part2/motor2.png)

Some things mentioned in the packet section above should stand out like the sequence numbers increasing, the fixed values, and the token/handshake values. But other than that, how do we know this is a motor packet? The most telling thing is that it's length 115 (we can see that in wireshark, we don't expect you to count them). We setup wireshark, and started moving the ebo. When we did that we noticed packets of length 115 came through. When we stopped moving the ebo, they stopped appearing. 

## Button Packet Branches

After staring at packets long enough and pressing enough buttons, we could tell that the value `0xbeca` was somehow controlling the branch of what buttons we pressed because the `0xca` byte would change depending on what button. THEN we noticed that some of the buttons would have ANOTHER branch value immediately after that. Below is a packet of a pressed button, and we'll go through the decompiled code using the branch values to figure out which button was pressed.

![TrickA](/assets/enabot_part2/trick_a.png)

At 0x5e we see the value `0xbec8`. Now that 0xbe seems to always be constant, but the 0xc8 changes depending on what we press. We can see some of the branches based off that value below in the decompilation of the firmware.

![ButtonBranch1](/assets/enabot_part2/button_branch1.png)

 ```C
 if (mode??? != 0xd7 && mode??? == 0xc8)
 ```
Shows that when that value is 0xc8 we take that branch and we enter the `enterSelfCheckingMode` function. A little bit further down though we see
```C
if (mode??? == 0x2d)
```
This is another branch that is taken when you start recording a video. When we press the record button in the app we could find a packet with the value `0x2d` at that spot and we'd know it's a packet to start recording.

So let's enter the `enterSelfCheckingMode` function, to then see the branches that can be taken inside of there...

![SelfCheck](/assets/enabot_part2/enter_self_checking_mode.png)

Now we see evern more branch values, and if we compare them to the packet above, the `0x9cb3` branch value will stick out. Remember the value is little endian, so even though it's `0xb39c` in the packet, when the code gets it, it interprets it as `0x9cb3`. If the value `0x9ca8` it would be a `forceEnterLowPowerMode` packet based off of the strings.

So based off the string `MAV_CMD_CONTROL_SKILL_A` we know it was a "skill button". The ebo has various buttons that make it do random stuff like spin, or shake. This string let's us know those buttons are referred to as skills and can be easily identified now.

Now that we undestand the branch values of these types of packets, it should be easy to just go into the decompilation and see what the motor packets are doing if we find the right branch where it's value is `0xca`!

![MotorBinja](/assets/enabot_part2/motor_packet.png)

*If only.* More often then not we'd go to a function which had our branch and we would have no clue what it was doing, at all... We know it takes this branch because of the `0xca` but the function it goes into seems to just unlock and lock some threads. 

This shows how tedious and hard decoding some of these packets was. This one packet alone pretty much had 4 branch values up to this point, and it felt like each branch value had multiple functions which handled them. We'd find a few branch values of one branch in one function and a few others of the same branch in another.

This is why we spent so much time in wireshark. As much fun as reversing code is, sometimes there are just better ways to do reversing. This packet was much easier to figure out by just trial and error.

In the two motor packets we see 8 bytes in the last full row of bytes. The packets have different values. We figured that since we knew all other parts of the packet, those values must control the direction and speed. So we setup a test.

A capture was started, then the ebo was only moved forward, the capture was stopped, and a new capture was made only moving backwards, etc. until we had all 4 directions.

Then we compared the bytes of the packets and after a little testing using the ebo_server motor functionality and adjusting values in the motor packets slightly, it was easy to figure out what was happening. Keep your focused on the 0x60 lines in the following packets and try to spot the patterns.

Forward


![forward](/assets/enabot_part2/forward.png)

Backward


![backward](/assets/enabot_part2/backward.png)

Left


![forward](/assets/enabot_part2/left.png)

Right


![right](/assets/enabot_part2/right.png)


The first four bytes were for forward and backward movement. We still don't know what they first two bytes do, they didn't seem to affect anything, but the next byte controlled the speed where 0 was the slowest, and the byte after that controlled the direction. `0xbf` moved forward and `0x3f` moved backwards. The next 4 bytes followed the same pattern but left and right. These two separate "motors" can also be used in conjunction to make sharper turns, but we haven't bothered to figure that out yet. For now we can move in all directions and that's all we care to achieve, currently...

This testing process also shows how we did a large majority of reversing the ebo packets. 


# Video Packets

The video packets were very easy to identify in wireshark. Video data is going to be alot larger than any other packet because it's a bunch of raw data being sent. So all the packets that were length 1122 stood out. Even moreso since all the data after the ebo procol stuff was just a bunch of random bytes. The only thing we didn't know was what format the data was in. Knowing nothing about video streaming, we just looked at the strings. RTP, h265, and h264 all stood out and seemed to have to do with video stuff.

Again, way too much effort was put into looking at the code and debugging trying to figure out where it encoded the video. The answer was just in the captured packets


All the video packets came back to back so it was obvious to tell where the frame started, and then at the end there would still be a long packet, but it wouldnt be length 1122, and that was obviously the end of the frame.

<p style="text-align:center;"><img src="/assets/enabot_part2/video_frame.png" alt="video frame" style="height: 400px; width:350px;"/></p>


The first packet in the sequence always had the value `0x0141` at offset 0x65 (see image below). After a bunch of googling, some forum post talked about those bytes being the start of an h264 P-Frame. More googling and another forum or something talked about using ffmpeg to convert h264 data to a video. So I tried appending all the bytes that I assumed to be video data and ran it through ffmpeg to see if it would pop out a video file. That didn't work. Then I noticed that some of the sequence of video packets had the header `0x01d7`. Some more googling later, it turned out that was the start of a I-Frame. 

![PFrame](/assets/enabot_part2/p_frame.png)

From the little bit I read about h264 from doing this research it seems that I-Frames are the initial frame of a video and P-Frames then modify that frame until the next I-Frame is sent. Basically, the video has to start with an I-Frame or it won't have an initial base to modify and thus can't produce a video. So I wrote a parser to parse all the video packets, and appended their h264 data together while making sure the first frame of the video was a P-Frame. I did this based off of the `branch1` values in the packets.


<p style="text-align:center;"><img src="/assets/enabot_part2/h264_branches.png" alt="H264 Packet Branches" style="height: 100px; width:320px;"/></p>


The `FINAL_FRAME` was the last packet in a frame transmission, so the packet that's length 271 a few images above would have that branch value. The `P_FRAME2` value appeared in packets that were length 1130 but there were some additional fields that made the packet slightly longer. They still had the P-Frame header though, so looking into them further wasn't worth the time.


Now all that was left was running the parser and generating the video. Apparently the appended bytes don't need run through ffmpeg and it can just be renamed to .mp4, but it was still done initially anyways. After running it through ffpmeg a real playable video popped out! We could nopw play video sent from the ebo by capturing, decoding, and stripping the bytes from packets.


<p style="text-align:center;"><iframe width="420" height="315" src="/assets/enabot_part2/video.mp4" frameborder="0" allowfullscreen></iframe></p>


From here, more research went into starting the video packets after connecting to the ebo. If we could figure that out we could connect to the ebo, start the ebo's video streaming, recieve the packets on our server, and then open a video player to watch the video live. The results of this will be shown in the final section.

Now H264 also supports sending audio and I was hoping after I created the video it would have the sound along with it, but it turns out, the audio packets were entirely separate from video.

# Audio Packets

Phone -> Ebo?

# Mic Packets

Ebo -> Phone?

# 