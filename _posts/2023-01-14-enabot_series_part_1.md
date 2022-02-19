---
layout: post
author: Etch
title:  "Enabot Hacking: Part 1"
date:   2022-02-18 1:01:37 -0500
categories: Hardware Series
ctf-category: PWN
---
# Enabot Hacking: Part 1 -> Teardown and Firmware Extraction

- [Enabot Hacking: Part 1 -> Teardown and Firmware Extraction](#enabot-hacking-part-1---teardown-and-firmware-extraction)
  - [About Enabot](#about-enabot)
  - [Project Goal](#project-goal)
  - [Teardown](#teardown)
  - [Getting the Firmware](#getting-the-firmware)
    - [Intercepting the firmware](#intercepting-the-firmware)
    - [Dumping the flash](#dumping-the-flash)
  - [Analyzing the firmware](#analyzing-the-firmware)
  - [Getting A Shell](#getting-a-shell)
  - [Part 1 Conclusion](#part-1-conclusion)

## About Enabot
I was looking for IoT devices to hack and I wanted something that would be a nightmare once compromised. I came across "Playdate" a dog toy ball that can use your voice and camera to play with your pets. When I tried to get one they hadn't come out yet, so I figured there was some cheap chinese knock-off that I could get which would do the same thing. A few minutes later I came across the Enabot SE. And what do you know there was a coupon for 40% off on amazon, I'll take two. This thing would be a nightmare to have rolling around my apartment. It has a microphone, speaker, camera, and can move around on its own.

## Project Goal
My goal is to get remote code execution through some parsing or network bug so that I can hack this thing without touching it. I also want to make a custom firmware that would give me complete control after someone boots it up and do fun stuff. This series will cover the entire process from start to finish about what I did, my thought process behind it, and why it worked.

## Teardown
Tearing down this was great. We didn't have to snap any plastic, 
and all the parts were easily detachable.
I could easily rebuild the device if needed.

Here is the full teardown with all the pieces, and chips written down

![Teardown_full](/assets/enabot_part1/full_td.jpg)

## Getting the Firmware

I'm going to obtain the firmware in 2 different ways, the first way by doing a firmware update and intercepting the file it downloads. I did this by connecting the device to a hotspot off of my computer. That way I can open wireshark and see the packets that first come to my computer, and then go out to the device.
The second way is by dumping the SPI flash on the board of the device. I'll do this before the update so we have the original firmware.

### Intercepting the firmware
First I hit capture packets (making sure wireshark was looking at my hotspot network) and then I hit update firmware in the ebo app immediately after. The packets started rolling in. 

Once the update was complete I hit stop capture and did a string search for a .com to get the url it grabbed them from figuring the file would start around there. It found a few which were just a generic server they have hosted for the firmware updates. Near one of the packets with a URL I came across across a packet that specified the filename: *1640594394-ebo-se-ipc20211223.tar*. This let me know that the file being downloaded was a tar file, and I knew I could just look for the packet with tar headers. That turned out to be the next packet. 

![tar_headers](/assets/enabot_part1/tar_headers.png)

I right clicked the packet, hit follow->tcp_stream, changed the data to a raw format, and then saved it as "intercepted_firmware.bin".

![tcp_follow](/assets/enabot_part1/follow_tcp.png)

It has some http headers at the beginning, but I know binwalk will still be able to extract it easily, so I just leave them.

I run binwalk with -evM so that it extracts it recursively, and prints the outputs verbosely. We now have the extracted firmware through an update interception.

### Dumping the flash
The firmware can also be obtained by dumping the flash. This can be done by removing the spi flash chip from the board, and then reading it with a spi flash reader. 


![Front](/assets/enabot_part1/board_top.jpg)

The SPI flash is the 8 pin chip in the top right corner.

I tried using my minicom without removing the chip, but as usual, 
it slightly powers the rest of the board, so it can't be properly dumped. 
I used a heat gun with some tweezers to first heat up and lift one side, then I did the same with the other and it came off.

![Removed](/assets/enabot_part1/removed.jpg)

Now here's what I have

![Read_chip](/assets/enabot_part1/read_chip.jpg)


I use a minicom pro with the [custom software](https://gitlab.com/DavidGriffith/minipro) maintained on gitlab.

Putting the chip in the socket reader and running the follow command dumped the firmware

    ./minipro -p "XM25QH128A@SOIC8" -r dumped_firmware.bin


If you reverse the 5v and ground of the chip, the minipro will warn you, so don't worry about shorting the chip.

And that's it, we have the firmware. Later we'll create a tool to unpack and repack the firmware so that we can easily flash new custom firmwares onto the chip 



## Analyzing the firmware

<details>
<summary>Binwalk Output</summary>

<pre>
binwalk -evM firmware_update.bin                

Scan Time:     2022-01-14 20:22:44
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/firmware_update.bin
MD5 Checksum:  4a6182ba9ac6ed14c107ba5a76e04ed8
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION

365           0x16D           POSIX tar archive (GNU), owner user name: ".crc32"


Scan Time:     2022-01-14 20:22:44
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/kernel
MD5 Checksum:  2537c46e17579468efd3ba04af61665c
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
64            0x40            xz compressed data


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/userfs.sqfs
MD5 Checksum:  c6724488e3884b5903682d7c76f317bc
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3575350 bytes, 86 inodes, blocksize: 131072 bytes, created: 2021-12-23 04:30:20


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/rootfs.sqfs.crc32
MD5 Checksum:  732c0e8bb3d7b386c838decca650c972
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/kernel.crc32
MD5 Checksum:  78118b0f6e208b971a935c84e180cea1
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/boot.bin
MD5 Checksum:  be21dfdb0b3676a6d7ea9030c90cb411
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
46267         0xB4BB          xz compressed data
47168         0xB840          CRC32 polynomial table, little endian
65600         0x10040         xz compressed data


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/miservice.sqfs.crc32
MD5 Checksum:  77a1ab5a661bc3cfa34c3f9fe9a1720c
Signatures:    391

 DECIMAL       HEXADECIMAL     DESCRIPTION


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/userfs.sqfs.crc32
MD5 Checksum:  cc8ae3368798f752b15840a393c8698d
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/miservice.sqfs
MD5 Checksum:  dc60b4a273a61bcd6511207801b98dd1
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 1410962 bytes, 44 inodes, blocksize: 131072 bytes, created: 2021-12-23 04:30:19


Scan Time:     2022-01-14 20:22:45
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/rootfs.sqfs
MD5 Checksum:  1feb11bd7634550cf213b7583acf0099
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2047938 bytes, 457 inodes, blocksize: 131072 bytes, created: 2021-12-23 04:30:19


Scan Time:     2022-01-14 20:22:46
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/boot.bin.crc32
MD5 Checksum:  aeebf1aaf10e0315b891d544672fba86
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION


Scan Time:     2022-01-14 20:22:46
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/_kernel.extracted/40
MD5 Checksum:  ff19ec641cab73c0edc8f57a8f7dc938
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
432           0x1B0           device tree image (dtb)
61492         0xF034          device tree image (dtb)
876872        0xD6148         SHA256 hash constants, little endian
989048        0xF1778         device tree image (dtb)
2053760       0x1F5680        CRC32 polynomial table, little endian
2761109       0x2A2195        xz compressed data
2775739       0x2A5ABB        Unix path: /usr/userfs/data/driver
2791305       0x2A9789        Unix path: /sys/firmware/devicetree/base
2791817       0x2A9989        Unix path: /sys/firmware/fdt': CRC check failed
2818515       0x2B01D3        Neighborly text, "neighbor table overflow!ck"
2838528       0x2B5000        ELF, 32-bit LSB shared object, ARM, version 1 (SYSV)
3233904       0x315870        device tree image (dtb)


Scan Time:     2022-01-14 20:22:46
Target File:   /home/etch/Projects/hardware/ebo/intercepted_firmware_update/_firmware_update.bin.extracted/_boot.bin.extracted/10040
MD5 Checksum:  0dc4bed7127c7e4f81c75deaec3f6dd4
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION

43420         0xA99C          uImage header, header size: 64 bytes, header CRC: 0x1EFF2FE1, created: 2101-06-18 02:48:09, image size: 16797923 bytes, Data Address: 0x28709DE5, Entry Point: 0x40A0E3, data CRC: 0x2C809DE5, OS: NetBSD, image name: ""
174836        0x2AAF4         CRC32 polynomial table, little endian
223951        0x36ACF         xz compressed data
</pre>

</details>

<br>
Then I'll run tree to see easily see all the files in the firmware
<br><br>
<details>
<summary>Tree Output</summary><br>
<pre>
% tree 
.
├── 16D.tar
├── boot.bin
├── boot.bin.crc32
├── _boot.bin.extracted
│   ├── 10040
│   ├── _10040.extracted
│   │   └── 36ACF.xz
│   ├── 10040.xz
│   └── B4BB.xz
├── kernel
├── kernel.crc32
├── _kernel.extracted
│   ├── 40
│   ├── _40.extracted
│   │   └── 2A2195.xz
│   └── 40.xz
├── miservice.sqfs
├── miservice.sqfs.crc32
├── _miservice.sqfs.extracted
│   ├── 0.squashfs
│   └── squashfs-root
│       ├── config_tool
│       ├── dump_config -> config_tool
│       ├── dump_mmap -> config_tool
│       ├── iqfile
│       │   ├── gc2053_api_day.bin
│       │   ├── gc2053_api_night.bin
│       │   ├── imx307_iqfile.bin
│       │   ├── iqfile0.bin -> imx307_iqfile.bin
│       │   ├── iqfile1.bin -> imx307_iqfile.bin
│       │   ├── iqfile2.bin -> imx307_iqfile.bin
│       │   └── iqfile3.bin -> imx307_iqfile.bin
│       ├── mmap.ini
│       ├── modules
│       │   └── 4.9.84
│       │       ├── ehci-hcd.ko
│       │       ├── fat.ko
│       │       ├── grace.ko
│       │       ├── kdrv_sdmmc.ko
│       │       ├── lockd.ko
│       │       ├── mhal.ko
│       │       ├── mi_ai.ko
│       │       ├── mi_ao.ko
│       │       ├── mi_common.ko
│       │       ├── mi_divp.ko
│       │       ├── mi_rgn.ko
│       │       ├── mi_sensor.ko
│       │       ├── mi_shadow.ko
│       │       ├── mi_sys.ko
│       │       ├── mi_venc.ko
│       │       ├── mi_vif.ko
│       │       ├── mi_vpe.ko
│       │       ├── mmc_block.ko
│       │       ├── mmc_core.ko
│       │       ├── msdos.ko
│       │       ├── ms_notify.ko
│       │       ├── nfs.ko
│       │       ├── nfsv2.ko
│       │       ├── sunrpc.ko
│       │       ├── usb-common.ko
│       │       ├── usbcore.ko
│       │       └── vfat.ko
│       └── venc_fw
│           └── chagall.bin
├── rootfs.sqfs
├── rootfs.sqfs.crc32
├── _rootfs.sqfs.extracted
│   ├── 0.squashfs
│   └── squashfs-root
│       ├── bin
│       │   ├── addgroup -> busybox
│       │   ├── adduser -> busybox
│       │   ├── ash -> busybox
│       │   ├── base64 -> busybox
│       │   ├── busybox
│       │   ├── cat -> busybox
│       │   ├── catv -> busybox
│       │   ├── chattr -> busybox
│       │   ├── chgrp -> busybox
│       │   ├── chmod -> busybox
│       │   ├── chown -> busybox
│       │   ├── conspy -> busybox
│       │   ├── cp -> busybox
│       │   ├── cpio -> busybox
│       │   ├── cttyhack -> busybox
│       │   ├── date -> busybox
│       │   ├── dd -> busybox
│       │   ├── delgroup -> busybox
│       │   ├── deluser -> busybox
│       │   ├── df -> busybox
│       │   ├── dmesg -> busybox
│       │   ├── dnsdomainname -> busybox
│       │   ├── dumpkmap -> busybox
│       │   ├── echo -> busybox
│       │   ├── ed -> busybox
│       │   ├── egrep -> busybox
│       │   ├── false -> busybox
│       │   ├── fdflush -> busybox
│       │   ├── fgrep -> busybox
│       │   ├── fsync -> busybox
│       │   ├── getopt -> busybox
│       │   ├── grep -> busybox
│       │   ├── gunzip -> busybox
│       │   ├── gzip -> busybox
│       │   ├── hostname -> busybox
│       │   ├── hush -> busybox
│       │   ├── ionice -> busybox
│       │   ├── iostat -> busybox
│       │   ├── ip -> busybox
│       │   ├── ipaddr -> busybox
│       │   ├── ipcalc -> busybox
│       │   ├── iplink -> busybox
│       │   ├── iproute -> busybox
│       │   ├── iprule -> busybox
│       │   ├── iptunnel -> busybox
│       │   ├── kill -> busybox
│       │   ├── linux32 -> busybox
│       │   ├── linux64 -> busybox
│       │   ├── ln -> busybox
│       │   ├── login -> busybox
│       │   ├── ls -> busybox
│       │   ├── lsattr -> busybox
│       │   ├── lzop -> busybox
│       │   ├── makemime -> busybox
│       │   ├── mkdir -> busybox
│       │   ├── mknod -> busybox
│       │   ├── mktemp -> busybox
│       │   ├── more -> busybox
│       │   ├── mount -> busybox
│       │   ├── mountpoint -> busybox
│       │   ├── mpstat -> busybox
│       │   ├── mt -> busybox
│       │   ├── mv -> busybox
│       │   ├── netstat -> busybox
│       │   ├── nice -> busybox
│       │   ├── pidof -> busybox
│       │   ├── ping -> busybox
│       │   ├── ping6 -> busybox
│       │   ├── pipe_progress -> busybox
│       │   ├── powertop -> busybox
│       │   ├── printenv -> busybox
│       │   ├── ps -> busybox
│       │   ├── pwd -> busybox
│       │   ├── reformime -> busybox
│       │   ├── rev -> busybox
│       │   ├── rm -> busybox
│       │   ├── rmdir -> busybox
│       │   ├── rpm -> busybox
│       │   ├── run-parts -> busybox
│       │   ├── scriptreplay -> busybox
│       │   ├── sed -> busybox
│       │   ├── setarch -> busybox
│       │   ├── setserial -> busybox
│       │   ├── sh -> busybox
│       │   ├── sleep -> busybox
│       │   ├── stat -> busybox
│       │   ├── stty -> busybox
│       │   ├── su -> busybox
│       │   ├── sync -> busybox
│       │   ├── tar -> busybox
│       │   ├── touch -> busybox
│       │   ├── true -> busybox
│       │   ├── umount -> busybox
│       │   ├── uname -> busybox
│       │   ├── usleep -> busybox
│       │   ├── vi -> busybox
│       │   ├── watch -> busybox
│       │   └── zcat -> busybox
│       ├── config
│       ├── configs
│       ├── dev
│       ├── etc
│       │   ├── crontabs
│       │   │   └── root
│       │   ├── dropbear
│       │   │   ├── dropbear_dss_host_key
│       │   │   └── dropbear_rsa_host_key
│       │   ├── fstab
│       │   ├── group
│       │   ├── hotplug
│       │   │   └── sd
│       │   │       ├── sd_insert
│       │   │       └── sd_remove
│       │   ├── init.d
│       │   │   ├── rcS
│       │   │   ├── S00devs
│       │   │   ├── S01udev
│       │   │   ├── S80network
│       │   │   └── udhcpc.script
│       │   ├── inittab
│       │   ├── mdev.conf
│       │   ├── passwd
│       │   ├── passwd-
│       │   ├── profile
│       │   ├── protocols
│       │   ├── resolv.conf -> ../configs/resolv.conf
│       │   ├── sysctl.conf
│       │   ├── wpa_cli.conf
│       │   └── wpa.conf
│       ├── home
│       ├── lib
│       │   ├── ld-uClibc-1.0.31.so
│       │   ├── ld-uClibc.so.0 -> ld-uClibc.so.1
│       │   ├── ld-uClibc.so.1 -> ld-uClibc-1.0.31.so
│       │   ├── libAEC_LINUX.so
│       │   ├── libAPC_LINUX.so
│       │   ├── libatomic.so -> libatomic.so.1.1.0
│       │   ├── libatomic.so.1 -> libatomic.so.1.1.0
│       │   ├── libatomic.so.1.1.0
│       │   ├── libBF_LINUX.so
│       │   ├── libc.so.0 -> libuClibc-1.0.31.so
│       │   ├── libc.so.1 -> libuClibc-1.0.31.so
│       │   ├── libc.so.6 -> libuClibc-1.0.31.so
│       │   ├── libg711.so
│       │   ├── libgcc_s.so -> libgcc_s.so.1
│       │   ├── libgcc_s.so.1
│       │   ├── libncurses.so -> libncurses.so.6
│       │   ├── libncurses.so.6 -> libncurses.so.6.0
│       │   ├── libncurses.so.6.0
│       │   ├── libSRC_LINUX.so
│       │   ├── libstdc++.so -> libstdc++.so.6.0.20
│       │   ├── libstdc++.so.6 -> libstdc++.so.6.0.20
│       │   ├── libstdc++.so.6.0.20
│       │   ├── libuClibc-1.0.31.so
│       │   └── modules
│       │       └── 4.9.84 -> /config/modules/4.9.84
│       ├── linuxrc -> bin/busybox
│       ├── mnt
│       │   └── backup
│       ├── nfsroot
│       ├── proc
│       ├── root
│       ├── sbin
│       │   ├── acpid -> ../bin/busybox
│       │   ├── adjtimex -> ../bin/busybox
│       │   ├── arp -> ../bin/busybox
│       │   ├── blkid -> ../bin/busybox
│       │   ├── blockdev -> ../bin/busybox
│       │   ├── bootchartd -> ../bin/busybox
│       │   ├── depmod -> ../bin/busybox
│       │   ├── devmem -> ../bin/busybox
│       │   ├── fbsplash -> ../bin/busybox
│       │   ├── fdisk -> ../bin/busybox
│       │   ├── findfs -> ../bin/busybox
│       │   ├── freeramdisk -> ../bin/busybox
│       │   ├── fsck -> ../bin/busybox
│       │   ├── fsck.minix -> ../bin/busybox
│       │   ├── getty -> ../bin/busybox
│       │   ├── halt -> ../bin/busybox
│       │   ├── hdparm -> ../bin/busybox
│       │   ├── hwclock -> ../bin/busybox
│       │   ├── ifconfig -> ../bin/busybox
│       │   ├── ifdown -> ../bin/busybox
│       │   ├── ifenslave -> ../bin/busybox
│       │   ├── ifup -> ../bin/busybox
│       │   ├── init -> ../bin/busybox
│       │   ├── insmod -> ../bin/busybox
│       │   ├── klogd -> ../bin/busybox
│       │   ├── loadkmap -> ../bin/busybox
│       │   ├── logread -> ../bin/busybox
│       │   ├── losetup -> ../bin/busybox
│       │   ├── lsmod -> ../bin/busybox
│       │   ├── makedevs -> ../bin/busybox
│       │   ├── man -> ../bin/busybox
│       │   ├── mdev -> ../bin/busybox
│       │   ├── mkdosfs -> ../bin/busybox
│       │   ├── mke2fs -> ../bin/busybox
│       │   ├── mkfs.ext2 -> ../bin/busybox
│       │   ├── mkfs.minix -> ../bin/busybox
│       │   ├── mkfs.vfat -> ../bin/busybox
│       │   ├── mkswap -> ../bin/busybox
│       │   ├── modinfo -> ../bin/busybox
│       │   ├── modprobe -> ../bin/busybox
│       │   ├── nameif -> ../bin/busybox
│       │   ├── pivot_root -> ../bin/busybox
│       │   ├── poweroff -> ../bin/busybox
│       │   ├── raidautorun -> ../bin/busybox
│       │   ├── reboot -> ../bin/busybox
│       │   ├── rmmod -> ../bin/busybox
│       │   ├── route -> ../bin/busybox
│       │   ├── runlevel -> ../bin/busybox
│       │   ├── setconsole -> ../bin/busybox
│       │   ├── slattach -> ../bin/busybox
│       │   ├── start-stop-daemon -> ../bin/busybox
│       │   ├── sulogin -> ../bin/busybox
│       │   ├── swapoff -> ../bin/busybox
│       │   ├── swapon -> ../bin/busybox
│       │   ├── switch_root -> ../bin/busybox
│       │   ├── sysctl -> ../bin/busybox
│       │   ├── syslogd -> ../bin/busybox
│       │   ├── tunctl -> ../bin/busybox
│       │   ├── udhcpc -> ../bin/busybox
│       │   ├── vconfig -> ../bin/busybox
│       │   ├── watchdog -> ../bin/busybox
│       │   └── zcip -> ../bin/busybox
│       ├── sys
│       ├── tmp
│       ├── usr
│       │   ├── bin
│       │   │   ├── [ -> ../../bin/busybox
│       │   │   ├── [[ -> ../../bin/busybox
│       │   │   ├── add-shell -> ../../bin/busybox
│       │   │   ├── arping -> ../../bin/busybox
│       │   │   ├── awk -> ../../bin/busybox
│       │   │   ├── basename -> ../../bin/busybox
│       │   │   ├── beep -> ../../bin/busybox
│       │   │   ├── bunzip2 -> ../../bin/busybox
│       │   │   ├── bzcat -> ../../bin/busybox
│       │   │   ├── bzip2 -> ../../bin/busybox
│       │   │   ├── cal -> ../../bin/busybox
│       │   │   ├── chat -> ../../bin/busybox
│       │   │   ├── chpst -> ../../bin/busybox
│       │   │   ├── chrt -> ../../bin/busybox
│       │   │   ├── chvt -> ../../bin/busybox
│       │   │   ├── cksum -> ../../bin/busybox
│       │   │   ├── clear -> ../../bin/busybox
│       │   │   ├── cmp -> ../../bin/busybox
│       │   │   ├── comm -> ../../bin/busybox
│       │   │   ├── crontab -> ../../bin/busybox
│       │   │   ├── cryptpw -> ../../bin/busybox
│       │   │   ├── cut -> ../../bin/busybox
│       │   │   ├── dc -> ../../bin/busybox
│       │   │   ├── deallocvt -> ../../bin/busybox
│       │   │   ├── diff -> ../../bin/busybox
│       │   │   ├── dirname -> ../../bin/busybox
│       │   │   ├── dos2unix -> ../../bin/busybox
│       │   │   ├── du -> ../../bin/busybox
│       │   │   ├── dumpleases -> ../../bin/busybox
│       │   │   ├── eject -> ../../bin/busybox
│       │   │   ├── env -> ../../bin/busybox
│       │   │   ├── envdir -> ../../bin/busybox
│       │   │   ├── envuidgid -> ../../bin/busybox
│       │   │   ├── ether-wake -> ../../bin/busybox
│       │   │   ├── expand -> ../../bin/busybox
│       │   │   ├── expr -> ../../bin/busybox
│       │   │   ├── fdformat -> ../../bin/busybox
│       │   │   ├── fgconsole -> ../../bin/busybox
│       │   │   ├── find -> ../../bin/busybox
│       │   │   ├── flock -> ../../bin/busybox
│       │   │   ├── fold -> ../../bin/busybox
│       │   │   ├── free -> ../../bin/busybox
│       │   │   ├── ftpget -> ../../bin/busybox
│       │   │   ├── ftpput -> ../../bin/busybox
│       │   │   ├── fuser -> ../../bin/busybox
│       │   │   ├── groups -> ../../bin/busybox
│       │   │   ├── hd -> ../../bin/busybox
│       │   │   ├── head -> ../../bin/busybox
│       │   │   ├── hexdump -> ../../bin/busybox
│       │   │   ├── hostid -> ../../bin/busybox
│       │   │   ├── id -> ../../bin/busybox
│       │   │   ├── ifplugd -> ../../bin/busybox
│       │   │   ├── install -> ../../bin/busybox
│       │   │   ├── ipcrm -> ../../bin/busybox
│       │   │   ├── ipcs -> ../../bin/busybox
│       │   │   ├── kbd_mode -> ../../bin/busybox
│       │   │   ├── killall -> ../../bin/busybox
│       │   │   ├── killall5 -> ../../bin/busybox
│       │   │   ├── last -> ../../bin/busybox
│       │   │   ├── less -> ../../bin/busybox
│       │   │   ├── logger -> ../../bin/busybox
│       │   │   ├── logname -> ../../bin/busybox
│       │   │   ├── lpq -> ../../bin/busybox
│       │   │   ├── lpr -> ../../bin/busybox
│       │   │   ├── lsof -> ../../bin/busybox
│       │   │   ├── lspci -> ../../bin/busybox
│       │   │   ├── lsusb -> ../../bin/busybox
│       │   │   ├── lzcat -> ../../bin/busybox
│       │   │   ├── lzma -> ../../bin/busybox
│       │   │   ├── lzopcat -> ../../bin/busybox
│       │   │   ├── md5sum -> ../../bin/busybox
│       │   │   ├── mesg -> ../../bin/busybox
│       │   │   ├── microcom -> ../../bin/busybox
│       │   │   ├── mkfifo -> ../../bin/busybox
│       │   │   ├── mkpasswd -> ../../bin/busybox
│       │   │   ├── nc -> ../../bin/busybox
│       │   │   ├── nmeter -> ../../bin/busybox
│       │   │   ├── nohup -> ../../bin/busybox
│       │   │   ├── nslookup -> ../../bin/busybox
│       │   │   ├── od -> ../../bin/busybox
│       │   │   ├── openvt -> ../../bin/busybox
│       │   │   ├── passwd -> ../../bin/busybox
│       │   │   ├── patch -> ../../bin/busybox
│       │   │   ├── pgrep -> ../../bin/busybox
│       │   │   ├── pkill -> ../../bin/busybox
│       │   │   ├── pmap -> ../../bin/busybox
│       │   │   ├── printf -> ../../bin/busybox
│       │   │   ├── pscan -> ../../bin/busybox
│       │   │   ├── pstree -> ../../bin/busybox
│       │   │   ├── pwdx -> ../../bin/busybox
│       │   │   ├── readahead -> ../../bin/busybox
│       │   │   ├── readlink -> ../../bin/busybox
│       │   │   ├── realpath -> ../../bin/busybox
│       │   │   ├── remove-shell -> ../../bin/busybox
│       │   │   ├── renice -> ../../bin/busybox
│       │   │   ├── reset -> ../../bin/busybox
│       │   │   ├── resize -> ../../bin/busybox
│       │   │   ├── rpm2cpio -> ../../bin/busybox
│       │   │   ├── rtcwake -> ../../bin/busybox
│       │   │   ├── runsv -> ../../bin/busybox
│       │   │   ├── runsvdir -> ../../bin/busybox
│       │   │   ├── rx -> ../../bin/busybox
│       │   │   ├── script -> ../../bin/busybox
│       │   │   ├── seq -> ../../bin/busybox
│       │   │   ├── setkeycodes -> ../../bin/busybox
│       │   │   ├── setsid -> ../../bin/busybox
│       │   │   ├── setuidgid -> ../../bin/busybox
│       │   │   ├── sha1sum -> ../../bin/busybox
│       │   │   ├── sha256sum -> ../../bin/busybox
│       │   │   ├── sha512sum -> ../../bin/busybox
│       │   │   ├── showkey -> ../../bin/busybox
│       │   │   ├── smemcap -> ../../bin/busybox
│       │   │   ├── softlimit -> ../../bin/busybox
│       │   │   ├── sort -> ../../bin/busybox
│       │   │   ├── split -> ../../bin/busybox
│       │   │   ├── strings -> ../../bin/busybox
│       │   │   ├── sum -> ../../bin/busybox
│       │   │   ├── sv -> ../../bin/busybox
│       │   │   ├── tac -> ../../bin/busybox
│       │   │   ├── tail -> ../../bin/busybox
│       │   │   ├── tcpsvd -> ../../bin/busybox
│       │   │   ├── tee -> ../../bin/busybox
│       │   │   ├── telnet -> ../../bin/busybox
│       │   │   ├── test -> ../../bin/busybox
│       │   │   ├── tftp -> ../../bin/busybox
│       │   │   ├── tftpd -> ../../bin/busybox
│       │   │   ├── time -> ../../bin/busybox
│       │   │   ├── timeout -> ../../bin/busybox
│       │   │   ├── top -> ../../bin/busybox
│       │   │   ├── tr -> ../../bin/busybox
│       │   │   ├── traceroute -> ../../bin/busybox
│       │   │   ├── traceroute6 -> ../../bin/busybox
│       │   │   ├── tty -> ../../bin/busybox
│       │   │   ├── ttysize -> ../../bin/busybox
│       │   │   ├── udpsvd -> ../../bin/busybox
│       │   │   ├── unexpand -> ../../bin/busybox
│       │   │   ├── uniq -> ../../bin/busybox
│       │   │   ├── unix2dos -> ../../bin/busybox
│       │   │   ├── unlzma -> ../../bin/busybox
│       │   │   ├── unlzop -> ../../bin/busybox
│       │   │   ├── unxz -> ../../bin/busybox
│       │   │   ├── unzip -> ../../bin/busybox
│       │   │   ├── uptime -> ../../bin/busybox
│       │   │   ├── users -> ../../bin/busybox
│       │   │   ├── uudecode -> ../../bin/busybox
│       │   │   ├── uuencode -> ../../bin/busybox
│       │   │   ├── vlock -> ../../bin/busybox
│       │   │   ├── volname -> ../../bin/busybox
│       │   │   ├── wall -> ../../bin/busybox
│       │   │   ├── wc -> ../../bin/busybox
│       │   │   ├── wget -> ../../bin/busybox
│       │   │   ├── which -> ../../bin/busybox
│       │   │   ├── who -> ../../bin/busybox
│       │   │   ├── whoami -> ../../bin/busybox
│       │   │   ├── whois -> ../../bin/busybox
│       │   │   ├── xargs -> ../../bin/busybox
│       │   │   ├── xz -> ../../bin/busybox
│       │   │   ├── xzcat -> ../../bin/busybox
│       │   │   └── yes -> ../../bin/busybox
│       │   ├── ftp-server-socket -> ./userfs/bin/ftp-server-socket
│       │   ├── lib
│       │   │   ├── libcrypto.so -> libcrypto.so.1.0.0
│       │   │   ├── libcrypto.so.1.0.0
│       │   │   ├── libnl.so -> libnl.so.1
│       │   │   ├── libnl.so.1 -> libnl.so.1.1.4
│       │   │   ├── libnl.so.1.1.4
│       │   │   ├── libssl.so -> libssl.so.1.0.0
│       │   │   ├── libssl.so.1.0.0
│       │   │   ├── libz.so -> libz.so.1.2.8
│       │   │   ├── libz.so.1 -> libz.so.1.2.8
│       │   │   ├── libz.so.1.2.8
│       │   │   └── modules
│       │   │       └── lib -> /usr/userfs/lib
│       │   ├── sbin
│       │   │   ├── brctl -> ../../bin/busybox
│       │   │   ├── chpasswd -> ../../bin/busybox
│       │   │   ├── chroot -> ../../bin/busybox
│       │   │   ├── crond -> ../../bin/busybox
│       │   │   ├── dhcprelay -> ../../bin/busybox
│       │   │   ├── dnsd -> ../../bin/busybox
│       │   │   ├── dropbear
│       │   │   ├── fakeidentd -> ../../bin/busybox
│       │   │   ├── fbset -> ../../bin/busybox
│       │   │   ├── ftpd -> ../../bin/busybox
│       │   │   ├── httpd -> ../../bin/busybox
│       │   │   ├── loadfont -> ../../bin/busybox
│       │   │   ├── lpd -> ../../bin/busybox
│       │   │   ├── nanddump -> ../../bin/busybox
│       │   │   ├── nandwrite -> ../../bin/busybox
│       │   │   ├── nbd-client -> ../../bin/busybox
│       │   │   ├── ntpd -> ../../bin/busybox
│       │   │   ├── popmaildir -> ../../bin/busybox
│       │   │   ├── rdate -> ../../bin/busybox
│       │   │   ├── rdev -> ../../bin/busybox
│       │   │   ├── readprofile -> ../../bin/busybox
│       │   │   ├── sendmail -> ../../bin/busybox
│       │   │   ├── setfont -> ../../bin/busybox
│       │   │   ├── setlogcons -> ../../bin/busybox
│       │   │   ├── svlogd -> ../../bin/busybox
│       │   │   ├── telnetd -> ../../bin/busybox
│       │   │   ├── ubiattach -> ../../bin/busybox
│       │   │   ├── ubidetach -> ../../bin/busybox
│       │   │   ├── ubimkvol -> ../../bin/busybox
│       │   │   ├── ubirmvol -> ../../bin/busybox
│       │   │   ├── ubirsvol -> ../../bin/busybox
│       │   │   ├── ubiupdatevol -> ../../bin/busybox
│       │   │   └── udhcpd -> ../../bin/busybox
│       │   ├── share
│       │   │   └── udhcpc
│       │   │       └── default.script
│       │   └── userfs
│       └── var
├── userfs.sqfs
├── userfs.sqfs.crc32
└── _userfs.sqfs.extracted
    ├── 0.squashfs
    └── squashfs-root
        ├── bin
        │   ├── ftp-server-socket
        │   └── FW_EBO_C
        ├── data
        │   ├── driver
        │   │   ├── aw87xxx_pid_59_off_0.bin
        │   │   ├── aw87xxx_pid_59_voice_0.bin
        │   │   ├── aw87xxx_pid_5a_off_0.bin
        │   │   └── aw87xxx_pid_5a_voice_0.bin
        │   ├── emo
        │   │   ├── buttonPressed.csv
        │   │   ├── charged.csv
        │   │   ├── charging20.csv
        │   │   ├── charging60.csv
        │   │   ├── charging95.csv
        │   │   ├── dormancy.csv
        │   │   ├── lowPower.csv
        │   │   ├── noInternet.csv
        │   │   ├── security.csv
        │   │   ├── start.csv
        │   │   ├── stateless.csv
        │   │   ├── strongShake.csv
        │   │   ├── test_colorLED_blue.csv
        │   │   ├── test_colorLED_green.csv
        │   │   ├── test_colorLED_off.csv
        │   │   ├── test_colorLED_red.csv
        │   │   ├── test.csv
        │   │   ├── ultraLowPower.csv
        │   │   ├── upgrading.csv
        │   │   ├── weekShake.csv
        │   │   ├── wifiBoundNoConnect.csv
        │   │   ├── wifiBoundNoConnect_noSSID.csv
        │   │   ├── wifiConnecting.csv
        │   │   ├── wifiNoConnect.csv
        │   │   └── wifiNoConnect_noSSID.csv
        │   └── sound
        │       ├── charge_done.g711a
        │       ├── charging_complete.g711a
        │       ├── charging.g711a
        │       ├── disablelaser.g711a
        │       ├── enablelaser.g711a
        │       ├── factory_reset.g711a
        │       ├── findnot-charge.g711a
        │       ├── link_failure.g711a
        │       ├── linking.g711a
        │       ├── link_success.g711a
        │       ├── longtime-playing.g711a
        │       ├── lowpower_10.g711a
        │       ├── lowpower_20.g711a
        │       ├── open.g711a
        │       ├── poweroff.g711a
        │       ├── record.g711a
        │       ├── roll.g711a
        │       ├── rounding.g711a
        │       ├── rushrool.g711a
        │       ├── scan_qrcode.g711a
        │       ├── shaking.g711a
        │       ├── snap.g711a
        │       ├── start-elecpet-ch.g711a
        │       ├── start-elecpet-en.g711a
        │       ├── start-patrol-ch.g711a
        │       ├── start-patrol-en.g711a
        │       ├── start-recharge-ch.g711a
        │       ├── start-recharge-en.g711a
        │       └── switch_mode.g711a
        ├── etc
        │   ├── EboDomainWhiteList.cfg
        │   ├── load_apps
        │   ├── load_modules
        │   └── timing_backup_log.sh
        ├── ko
        │   ├── aw87XXX.ko
        │   ├── gc2053_MIPI.ko
        │   ├── mi_cipher.ko
        │   └── rtl8192eu.ko
        ├── lib
        ├── sbin
        │   ├── i2c_read_write
        │   └── wpa_supplicant
        └── share

54 directories, 542 files
</pre>

<br>
</details><br>

There's all the files and directories. Some that are notable are the busybox telnet symlink, boot.bin, kernel, passwd, FW_EBO_C, and of course the sound directory cause I think it be funny to make this thing say stupid crap.

One important thing it's missing is a netcat symlink in the busybox. When I make my own firmware, I'll definitely plan on putting my own busybox on the device so I can setup a netcat reverse shell.

<br>

## Getting A Shell
I'll start off with the passwd file. If we can crack the root password in that file, we can get a root shell through telnet or ssh if either of those are enabled.

The contents are as follows

```
root:RKVyRbEzRyync:0:0::/root:/bin/sh
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
```

We see there is a password hash for the root user (*RKVyRbEzRyync*), and it seems like they have access to ssh. If we can crack the password, we should be able to access the device through ssh. After trying to crack it with John The Ripper and Hashcat with a few different wordlists, I didn't have any luck. 

I also looked at the backup passwd file, the ```passwd-``` file. It contained the following.
```
root:ab8nBoH3mb8.g:0:0::/root:/bin/sh
```
It has a different hash for the root user and was easily cracked with rockyou.txt. The password was ```helpme```. They probably updated the password in the newer firmware update after figuring out it could be cracked in less than a second. 

I then wanted to check how long a bruteforce would take. I did a little research about the hashing algorithm they use, "DES Crypt". Turns out it can only be 8 characters long, so definitely crackable with enough time and good enough hardware. I tried bruteforcing everything up to 7 characters which took about a day, and had no luck. That means the password is 8 characters. My hashrate with a 1060 TI is about 460 Megahashes per second. After doing the math it would take my machine 5 years running nonstop to check every 8 character password. I did some reasearch and found these alternative options for cracking

1. A google collab hashcat session gave me 850 Mh/s
    * [Colabcat](https://github.com/someshkar/colabcat)
2. Hashtopolis is a project that would let me crack hashes in conjunction with other machines
    * [Hashtopolis](https://github.com/hashtopolis)
3. Cloudtopolis is a combination of options 1 and 2 where you setup multiple sessions that all work in conjunction
    * [Cloudtopolis](https://github.com/JoelGMSec/Cloudtopolis)
4. Crack.sh would crack a descrypt hash for $100


I went with option 4. The amount of time and/or energy needed (literal energy from graphics cards and CPU's) would be way over $100, and my friends agreed to split the cost with me if they could help hack the Ebo. This was just a no brainer. A few day later, I have the password.

    fz@2019*

Note that getting this password really wasn't necessary as we could've just modified the passwd file, or added a backdoor to the firmware, and then reflashed it. It's just cool knowing we know the root password on the most up to date firmware.


Let's connect through SSH and see what processes are running. 

    ssh root@<ip>

<details>
<summary> Running Processes </summary>

<pre>
~ # ps
PID   USER     TIME   COMMAND
    1 root       0:00 {linuxrc} init
    2 root       0:00 [kthreadd]
    3 root       0:03 [ksoftirqd/0]
    5 root       0:00 [kworker/0:0H]
    7 root       0:04 [rcu_preempt]
    8 root       0:00 [rcu_sched]
    9 root       0:00 [rcu_bh]
   10 root       0:00 [lru-add-drain]
   11 root       0:00 [watchdog/0]
   12 root       0:00 [kdevtmpfs]
   13 root       0:00 [netns]
  134 root       0:00 [oom_reaper]
  135 root       0:00 [writeback]
  137 root       0:00 [kcompactd0]
  138 root       0:00 [crypto]
  139 root       0:00 [bioset]
  141 root       0:00 [kblockd]
  161 root       0:00 [cfg80211]
  163 root       0:00 [watchdogd]
  186 root       0:00 [kswapd0]
  279 root       0:02 [urdma_tx_thread]
  298 root       0:00 [bioset]
  303 root       0:00 [bioset]
  308 root       0:00 [bioset]
  313 root       0:00 [bioset]
  318 root       0:00 [bioset]
  323 root       0:00 [bioset]
  328 root       0:00 [bioset]
  339 root       0:00 [monitor_temp]
  345 root       0:48 [spi0]
  347 root       0:00 [spi1]
  359 root       0:00 [kworker/0:1H]
  382 root       0:00 [jffs2_gcd_mtd5]
  384 root       0:00 [jffs2_gcd_mtd6]
  406 root       0:00 [rpciod]
  407 root       0:00 [xprtiod]
  413 root       0:00 [nfsiod]
  443 root       0:00 [bioset]
  444 root       0:00 [mmcqd/0]
  465 root       0:00 [SensorIfThreadW]
  474 root       0:05 [IspDriverThread]
  544 root      18:49 /usr/userfs/bin//FW_EBO_C
  545 root       0:00 {linuxrc} init
  560 root       0:00 /usr/sbin/dropbear
  580 root       0:22 [ai0_P0_MAIN]
  593 root       0:02 [RTW_CMD_THREAD]
  615 root       0:00 wpa_supplicant -B -Dnl80211 -iwlan0 -c/configs/wpa_supplicant.conf
  622 root       0:03 [vif0_P0_MAIN]
  623 root       0:00 [vif1_P0_MAIN]
  624 root       0:14 [vpe0_P0_MAIN]
  625 root       0:00 [vpe0_P1_MAIN]
  626 root       0:00 [vpe0_P2_MAIN]
  627 root       0:00 [VEP_DumpTaskThr]
  637 root       0:00 [divp0_P0_MAIN]
  639 root       0:15 [venc0_P0_MAIN]
  640 root       0:00 [venc1_P0_MAIN]
  704 root       0:01 /usr/sbin/dropbear
  706 root       0:00 -sh
  760 root       0:10 [kworker/u2:2]
  768 root       0:00 sh
  769 root       0:00 sh
  800 root       0:04 [kworker/0:0]
  804 root       0:07 [kworker/u2:0]
  805 root       0:04 [kworker/0:1]
  813 root       0:04 [kworker/0:2]
  825 root       0:01 [kworker/u2:1]
  830 root       0:00 ps
~ # 
</pre>

</details><br>

Here's me messing around a bit in the shell. We can see the sys files that we can't see in the dumped firmware since they contain information about the system and it's hardware components during runtime

![rootshell](/assets/enabot_part1/rootshell.png)

We now have a working shell and can access the device. We see that the main process running is the EBO_FW_C file which now confirms this is the main file running the system.

## Part 1 Conclusion

We now have the tools and resources for hacking this thing. We were able to get two firmware versions by intercepting an update, and dumping the chip. We also got a rootshell on the device. We can now dive into the firmware and see how it actually interacts with the device through our shell. Next post will cover this as we dive into the EBO_FW_C file analysis and try look for vulnerabilities.

<br>

