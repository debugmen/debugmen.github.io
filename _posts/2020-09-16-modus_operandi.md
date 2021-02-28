---
layout: post
author: Veryyes
title: "CSAW 2020 CTF: Modus Operandi"
date: 2020-09-16 22:26:14 -0500
categories: CTF-writeup
ctf-category: Crypto
---

# modus_operandi
## Overview
They just give you a port to talk to. Here is an example 
```
$ nc crypto.chal.csaw.io 5001
Hello! For each plaintext you enter, find out if the block cipher used is ECB or CBC. Enter "ECB" or "CBC" to get the flag!
Enter plaintext: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ciphertext is:  722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447722c2ddf12df90f252d8f6b8d4988447ec8640be7f3b00e8386b228308a35a66
ECB or CBC? 
ECB
Enter plaintext: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ciphertext is:  6a09dbaf7c285f748d0b9ca15ccd66a124502e3e127ac62238c5ac1404513b837d2459474e0b842a3cf5cbe4ef68f122ec1a5a5c38b7f4917ecbee0c8ec75c2d5e89b2acfa32f56e3b534b139bc6664f912ae0d13822d1ee22fe4feb1b4dc6d62b4244462d3d8c6f990a1a0b673ae0f3ff60f34ef6c5f2544feab2f94d05a79f8f1762737ceb9788274b9bb39a2c2351
ECB or CBC? 
CBC
```

## Solution
So if you have any understanding about ECB, then you know it sucks and that identical message blocks encrypt to identical cipher text blocks.

All you need to do is figure out the blocksize. In this case just sending a empty string is enough as there is some mechanism to pad the message text before encryption. In this case, the message size is 32 characters.

To tell if something is being encrypted in ECB mode in this challenge, just send the same 32 bytes twice and the corresponding blocks should be excatly the same. If you look in the example above, you will see that the ECB cipher text repeats when the entire message is just all "A"s

### my solution script
```
#!/usr/bin/env python3
import hexdump

from pwn import *
import os
import time
plain = 'A' * 128
r = remote('crypto.chal.csaw.io', 5001)
count = 0

binary = []
def do_it():

    print(str(r.readuntil(":"), 'utf-8'))
    print(str(r.readline(), 'utf-8'))
    r.sendline(plain)
    print(str(r.readuntil(": "), 'utf-8'))
    cipher = str(r.readline(), 'utf8')
    cipher = cipher.strip()
    print(hexdump(cipher))
    print(len(cipher))
    c1 = cipher[0:16]
    c2 = cipher[32:48]
    print(c1, c2)
    if c1 == c2:
        print('ECB')
        binary.append(1)
        r.sendline("ECB")
    else:
        binary.append(0)
        print("CBC")
        r.sendline("CBC")

for i in range(176):
    do_it()
# r.interactive()

n = int(''.join(['0' if x==1 else '1' for x in binary]), 2)
print(n.to_bytes((n.bit_length() + 7) // 8, 'big').decode())
```

The last part was a little "guessy" after 176 iterations of guessing I received an EOF, but no flag. I did notice that the answers were always in the same order and there were only two possible choices, which implies a binary encoding

```
flag{ECB_re@lly_sUck$}
```