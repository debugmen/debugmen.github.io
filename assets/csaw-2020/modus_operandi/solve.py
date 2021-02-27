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
