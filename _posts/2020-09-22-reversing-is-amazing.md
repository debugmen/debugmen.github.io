---
layout: post
author: Veryyes
title: "Tokyo Westerns CTF 2020: reversing is amazing"
date: 2020-09-22 20:21:22 -0500
categories: CTF-writeup
ctf-category: RE
---

# reversing is amazing

## Overview

The [binary](/assets/tokyo_western_2020/reverseing_is_amazing/rsa-5ad9c93834a56350ec040acc82ffe699a20f52767a8681f1c59bd5f33caa51bd) given takes in an input from the command line arguments
```
$ ./rsa-5ad9c93834a56350ec040acc82ffe699a20f52767a8681f1c59bd5f33caa51bd TWCTF{dongs}
Incorrect!
```

Threw the binary into Ghidra for dissassembly and grabbed the decomplication for main

[Decompiled Main](/assets/tokyo_western_2020/reverseing_is_amazing/main.c)

### Pulling the Private Key Out
Although it would've helped if I knew more about libcrypto/libssl, with some googling its pretty clear whats happening here.

![Main](/assets/tokyo_western_2020/reverseing_is_amazing/main_func.png)

The first while loop is loading some data at *0x555555555100* to the stack, *puVar6* in this case. Then it *memcpy*s the command line argument to *plain_text* and creates an rsa struct and calls *BIO_new_mem_buf*, which initialzes a new struct for a key (I think) at *local_a78* which points to where *puVar6* is pointing.
The resulting pointer gets used in *d2i_PrivateKey_bio*. At this point whatever is at *0x555555555100* is definitly a private key of some sort, so I ripped it out and base64'd it. We get a PEM file missing its header and footer, so I added the corresponding ones for an RSA Private Key.
```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCuaGHUc6YzMTPCGl6+9eyQ6oV36sLbYnO1KV3Cuzo80VC71NSe7jPdOzBFPOu+
8R9n5AVci5xvOla64rrsmqfQQ+28J1BGyECSLoe2JOP0wxvWva1VpFFkIxDRbBT9NagYoZ+rMxT5
PlA0xDwothDS/JCbl2DVmhPlPr840FJmfQIDAQABAoGAA36B30DF5qaos83Vchv5NloMfH+Okdii
GtIOV9VqcEd9R5YXAGwjS95gtDJpQrUP/QPbe6QsaSoRDMN4HT9n90K8ujiuzCbbyoEeSf36Br0y
gzueZh6bi0/1BF6B2mnbkX4PlmmhUZOzUPSEENhJJMawUSu8euAm30Lvu5tX4t0CQQDZi4Op9r2U
zO+TNFo17ouzTjJBfMacKl7wl8JFPY9oHjS3sF+vXp79QbjuXItayk63UXreVyE3qkCeIwpRHe1r
AkEAzTzLOX7O35/SyGedZIYi0+W8PwozMrjgP9ygf+am/IffToaAgTrk4F7hQRrQ9LjCTgCRmhrw
HjifylXioy3NtwJBAIEpe3frXq49azUMTU9eHaXNFLubGNTZt1rDz/2KSl34KTayymz2EhGt9t3X
Joo2ObxP7VKbisZhGFKL3XFCApcCQBKtUaEt1Q2ssbXjGAOp4Ul/Qp5KA1a+VEn7fe+lwdSBWOUA
gHlCLsnsWHtgQVvD5IrMqnNnuCpH5OK45iMLbAkCQD52ZGPUg7AOYka4Hw3jMD7pFkB5j4p3MGau
JebDO3V+q37/SgngOOy2XeuzhVnAbVVOqAXDce9gGNsrbcwekvw=
-----END RSA PRIVATE KEY-----
```

With OpenSSL I can verify this is an actual PEM file because it parses it correctly. i.e. `$ openssl asn1parse -in key.pem`. (More so a sanity check tbh).


### Cipher Text

Next we see that the binary calls *RSA_private_encrypt* to encrypt the user's input with and writes it to *cipher_text*.

Now it does a *memcmp* with the cipher_text and the giant blob of data that got loaded into the stack at the very beginning of the function. If those two bufers are equal then it returns `Correct!` otherwise  `Incorrect!`.

Clearly, that giant block of data on the stack is the encrypted version of the flag using the same RSA key. So all we gotta do is decrypt that cipher text, which we can do since we have the private key too.

First we gotta pull off the key. I used GDB by breaking right after it got loaded in and printed it out
```
00000000: 6f86 e496 29be 8a5e 21e2 c0da 25b7 95e0  o...)..^!...%...
00000010: 5f0a 6ce9 44db 124c 3a6c 1487 c636 6b6d  _.l.D..L:l...6km
00000020: 9506 1c2d 119e f872 cc9b 7487 73a7 5272  ...-...r..t.s.Rr
00000030: 0c5b 928d 7ca9 35eb c5d6 1e1c 9e7e d36e  .[..|.5......~.n
00000040: 4335 93d0 6c26 b495 e599 2863 5eeb ad40  C5..l&....(c^..@
00000050: ce26 67f7 32b2 030d 3024 9384 3a19 ac6f  .&g.2...0$..:..o
00000060: 11bb 0b5b 418d 9d49 1ab1 21d9 7943 bc83  ...[A..I..!.yC..
00000070: 1c36 98b9 5a53 d9f4 a399 3467 a28b ce06  .6..ZS....4g....
```

### Decryption
So If they used the **Private Key** to **Encrypt** the flag, then we have to generate a **Public Key** from the **Private Key** and **decrypt** the cipher text to obtain the flag.

Thankfully, OpenSSL does all this on the command line, so we don't have to write out own program to do it.

#### Generating a public key
The private key was saved to **key.pem**, and here I'm creating a public key from it named **key.pub**
```
$ openssl rsa -in key.pem -pubout > key.pub
writing RSA key

$ cat key.pub 
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuaGHUc6YzMTPCGl6+9eyQ6oV3
6sLbYnO1KV3Cuzo80VC71NSe7jPdOzBFPOu+8R9n5AVci5xvOla64rrsmqfQQ+28
J1BGyECSLoe2JOP0wxvWva1VpFFkIxDRbBT9NagYoZ+rMxT5PlA0xDwothDS/JCb
l2DVmhPlPr840FJmfQIDAQAB
-----END PUBLIC KEY-----
```

#### Decryption
The cipher text was saved to **cipher_text.bin**. and here is the command to decrypt the cipher text.

```
$ openssl rsautl -verify -inkey key.pub -pubin -in cipher_text.bin
TWCTF{Rivest_Shamir_Adleman}
```
