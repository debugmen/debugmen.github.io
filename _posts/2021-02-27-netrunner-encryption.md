---
layout: post
author: Veryyes
title: "Tenable CTF: Netrunner Encryption"
date: 2021-02-27 17:17:50 -0500
categories: CTF-writeup
ctf-category: Crypto
---

# Netrunner Encryption

## Overview
This challenge is a classic ECB mode CTF Challenge. The challenge description has a link to a PHP Webpage that simply concatenates your input and the flag together, then pads it to 16 bytes chunks.

Below is the source:

```
<html>
<body>
  <h1>Netrunner Encryption Tool</h1>
  <a href="netrun.txt">Source Code</a>
  <form method=post action="crypto.php">
  <input type=text name="text_to_encrypt">
  <input type="submit" name="do_encrypt" value="Encrypt">
  </form>

<?php

function pad_data($data)
{
  $flag = "flag{wouldnt_y0u_lik3_to_know}"; 

  $pad_len = (16 - (strlen($data.$flag) % 16));
  return $data . $flag . str_repeat(chr($pad_len), $pad_len);
}

if(isset($_POST["do_encrypt"]))
{
  $cipher = "aes-128-ecb";
  $iv  = hex2bin('00000000000000000000000000000000');
  $key = hex2bin('74657374696E676B6579313233343536');
  echo "</br><br><h2>Encrypted Data:</h2>";
  $ciphertext = openssl_encrypt(pad_data($_POST['text_to_encrypt']), $cipher, $key, 0, $iv); 

  echo "<br/>";
  echo "<b>$ciphertext</b>";
}
?>
</body>
</html>

```

## Observations

You'll notice that the IV and encryption key are the same for every request and that the encryption scheme is in ECB mode i.e. message blocks encrypt to the same cipher text block regardless of position in the message

## Leaking parts of the encrypted flag
Since we control the first portion of the cipher text followed by the encrypted flag and know the block size already via the source, we can construct a message block where all but the last byte in the block is know and encrypt it. This allows us to check what value that last byte is by checking all possible values for that byte by sending more messages to the website to encrypt.

For example:

Let our first message `M1 = aaaaaaaaaaaaaaa`. which is 15 'a' characters, one short of the block size. This means the first block will contain 15 'a's and the first character of the flag. So when we encrypt `M1` we get some cipher text block we call `C1`. Next we guess and check for that last character by encrypting `M1' = M1 + X`
where `X` is the single letter we are guessing. We keep trying different `X`s until `M1'` encrypts to `C1` meaning we've correctly guessed the first character of the flag. In this case the first letter is 'f'.

We repeat this process, adding on each known letter of the flag to our message until we get the whole flag.

```
M2 = aaaaaaaaaaaaaaf
M3 = aaaaaaaaaaaaafa
M4 = aaaaaaaaaaaafla
M5 = aaaaaaaaaaaflag
```
and so forth.


## Solution

For my solution, instead of using an inital 15 'a's to start guessing with, I used 79 = (4*16) + 15 'a's to pad my message with an extra 4 blocks of 'a's in case the flag is bigger than a single block.

```
import requests
import base64
import string

def encrypt(data:str):
    r = requests.post('http://167.71.246.232:8080/crypto.php', data={'text_to_encrypt': data, 'do_encrypt':'Encrypt'})

    res = r.content.split(b'</form>\n\n</br><br><h2>Encrypted Data:</h2><br/><b>')[1]
    res = res.split(b'</b>')[0]
    return base64.b64decode(res)


correct = []
padding = 64 + 15
for i in range(64):
    p1 = 'a' * (padding-i)
    c1 = encrypt(p1)
    for char in string.printable:
        p2 = ('a' * (padding-i)) + ''.join(correct) + char
        c2 = encrypt(p2)
        if c1[0:64+16] == c2[0:64+16]:
            print(char)
            correct.append(char)
            break

```

We don't know how big the flag actually is until we try it and see that it ended with a '}', so my code just keeps going even after it prints the whole flag

Run the code and we get:

`flag{b4d_bl0cks_for_g0nks}`