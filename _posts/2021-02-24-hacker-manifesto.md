---
layout: post
author: Vergil
title:  "Tenable CTF: Hacker Manifesto"
date:   2021-02-24 22:39:37 -0500
categories: CTF-writeup
ctf-category: RE
---

# Hacker Manifesto (RE):

This was a good challenge for practice in reversing a compression technique.
<br/><br/>
``
We found this file on a compromised host. It appears to contain data, but we're not sure how to decode it. Maybe you can figure it out?
``
<br/><br/>

We are given a single file with zero context other than it's name.
Let's check it out.

[hacker_manifesto.txt](/assets/hackermanifesto/hacker_manifesto.txt)


```
xxd hacker_manifesto.txt
```
```
00000000: 0000 4900 0020 0000 6100 006d 0308 2000  ..I.. ..a..m.. .
00000010: 0068 0304 6300 006b 0000 6500 0072 0000  .h..c..k..e..r..
00000020: 2c08 0465 0000 6e00 0074 0708 2012 0479  ,..e..n..t.. ..y
00000030: 0304 7700 006f 0704 6c00 0064 0000 2e01  ..w..o..l..d....
00000040: 042e 0000 0a00 004d 0000 6913 0465 0e04  .......M..i..e..
00000050: 6900 0073 240c 7713 1020 2004 680a 0474  i..s$.w..  .h..t
00000060: 0504 6213 0467 1708 7312 0869 0e08 2007  ..b..g..s..i.. .
00000070: 0463 0404 6f01 046c 2b0c 204c 0427 4b08  .c..o..l+. L.'K.
00000080: 7303 0461 2604 7443 0c74 2708 6e48 086f  s..a&.tC.t'.nH.o
00000090: 0f04 7405 046f 0000 660d 0c65 0708 7405  ..t..o..f..e..t.
000000a0: 0872 0604 6b32 0464 1304 2c10 0c69 3d08  .r..k2.d..,..i=.
000000b0: 630e 0461 0000 701a 1079 0508 657e 0868  c..a..p..y..e~.h
000000c0: 0604 7513 0862 6208 6506 086d 0404 2e4d  ..u..bb.e..m...M
000000d0: 0c0a 0104 449a 086e 1608 6e31 0465 2908  ....D..n..n1.e).
000000e0: 6331 0865 0000 7608 082e 0f04 2000 0054  c1.e..v..... ..T
000000f0: 310c 2726 0820 1304 6c01 0420 0408 69b5  1.'&. ..l.. ..i.
00000100: 082e 2908 4978 0c69 2b08 6a2c 0869 4108  ..).Ix.i+.j,.iA.
...
...
...
```

Now, at this point it's pretty obvious that this file is a somehow modifed version of the original 'Hacker Manifesto'. If you're unfamiliar with the document, here it is below:

```
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
The following was written shortly after my arrest...

                       \/\The Conscience of a Hacker/\/

                                      by

                               +++The Mentor+++

                          Written on January 8, 1986
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

        Another one got caught today, it's all over the papers.  "Teenager
Arrested in Computer Crime Scandal", "Hacker Arrested after Bank Tampering"...
        Damn kids.  They're all alike.

        But did you, in your three-piece psychology and 1950's technobrain,
ever take a look behind the eyes of the hacker?  Did you ever wonder what
made him tick, what forces shaped him, what may have molded him?
        I am a hacker, enter my world...
        Mine is a world that begins with school... I'm smarter than most of
the other kids, this crap they teach us bores me...
        Damn underachiever.  They're all alike.

        I'm in junior high or high school.  I've listened to teachers explain
for the fifteenth time how to reduce a fraction.  I understand it.  "No, Ms.
Smith, I didn't show my work.  I did it in my head..."
        Damn kid.  Probably copied it.  They're all alike.

        I made a discovery today.  I found a computer.  Wait a second, this is
cool.  It does what I want it to.  If it makes a mistake, it's because I
screwed it up.  Not because it doesn't like me...
                Or feels threatened by me...
                Or thinks I'm a smart ass...
                Or doesn't like teaching and shouldn't be here...
        Damn kid.  All he does is play games.  They're all alike.

        And then it happened... a door opened to a world... rushing through
the phone line like heroin through an addict's veins, an electronic pulse is
sent out, a refuge from the day-to-day incompetencies is sought... a board is
found.
        "This is it... this is where I belong..."
        I know everyone here... even if I've never met them, never talked to
them, may never hear from them again... I know you all...
        Damn kid.  Tying up the phone line again.  They're all alike...

        You bet your ass we're all alike... we've been spoon-fed baby food at
school when we hungered for steak... the bits of meat that you did let slip
through were pre-chewed and tasteless.  We've been dominated by sadists, or
ignored by the apathetic.  The few that had something to teach found us will-
ing pupils, but those few are like drops of water in the desert.

        This is our world now... the world of the electron and the switch, the
beauty of the baud.  We make use of a service already existing without paying
for what could be dirt-cheap if it wasn't run by profiteering gluttons, and
you call us criminals.  We explore... and you call us criminals.  We seek
after knowledge... and you call us criminals.  We exist without skin color,
without nationality, without religious bias... and you call us criminals.
You build atomic bombs, you wage wars, you murder, cheat, and lie to us
and try to make us believe it's for our own good, yet we're the criminals.

        Yes, I am a criminal.  My crime is that of curiosity.  My crime is
that of judging people by what they say and think, not what they look like.
My crime is that of outsmarting you, something that you will never forgive me
for.

        I am a hacker, and this is my manifesto.  You may stop this individual,
but you can't stop us all... after all, we're all alike.

                               +++The Mentor+++
_______________________________________________________________________________
```

From the hexdump, we can clearly see that pieces of the original text starting at the "I am a hacker, enter my world...' line.

It appears the data has been modified somehow. It's likely if we can reverse engineer what method was used to modify the text, then we will get a flag.

A task like this can be a bit of guess and check when there's so little to go on. I googled a couple compression algorithms, but its not easy to find something like this just from the data doing the obfuscation. 

Nothing really came up, so I just started trying to figure out if I could notice any patterns.

First thing to note, is there is clearly a diagonal pattern to the readable ascii. You can see that each line the ascii words shift two bytes to the left (or arguably one byte to the right).

```
00000000: 0000 4900 0020 0000 6100 006d 0308 2000  ..I.. ..a..m.. .
00000010: 0068 0304 6300 006b 0000 6500 0072 0000  .h..c..k..e..r..
00000020: 2c08 0465 0000 6e00 0074 0708 2012 0479  ,..e..n..t.. ..y
00000030: 0304 7700 006f 0704 6c00 0064 0000 2e01  ..w..o..l..d....
00000040: 042e 0000 0a00 004d 0000 6913 0465 0e04  .......M..i..e..
```
Let's fix this by changing the column width to 0xC instead of 0x10.

```
00000000: 0000 4900 0020 0000 6100 006d  ..I.. ..a..m
0000000c: 0308 2000 0068 0304 6300 006b  .. ..h..c..k
00000018: 0000 6500 0072 0000 2c08 0465  ..e..r..,..e
00000024: 0000 6e00 0074 0708 2012 0479  ..n..t.. ..y
00000030: 0304 7700 006f 0704 6c00 0064  ..w..o..l..d
0000003c: 0000 2e01 042e 0000 0a00 004d  ...........M
00000048: 0000 6913 0465 0e04 6900 0073  ..i..e..i..s
00000054: 240c 7713 1020 2004 680a 0474  $.w..  .h..t
00000060: 0504 6213 0467 1708 7312 0869  ..b..g..s..i
0000006c: 0e08 2007 0463 0404 6f01 046c  .. ..c..o..l
00000078: 2b0c 204c 0427 4b08 7303 0461  +. L.'K.s..a
00000084: 2604 7443 0c74 2708 6e48 086f  &.tC.t'.nH.o
00000090: 0f04 7405 046f 0000 660d 0c65  ..t..o..f..e
0000009c: 0708 7405 0872 0604 6b32 0464  ..t..r..k2.d
000000a8: 1304 2c10 0c69 3d08 630e 0461  ..,..i=.c..a
000000b4: 0000 701a 1079 0508 657e 0868  ..p..y..e~.h
000000c0: 0604 7513 0862 6208 6506 086d  ..u..bb.e..m
000000cc: 0404 2e4d 0c0a 0104 449a 086e  ...M....D..n
000000d8: 1608 6e31 0465 2908 6331 0865  ..n1.e).c1.e
000000e4: 0000 7608 082e 0f04 2000 0054  ..v..... ..T
000000f0: 310c 2726 0820 1304 6c01 0420  1.'&. ..l.. 
000000fc: 0408 69b5 082e 2908 4978 0c69  ..i...).Ix.i
00000108: 2b08 6a2c 0869 4108 202b 0867  +.j,.iA. +.g
...
...
...
```
Well, look at that. The ascii characters all lines up in perfectly neat little columns. It also becomes pretty clear that the 2-byte sections of 0x0000 line up at the beginning as well. From just looking at this, it looks like there is a very specific pattern of 2 bytes of metadata, followed by a single byte of ascii.


Now, at this point it becomes a little tough to figure out what is going on. After much trial and error I noticed three key clues in the data which enabled me to figure it out.


1. No letters go missing from the original file until they've already appeared at least once.
   
   This is evident almost immediately with the missing 'a' from the word hacker. The second missing letter is an 'e' which has also appeared at least once. This holds true for the entire document. A letter/pattern CANNOT go missing until it has already appeared once at least. This fact alone makes me expect that this is a compression algorithm which is using previous data to save space later in the document.

2. If we look at the "metadata" bytes in between the normal ascii, they are 0x000 until the point where letters start disapearing from the message.
   
   This leads us to believe that the metadata bytes are directly linked to the missing letters.

3. One VERY particular example of missing text clued me into exactly what is going on here. The word 'world' appears twice in the hacker manifesto within close succession. 

```
  world...
        Mine is a world
```
The first time world appears in the binary file, w o l d are all present, but almost immediately after, the next instance of world is represented by only a single w.
```
00000030: 0304 7700 006f 0704 6c00 0064  ..w..o..l..d
0000003c: 0000 2e01 042e 0000 0a00 004d  ...........M
00000048: 0000 6913 0465 0e04 6900 0073  ..i..e..i..s
00000054: 240c 7713 1020 2004 680a 0474  $.w..  .h..t
```

These facts led me to believe that we're dealing with a compression algorithm capable of taking small to medium chunks of text that were previously represented in the data, and referencing them at later times in order to not have to repeat them.

The key here is too try and find a connection between the metadata and the ascii.

```
00000000: 0000 4900 0020 0000 6100 006d  ..I.. ..a..m
0000000c: 0308 2000 0068 0304 6300 006b  .. ..h..c..k
```

After staring and a significant amount of guess and check, I was able to figure out the pattern.

The algorithm generates a string as it goes, then uses the first byte of the metadata as an offset backwards from the end of the 'running' string.

The 2nd byte of metadata is a length value.

The triplets follow this format:
```
|offset|length|ascii_char|
```
I'll show it in action step by step:

The first triplets have no metadata so you simply add the provided ascii character to the string in order.

```
00000000: 0000 49

String: 'I'
```

```
00000000: 0000 4900 0020

String: 'I '
```
```
00000000: 0000 4900 0020 0000 61
String: 'I a'
```

```
00000000: 0000 4900 0020 0000 6100 006d
String: 'I am'
```

Now, heres where it gets interesting:

```
00000000: 0000 4900 0020 0000 6100 006d
0000000c: 0308 20
String: 'I am a '
```
To end up updating the string this way, we simply need to take the 0x03 as a negative offset from the end of the string + 1. 
```
  123_
  |
  V
'I am'
```
From here, we use the 2nd byte 0x8 and divide that by 4 in order to know how many bytes from that calculated offset we should copy to the end of the string. In this case, it is 2 bytes.

```
   |
   V
'I| a|m'
```
We take this, append it to the end of the string, then we add the actual 0x20 from the ascii byte to the end afterwards. This gives us the string I showed you before.

```
00000000: 0000 4900 0020 0000 6100 006d
0000000c: 0308 20
String: 'I| a|m| a| '
           __---^^

String: 'I am a '
```

Lets do another for good measure.

```
00000000: 0000 4900 0020 0000 6100 006d
0000000c: 0308 20
String: 'I am a '
```

```
00000000: 0000 4900 0020 0000 6100 006d  ..I.. ..a..m
0000000c: 0308 2000 0068
String: 'I am a h'
```


```
00000000: 0000 4900 0020 0000 6100 006d  ..I.. ..a..m
0000000c: 0308 2000 0068 0304 63
Offset: 0x3
Length: 1
Ascii char: 'c'
              123
              |
              V
String: 'I am a h'

String: 'I am |a| h'

String: 'I am |a| h|a|'
               _----^

String 'I am a h|a|c'

String 'I am a hac'
```

This pattern continues for awhile, and you can see it could quickly become reasonably efficient as entire words get re-used often in a large text file. I wrote up a simple python script to automate this process.

{% highlight python %}
f = open('hacker_manifesto.txt', 'rb')
string = b''
counter = 0
while(f):
    counter += 3
    triplet = f.read(3)
    if not triplet:
        break
    print(triplet)
    if(triplet[0] == 0 and triplet[1] == 0):
        string = string + bytes([triplet[2]])
    else:
        print(triplet[0])
        mod = triplet[1] % 4

        pos = len(string) - (triplet[0] + mod * 256)
        slic = string[pos:(pos + triplet[1]//4)]
        print(slic)
        string = string + slic
        string = string + bytes([triplet[2]])
        print(string)
        print(len(string))
        if b'fifteenth' in string:
            print(string.find(b'nt'))
            print(hex(counter))
            binstart = True

            
        #string = string + bytes([triplet[2]])
{% endhighlight %}


After attempting to run my original script, it turns out some of the later triplets, have non-divisible by 4 length values. This put a small wrench in things, but its pretty easy to see whats happening here.

```
                                    V
000001d4: ff1c 61ff 1c65 ff10 2074 0964  ..a..e.. t.d
```
In order to re-use characters that are more than 256 characters behind the current end of the string, the algorithm uses a modulo 4 remainder on the length value to add 256 to the offset value.

So, in this case below, the offset is actually 256 + 0x74 since 9 % 4 = 1
```
000001d4: ff1c 61ff 1c65 ff10 2074 0964  ..a..e.. t.d
```

Let's run the script now that its modified to account for this:

``
b'I am a hacker, enter my world...\nMine is a world that begins with school... I\'m smarter than most of 
the other kids, this crap they teach us bores me... \n\nDamn underachiever.  They\'re all alike.\n\nI\'m in 
junior high or high school.  I\'ve listened to teachers explain for the fifteenth time how to reduce a 
fraction.  I understand it.  "No, Ms. Smith, I didn\'t show my work.  I did it in my head..."\n\nDamn kid.  
Probably copied it.  They\'re all alike.\n\nI made a discovery today.  I found a computer.  Wait a second, 
this is cool.  It does what I want it to.  If it makes a mistake, it\'s because I screwed it up.  Not 
because it doesn\'t like me...\n\nOr feels threatened by me...\nOr thinks I\'m a smart ass...\nOr doesn\'t 
like teaching and shouldn\'t be here...\nDamn kid.  All he does is play games.  They\'re all alike.\n\nAnd 
then it happened... a door opened to a world... rushing through the phone line like heroin through an 
addict\'s veins, an electronic pulse is sent out, a refuge from the day-to-day incompetencies is sought... 
a board is found.\n\nThe flag is "flag{TheMentorArrested}".\n\n"This is it... this is where I belong..." I 
know everyone here... even if I\'ve never met them, never talked to them, may never hear from them again... 
I know you all... Damn kid.  Tying up the phone line again.  They\'re all alike...\n\nYou bet your ass 
we\'re all alike... we\'ve been spoon-fed baby food at school when we hungered for steak... the bits of 
meat that you did let slip through were pre-chewed and tasteless.  We\'ve been dominated by sadists, or 
ignored by the apathetic.  The few that had something to teach found us will-ing pupils, but those few are 
like drops of water in the desert.\n'
1682
16
0x579
``

And there it is.
```
flag{TheMentorArrested}
```
