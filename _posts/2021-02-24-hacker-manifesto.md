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

[hacker_manifesto.txt](/assets/diceisyou/working_non_working.png)


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
00000110: 202b 0867 4d08 6f08 1c73 9d18 209c 0c76   +.gM.o..s.. ..v
00000120: 3508 6c77 0874 e208 65c5 0c6f 7518 6527  5.lw.t..e..ou.e'
00000130: 0473 f308 7887 046c 0b04 693f 0866 340c  .s..x..l..i?.f4.
00000140: 74a9 0c66 0c04 661c 0865 0809 680e 0869  t..f..f..e..h..i
00000150: 8b08 2040 0877 2f10 7236 0875 3004 6506  .. @.w/.r6.u0.e.
00000160: 0d66 8e0c 7468 086e 5410 209e 1473 0f04  .f..th.nT. ..s..
00000170: 6107 0820 0b09 2e12 0822 0000 4e19 042c  a.. ....."..N..,
00000180: 0504 4d11 042e 0404 533a 0469 4108 2c22  ..M.....S:.iA.,"
00000190: 0c64 f108 6e7b 0474 8808 6847 0c6d 5715  .d..n{.t..hG.mW.
000001a0: 6b3a 1464 1808 2023 0820 780c 6d16 0868  k:.d.. #. x.m..h
000001b0: 8c08 64f4 0c22 f41c 6b1c 082e 2408 502a  ..d.."..k...$.P*
000001c0: 046f 1005 6102 046c 1e08 6308 0470 fe08  .o..a..l..c..p..
000001d0: 6461 1854 ff1c 61ff 1c65 ff10 2074 0964  da.T..a..e.. t.d
000001e0: 9b10 64df 0863 2c04 7691 0879 b10c 640f  ..d..c,.v..y..d.
000001f0: 0479 6814 660a 0475 9d0c 6145 0c6d 4604  .yh.f..u..aE.mF.
00000200: 7599 0d2e 1508 57ee 0874 120c 730d 0463  u.....W..t..s..c
00000210: c608 648d 1d69 900d 6f29 1974 4808 6f86  ..d..i..o).tH.o.
00000220: 0d77 e811 4907 0861 0a09 2030 0c74 1404  .w..I..a.. 0.t..
00000230: 2e1c 0c66 0b10 6d13 046b 200c 6108 0869  ...f..m..k .a..i
00000240: fa0c 6b0b 042c 140c 27bc 0d65 4104 61c3  ..k..,..'..eA.a.
00000250: 0965 330c 73da 0965 3704 65df 1475 7404  .e3.s..e7.e..ut.
00000260: 2e36 084e fb09 201e 1c20 140c 645e 0c6e  .6.N.. .. ..d^.n
00000270: 130d 6cbe 0c20 ec15 0a01 044f 7b09 6674  ..l.. .....O{.ft
00000280: 096c 4608 7476 0472 0c09 74a4 1562 c708  .lF.tv.r..t..b..
00000290: 6d1e 144f 9811 6913 046b 1e08 49e9 0d61  m..O..i..k..I..a
000002a0: 631a 2004 0473 6709 2e1d 1464 511c 6c51  c. ..sg....dQ.lQ
000002b0: 1074 d711 690f 0467 2008 6e43 0873 7609  .t..i..g .nC.sv.
000002c0: 75b3 0a6e 1c0c 62c9 0d65 5b08 2e32 0c44  u..n..b..e[..2.D
000002d0: 631d 2e9a 0841 460d 681a 0864 f010 6903  c....AF.h..d..i.
000002e0: 0870 080a 7905 0467 1f08 65c1 0d20 6a1d  .p..y..g..e.. j.
000002f0: 206a 1d6b 6a11 4154 0c74 1808 6ec7 1068   j.kj.AT.t..n..h
00000300: be0a 70a8 102e ac0e 6143 0c6f 8908 6f11  ..p.....aC.o..o.
00000310: 1420 2e0e 6140 1f2e 1c08 72f7 0868 9010  . ..a@....r..h..
00000320: 74da 086f 0b04 6755 0e68 5408 7098 086e  t..o..gU.hT.p..n
00000330: 8e12 6e05 106b 9b14 6f0a 0e74 231c 610b  ..n..k..o..t#.a.
00000340: 0861 3c04 6411 0463 5711 761b 0469 690b  .a<.d..cW.v..ii.
00000350: 2c13 1065 2b04 6512 0872 3908 6906 0420  ,..e+.e..r9.i.. 
00000360: ca09 6c4c 1173 c40d 6e61 0f75 0404 2c72  ..lL.s..na.u..,r
00000370: 0c72 0c04 663d 0865 a00e 6f25 0974 d610  .r..f=.e..o%.t..
00000380: 61c0 042d 8b08 2d07 0c20 4308 63ff 0d65  a..-..-.. C.c..e
00000390: 580d 634a 0a73 3914 6f69 0c74 bc18 620c  X.cJ.s9.oi.t..b.
000003a0: 0461 3404 6415 1066 2c12 2ee7 0854 0613  .a4.d..f,....T..
000003b0: 6c15 0467 1410 2209 107b 120c 4d6b 0c6f  l..g.."..{..Mk.o
000003c0: 2804 4102 0472 4108 74e5 087d 1804 2e28  (.A..rA.t..}...(
000003d0: 0822 1708 694e 1469 4a14 740e 1c77 6a11  ."..iN.iJ.t..wj.
000003e0: 2008 0a62 b208 6ff9 082e d80e 200d 086b   ..b..o..... ..k
000003f0: 0a04 6f01 0b65 9d12 6ff6 0c68 8c19 2011  ..o..e..o..h.. .
00000400: 0c6e 3308 669e 1b6e 1f10 207e 0974 bf10  .n3.f..n.. ~.t..
00000410: 6dd3 086e 1014 747d 096b b21f 6816 106d  m..n..t}.k..h..m
00000420: d00c 6e1a 1468 eb09 72ef 1c68 1a08 20a7  ..n..h..r..h.. .
00000430: 0861 e808 2e55 0c49 6d18 79ce 0820 bd0d  .a...U.Im.y.. ..
00000440: 2e12 0c44 f31d 2ed7 0d79 8d11 750d 0520  ...D.....y..u.. 
00000450: 881d 6e88 1d61 3e14 20f7 1d65 f71d 69f7  ..n..a>. ..e..i.
00000460: 0d2e ea0c 594c 0c62 990c 7908 0872 7a12  ....YL.b..y..rz.
00000470: 20e0 0a27 251c 6125 1c20 130c 7613 0862   ..'%.a%. ..v..b
00000480: c70a 6e5e 0970 0f0a 6e7a 0566 c512 61c7  ..n^.p..nz.f..a.
00000490: 0e66 0e08 6428 0874 190f 6864 0f20 200d  .f..d(.t..hd.  .
000004a0: 6e2e 0c20 0704 758a 0865 4608 6420 0c72  n.. ..u..eF.d .r
000004b0: 1c08 74ce 086b 4619 6536 0869 0604 73d7  ..t..kF.e6.i..s.
000004c0: 0966 0c0d 610d 1161 7914 2012 0a64 ac08  .f..a..ay. ..d..
000004d0: 6547 0c6c 0904 702c 1e68 480c 72c8 0c72  eG.l..p,.hH.r..r
000004e0: 0404 2d5c 0865 7513 61a3 1261 4e0c 6ca8  ..-\.eu.a..aN.l.
000004f0: 0973 ed13 6596 1c6e a40e 6de3 0861 bd0d  .s..e..n..m..a..
00000500: 2094 0c73 620a 6926 0873 5009 6f7c 0869   ..sb.i&.sP.o|.i
00000510: 4804 6e06 0865 1714 747e 0c61 4f04 6107  H.n..e..t~.aO.a.
00000520: 0c74 680a 2e0f 1520 c808 7785 1868 3408  .th.... ..w..h4.
00000530: 2039 0a6d 1b08 68d1 166f 6d1b 2037 1620   9.m..h..om. 7. 
00000540: e70a 2027 0469 1009 2d1b 1070 6009 69a2  .. '.i..-..p`.i.
00000550: 0a2c 5108 75bf 106f ac0e 6644 0c61 aa0c  .,Q.u..o..fD.a..
00000560: 6cef 1264 bb08 70e0 1477 8e0c 729e 0e20  l..d..p..w..r.. 
00000570: b016 6528 0872 490a 0a                   ..e(.rI..
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
00000114: 4d08 6f08 1c73 9d18 209c 0c76  M.o..s.. ..v
00000120: 3508 6c77 0874 e208 65c5 0c6f  5.lw.t..e..o
0000012c: 7518 6527 0473 f308 7887 046c  u.e'.s..x..l
00000138: 0b04 693f 0866 340c 74a9 0c66  ..i?.f4.t..f
00000144: 0c04 661c 0865 0809 680e 0869  ..f..e..h..i
00000150: 8b08 2040 0877 2f10 7236 0875  .. @.w/.r6.u
0000015c: 3004 6506 0d66 8e0c 7468 086e  0.e..f..th.n
00000168: 5410 209e 1473 0f04 6107 0820  T. ..s..a.. 
00000174: 0b09 2e12 0822 0000 4e19 042c  ....."..N..,
00000180: 0504 4d11 042e 0404 533a 0469  ..M.....S:.i
0000018c: 4108 2c22 0c64 f108 6e7b 0474  A.,".d..n{.t
00000198: 8808 6847 0c6d 5715 6b3a 1464  ..hG.mW.k:.d
000001a4: 1808 2023 0820 780c 6d16 0868  .. #. x.m..h
000001b0: 8c08 64f4 0c22 f41c 6b1c 082e  ..d.."..k...
000001bc: 2408 502a 046f 1005 6102 046c  $.P*.o..a..l
000001c8: 1e08 6308 0470 fe08 6461 1854  ..c..p..da.T
000001d4: ff1c 61ff 1c65 ff10 2074 0964  ..a..e.. t.d
000001e0: 9b10 64df 0863 2c04 7691 0879  ..d..c,.v..y
000001ec: b10c 640f 0479 6814 660a 0475  ..d..yh.f..u
000001f8: 9d0c 6145 0c6d 4604 7599 0d2e  ..aE.mF.u...
00000204: 1508 57ee 0874 120c 730d 0463  ..W..t..s..c
00000210: c608 648d 1d69 900d 6f29 1974  ..d..i..o).t
0000021c: 4808 6f86 0d77 e811 4907 0861  H.o..w..I..a
00000228: 0a09 2030 0c74 1404 2e1c 0c66  .. 0.t.....f
00000234: 0b10 6d13 046b 200c 6108 0869  ..m..k .a..i
00000240: fa0c 6b0b 042c 140c 27bc 0d65  ..k..,..'..e
0000024c: 4104 61c3 0965 330c 73da 0965  A.a..e3.s..e
00000258: 3704 65df 1475 7404 2e36 084e  7.e..ut..6.N
00000264: fb09 201e 1c20 140c 645e 0c6e  .. .. ..d^.n
00000270: 130d 6cbe 0c20 ec15 0a01 044f  ..l.. .....O
0000027c: 7b09 6674 096c 4608 7476 0472  {.ft.lF.tv.r
00000288: 0c09 74a4 1562 c708 6d1e 144f  ..t..b..m..O
00000294: 9811 6913 046b 1e08 49e9 0d61  ..i..k..I..a
000002a0: 631a 2004 0473 6709 2e1d 1464  c. ..sg....d
000002ac: 511c 6c51 1074 d711 690f 0467  Q.lQ.t..i..g
000002b8: 2008 6e43 0873 7609 75b3 0a6e   .nC.sv.u..n
000002c4: 1c0c 62c9 0d65 5b08 2e32 0c44  ..b..e[..2.D
000002d0: 631d 2e9a 0841 460d 681a 0864  c....AF.h..d
000002dc: f010 6903 0870 080a 7905 0467  ..i..p..y..g
000002e8: 1f08 65c1 0d20 6a1d 206a 1d6b  ..e.. j. j.k
000002f4: 6a11 4154 0c74 1808 6ec7 1068  j.AT.t..n..h
00000300: be0a 70a8 102e ac0e 6143 0c6f  ..p.....aC.o
0000030c: 8908 6f11 1420 2e0e 6140 1f2e  ..o.. ..a@..
00000318: 1c08 72f7 0868 9010 74da 086f  ..r..h..t..o
00000324: 0b04 6755 0e68 5408 7098 086e  ..gU.hT.p..n
00000330: 8e12 6e05 106b 9b14 6f0a 0e74  ..n..k..o..t
0000033c: 231c 610b 0861 3c04 6411 0463  #.a..a<.d..c
00000348: 5711 761b 0469 690b 2c13 1065  W.v..ii.,..e
00000354: 2b04 6512 0872 3908 6906 0420  +.e..r9.i.. 
00000360: ca09 6c4c 1173 c40d 6e61 0f75  ..lL.s..na.u
0000036c: 0404 2c72 0c72 0c04 663d 0865  ..,r.r..f=.e
00000378: a00e 6f25 0974 d610 61c0 042d  ..o%.t..a..-
00000384: 8b08 2d07 0c20 4308 63ff 0d65  ..-.. C.c..e
00000390: 580d 634a 0a73 3914 6f69 0c74  X.cJ.s9.oi.t
0000039c: bc18 620c 0461 3404 6415 1066  ..b..a4.d..f
000003a8: 2c12 2ee7 0854 0613 6c15 0467  ,....T..l..g
000003b4: 1410 2209 107b 120c 4d6b 0c6f  .."..{..Mk.o
000003c0: 2804 4102 0472 4108 74e5 087d  (.A..rA.t..}
000003cc: 1804 2e28 0822 1708 694e 1469  ...(."..iN.i
000003d8: 4a14 740e 1c77 6a11 2008 0a62  J.t..wj. ..b
000003e4: b208 6ff9 082e d80e 200d 086b  ..o..... ..k
000003f0: 0a04 6f01 0b65 9d12 6ff6 0c68  ..o..e..o..h
000003fc: 8c19 2011 0c6e 3308 669e 1b6e  .. ..n3.f..n
00000408: 1f10 207e 0974 bf10 6dd3 086e  .. ~.t..m..n
00000414: 1014 747d 096b b21f 6816 106d  ..t}.k..h..m
00000420: d00c 6e1a 1468 eb09 72ef 1c68  ..n..h..r..h
0000042c: 1a08 20a7 0861 e808 2e55 0c49  .. ..a...U.I
00000438: 6d18 79ce 0820 bd0d 2e12 0c44  m.y.. .....D
00000444: f31d 2ed7 0d79 8d11 750d 0520  .....y..u.. 
00000450: 881d 6e88 1d61 3e14 20f7 1d65  ..n..a>. ..e
0000045c: f71d 69f7 0d2e ea0c 594c 0c62  ..i.....YL.b
00000468: 990c 7908 0872 7a12 20e0 0a27  ..y..rz. ..'
00000474: 251c 6125 1c20 130c 7613 0862  %.a%. ..v..b
00000480: c70a 6e5e 0970 0f0a 6e7a 0566  ..n^.p..nz.f
0000048c: c512 61c7 0e66 0e08 6428 0874  ..a..f..d(.t
00000498: 190f 6864 0f20 200d 6e2e 0c20  ..hd.  .n.. 
000004a4: 0704 758a 0865 4608 6420 0c72  ..u..eF.d .r
000004b0: 1c08 74ce 086b 4619 6536 0869  ..t..kF.e6.i
000004bc: 0604 73d7 0966 0c0d 610d 1161  ..s..f..a..a
000004c8: 7914 2012 0a64 ac08 6547 0c6c  y. ..d..eG.l
000004d4: 0904 702c 1e68 480c 72c8 0c72  ..p,.hH.r..r
000004e0: 0404 2d5c 0865 7513 61a3 1261  ..-\.eu.a..a
000004ec: 4e0c 6ca8 0973 ed13 6596 1c6e  N.l..s..e..n
000004f8: a40e 6de3 0861 bd0d 2094 0c73  ..m..a.. ..s
00000504: 620a 6926 0873 5009 6f7c 0869  b.i&.sP.o|.i
00000510: 4804 6e06 0865 1714 747e 0c61  H.n..e..t~.a
0000051c: 4f04 6107 0c74 680a 2e0f 1520  O.a..th.... 
00000528: c808 7785 1868 3408 2039 0a6d  ..w..h4. 9.m
00000534: 1b08 68d1 166f 6d1b 2037 1620  ..h..om. 7. 
00000540: e70a 2027 0469 1009 2d1b 1070  .. '.i..-..p
0000054c: 6009 69a2 0a2c 5108 75bf 106f  `.i..,Q.u..o
00000558: ac0e 6644 0c61 aa0c 6cef 1264  ..fD.a..l..d
00000564: bb08 70e0 1477 8e0c 729e 0e20  ..p..w..r.. 
00000570: b016 6528 0872 490a 0a         ..e(.rI..
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
