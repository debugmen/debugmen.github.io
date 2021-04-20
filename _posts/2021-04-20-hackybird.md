---
layout: post
author: Etch
title: "HackTheBox: Hackybird"
date:   2021-04-19 18:32:53 -0500
categories: CTF-writeup
ctf-category: RE
---

# Hackybird (RE)

Hackybird was a pretty simple challenge once I learned how to go about solving it. I think they should add a hint to prevent wasted time.
It really came down to just knowing to use cheatengine to do all the work for you.

Still a cool challenge and I definitely learned new things that'll be helpful for future challenges.


<br/>

    hackybird
    628 solves / 30 points

    Even Mr. Miyagi cannot seem to beat this game. Flap your wings and show him the way!


[HackTheBox](https://hackthebox.eu)


<br/>


## Intial thoughts

First things first I ran it through [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy). This will just tell me what type of executable hackybird is.

<br/>

![detect](/assets/hackybird/detect.png)

<br/>

Okay, nothing special. Just a GUI program compiled with Visual Studio C/C++. 
I was thinking that this could have been a unity game, but clearly not. I now know not to bother
looking at this exectuable in [dnSpy](https://github.com/dnSpy/dnSpy).

Alright, I'll move it over to my windows VM and run it.

<br/>

![flappy101](/assets/hackybird/flappy101.png)


<br/>


Looks like just a regular bootleg version of flappybird. It plays exactly the same as regular flappy bird.
If you go through the pipes, you get a point, hit them or fall out of bounds and restart.


Just because I know this is an easy level challenge,
I'm going to assume all I need to do is get a certain score and I'll get the flag.
Obviously I don't know this for sure, but this is a pretty safe bet.


To do this, I'll try examining the program in Ghidra and see if I can just modify a jump instruction to
continually increase my points or something. Let's try it out.

<br/>

## Examing the program

Ill try analyzing it with Ghidra and see if there are any useful functions.

<br>

![stripped](/assets/hackybird/stripped.png)

<br>

I see all the function names have been stripped.
Pretty disappointing, especially since I've never worked with an executable like this
so I don't really have anything to go off of.

Here is one of the decompiled functions that has no name. I really don't understand what's going on,
and I know I probably don't need to.



![load_bit](/assets/hackybird/loadbit.png)

<br>

I see a few function calls such as LoadBitapW and GetObjectW. A quick [google search](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadbitmapw) shows these that
these functions are part of the winuser.h library. This just shows that its updating values and sending them to the window the executable is running in.

I skim through all the stripped functions, but I don't recognize anything useful, so I'll debug it with [x32dbg](https://x64dbg.com/#start) and see if I can
find where it increments my score.

<br/>

![dbg](/assets/hackybird/dbg.png)

<br/>

I tinkered around with this for a long time. There's a loop that the program keeps running through.
It updates the window in the DispatchMessage function call, but trying to track it down is going to be a pain.

After tinkering around with it for way too long, I knew there had to be a better way.
I'd heard of [cheat engine](https://www.cheatengine.org/downloads.php), but for some reason I assumed it was only for specific game engines.
I decided to try it anyway.

I looked up how to use cheat engine, and I found [this](https://www.youtube.com/watch?v=-A3xK8_oyRU) video. I watched a bit of it and it was clearly exactly what I needed. Shoutouts to Cyborg Elf.

<br>

## Using Cheat engine

So the way cheat engine works is it attaches to a process and you can easily find where a value
is stored in memory by checking what values change when something on screen changes.
You can then modify that value in real time and thus cheat the game. __Just watch the video above to see how to set everything up. It's actually pretty helpful__.

We care about changing the score, so
let's find where the score is being stored.

So I first put the value of 0 into the value box. 
This would check for addresses with value 0 that get used or modified.
Then I pressed space to start the game and hit new scan. 
This found all the addresses addresses being used that had value 0.
I died, and changed the value to 1. 
Then I played the game and went through the first pipe. 
Once my score went to 1, I hit next scan. 
This filtered values that had changed from 0 to 1. 
There were now less values in the box. 
Finally I repeated the process, but went to the 2nd pipe with the value set to 2. 
This left one address remaining which had to be where the score was being kept.

<br/>

![find_address](/assets/hackybird/findaddress.png)

<br/>

Now I can start the game, pause it with P, 
a discovery I made after trying to set a pause hotkey in cheat engine,
and then modify the score value!

<br/>

![500](/assets/hackybird/500.png)

<br/>

After playing around with some score values. I wasn't able to win. I messed around with cheatengine and saw I could right click the address and see what wrote to the address

<br/>

![write](/assets/hackybird/write.png)

<br/>

Sweet. It's a local address so it isn't some linked function where we'd have track down how it's called.

Lets look at the 2nd address, 0x40312D because the 0x403404 address only sets the score when the game starts. 

<br/>

![ghidra](/assets/hackybird/ghidra.png)

<br/>

Aha. A nice hidden undefined function. Although, even if I had found this earlier, I wouldn't have realized what it was doing
just from skimming.

After the increment is a compare to see if 999 is less than the score.
Let's go back to cheat engine and change our score to 999 and go through the first pipe to see if that's the win condition.

<br/>

![flag](/assets/hackybird/flag.png)


Overall I enjoyed this challenge. A lot of time would have been saved with a cheat engine hint,
but thats just part of solving CTF challenges.