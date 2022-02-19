---
layout: post
author: playoff-rondo
title:  "Custom CTF Platforms: Part 1"
date:   2021-08-18 1:01:37 -0500
categories: general
---
Over the past 8ish years I've played CTFs, I created a couple CTF platforms with a some help from some friends. This was before CTFd was a thing and every CTF seemed to have their own custom platform.

This is part 1 of 2 posts where, I'm going to revist two of my platforms and go over some of the features I implemented and some mistakes made during its creation.

# The Orignal Platform
I created this with my friend Alex a little after the first picoCTF competition in hopes to run a CTF for my high school and recruit new teammates to play with me in the next picoCTF.

Alex mostly spent time on the front end while I developed the backend with Rails.
Unfortunately, looking back at our commit history, most of our commit messages were garbage so its a little hard to trackdown when we added certain features.

![pic1](/assets/customctf/Pasted image 20210818192714.png)

## Features
We tried to add some features that we tended to see in other CTF platforms. Going through page by page, I list what we implemented.

### Main Page

![pic2](/assets/customctf/Pasted image 20210818193014.png)

We have a navbar with links to
- News Page
- Challenges
- Scoreboard
- Game Log
- Chat

On every page, we can login with the form underneith the navbar.

We also have the registration on this page. For registration, we only required Email, Team Name, and Password. No password confirmation, no captcha or anything like that. Only one account per team as well. No password requirements either.

Also seems to allow multiple teams per email, but can not register a team name that has already been registered.

A little message also is shown confirming a user was created.

![pic3](/assets/customctf/Pasted image 20210818193730.png)

Upon team creation, an email is sent with a code to validate the account:
```
Subject: Thank you for Registering for SARCTF
Mime-Version: 1.0
Content-Type: text/html;
 charset=UTF-8
Content-Transfer-Encoding: 7bit

<p>Welcome playoff-rondo!</p>
<p>================================================</p>
<br>
<p>Thank you for registering for the 2014 SAR CTF!</p>
<p>To login and compete, please go to http://ctf.wtwoodson.org/validate and use this access code 183a9c38f20ad7e4fd992ed88523185b.</p>
<br>
<p>Thanks for registering and competing!</p>
```
However, I decied to have usersbe validated by default when setting this up because I was unsure if the email would actually get sent right now. (It didn't)
```
diff --git a/app/controllers/main_controller.rb b/app/controllers/main_controller.rb
index 60b6a08..c1c006b 100644
--- a/app/controllers/main_controller.rb
+++ b/app/controllers/main_controller.rb
@@ -26,7 +26,7 @@ class MainController < ApplicationController
           @user.before_save
           @user.score = 0
           @user.flags_scored=""
-          @user.isvalidated="false"
+          @user.isvalidated="true"
       if @user.save
         flash[:notice] = "User created."
          MailMan.validate(@user).deliver
```

The records in the database after creating a team looks like:
```
=> #<ActiveRecord::Relation [#<User id: 1, username: "test", password: "31a9ce29645d928232468b0e2c8b36dd", salt: "40385", score: 0, email: "famissing@yahoo.com", isvalidated: "true", access_code: "f2e71c328a23b279a4deb106b0806a8a", flags_scored: "", message: "", created_at: "2021-08-18 23:33:59", updated_at: "2021-08-18 23:33:59">, #<User id: 2, username: "playoff-rondo", password: "dd498178000f7835c41aea570dd0d33f", salt: "66686", score: 0, email: "famissing@yahoo.com", isvalidated: "true", access_code: "183a9c38f20ad7e4fd992ed88523185b", flags_scored: "", message: "", created_at: "2021-08-18 23:34:42", updated_at: "2021-08-18 23:34:42">]>
irb(main):003:0>
```
I do hash the password with a salt and store that. Other fields for the user (Team) are:
```ruby
  create_table "users", force: true do |t|
    t.string  "username"
    t.string  "password"
    t.string  "salt"
    t.integer "score"
    t.string  "email"
    t.string  "isvalidated"
    t.string  "access_code"
    t.text    "flags_scored", limit: 2147483647
    t.text    "message"
    t.string  "created_at"
    t.string  "updated_at"
  end
```
`flags_scored` is basically a big string of the names of each challenge a user has solved.
`message` is something that can be set so a persistent message can be displayed to that team. I used it when looking at logs and saw people submit flags that were close but incorrect. I would manually send them a message saying they are close and maybe fix capitalizations or something like that.

### Validate Page

![pic4](/assets/customctf/Pasted image 20210818194153.png)

Pretty simple, use the code from the email to validate your team.
Validating gives a message for confirmation and redirects to the challenge page, however you still need to log in.

### News Page
This page is where I would create posts that are messages I want all teams to see. The posts are ordered newest on top.

![pic5](/assets/customctf/Pasted image 20210818195304.png)

The news schema was pretty short:
```ruby
  create_table "news", force: true do |t|
    t.text   "title"
    t.text   "message"
    t.string "created_at"
    t.string "updated_at"
  end
```

I had no admin panel so to add new posts during competition, I needed to use the rails console and create a post from there.
```ruby
irb(main):001:0> News.create("title"=>"Rotate Me (300) updated","message"=>"The Rotate Me challenge has been updatyed with a new binary for small fixes")
   (0.2ms)  BEGIN
  SQL (0.2ms)  INSERT INTO `news` (`created_at`, `message`, `title`, `updated_at`) VALUES ('2021-08-18 23:52:41', 'The Rotate Me challenge has been updatyed with a new binary for small fixes', 'Rotate Me (300) updated', '2021-08-18 23:52:41')
   (4.0ms)  COMMIT
=> #<News id: 2, title: "Rotate Me (300) updated", message: "The Rotate Me challenge has been updatyed with a ne...", created_at: "2021-08-18 23:52:41", updated_at: "2021-08-18 23:52:41">
```

### Challenges
For the challenges page, the categories were hardcoded and there was one universal form for flag submission. At this time, i believe most if not all CTFs were scored statically, at least I can't remember any ones that didn't.

![pic6](/assets/customctf/Pasted image 20210818195809.png)

The challenges schema was:
```ruby
  create_table "challenges", force: true do |t|
    t.string  "name"
    t.string  "description"
    t.string  "flag"
    t.integer "value"
    t.string  "category"
    t.integer "solves"
    t.string  "created_at"
    t.string  "updated_at"
  end
```

Each challenge box showed the challenge name followed by the point value and underneith was the solve count.

Clicking on a challenge expanded the challenge box to display the description.

![pic7](/assets/customctf/Pasted image 20210818200159.png)

Pretty much all the descriptions were links to challenge files so the "fit" within the boxes.
It could get uglier when expanding multiple in the same row.

![pic8](/assets/customctf/Pasted image 20210818200614.png)

Solving a challenege will display a message with the amount of points scored and increase their total score.

![pic9](/assets/customctf/Pasted image 20210818200727.png)

The challenge box will be green and say "completed"

![pic10](/assets/customctf/Pasted image 20210818200759.png)

The reason for the universal flag submission form may have had to do with the one bonus flag that was hidden on the website.

### Scoreboard
The scoreboard lists the rankings with each team clickable.

![pic11](/assets/customctf/Pasted image 20210818201049.png)

Clicking a team goes to their team page.

### Team Page
The team page shows their current place with how many points they have as well as which challenges have been solved.

Then there is a "mini scoreboard" showing the team ahead and behind the current team.

![pic12](/assets/customctf/Pasted image 20210818201309.png)
![pic13](/assets/customctf/Pasted image 20210818201333.png)


### Game Log
The game log just shows all the flag submissions, whether correct or incorrect and you can click on a team from the log to get to their team page,

![pic13](/assets/customctf/Pasted image 20210818201810.png)

### Chat
Lastly, I embeded a Kiwi IRC client so teams can chat about the ctf.
This was all before discord was a thing so pretty much every ctf had an irc server/channel dedicated to discussing the ctf.

![pic14](/assets/customctf/Pasted image 20210818201956.png)

# Mistakes
Besides the mistakes mentioned in the features section, other mistakes I made included not having an admin panel as it was a pain to update things in the database through the rails console.

Also, someone from team Hexpresso, reached out to me asking to use this platform to interview potential new members. One of their more senior teammates ended up finding some vuln which allowed them to take over the server I was hosting it on. I don't recall them telling me what they actually did to exploit it, however I dont believe they did anything harmful besides seeing if it was possible to break.

There are a ton of other missing features which I attempted to add in the newer version of the platform.

In the end, only like 20 students in my high school attempted the CTF. Only a few of them actually tried more than a few minutes and of them most of them were my friends.

There was however one person who ended up getting second I believe and while we did find out he was cheating ([https://hackforums.net/showthread.php?tid=4470038](https://hackforums.net/showthread.php?tid=4470038)), we invited him to join our picoCTF team to give him a chance.
