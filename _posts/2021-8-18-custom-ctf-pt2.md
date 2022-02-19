---
layout: post
author: playoff-rondo
title:  "Custom CTF Platforms: Part 2"
date:   2021-08-18 2:01:37 -0500
categories: general
---
This is part 2 of the Custom CTF Platforms posts, where I explain some of the features and mistakes I made in the CTF platforms I have created

# The Newest Platform
This platform was created about 2 years after my first platform, my friends and I had messed with a few other versions in between these two, however this one contains most of the features of all the platforms combined. When I started this version, CTFd 1.0 still hadn't been released yet, I don't exactly remeber correctly if ctfs were using a beta version of CTFd but I would imagine so. 

My orginal team "Some Assembly Required" all graduated high school and we slowly stopped playing ctfs together and I did pretty much all the development for this final version, however my teammates helped out a lot in the prior version so I luckly did not have to do as much front end development. 

Since I was mostly working alone, I neglected good development practices and only made 3 commits.

![pic1](/assets/customctf/Pasted image 20210818205000.png)

## Features
Because most of the design was created as a group with my teammates, I think the overall design looks much better than the orginal blue theme.

### Main Page

![pic1](/assets/customctf/Pasted image 20210818205443.png)

We had a navbar containing links to:
- Challenges
- Scoreboard
- News
- About
- Learn
- Login
- Register

### Register Page
A couple extra fields were added since the first version. An affliation field and a password confirmation field.

![pic1](/assets/customctf/Pasted image 20210818210525.png)![pic1](/assets/customctf/

Now, we added some restrictions to teamname and password and had a check for a valid email address. 

Creating a team redirects to the main page and has a little notice saying team created. Not sure why I removed email verification.

### Reset Password
Theres a reset page as well but was unimplemented.

![pic1](/assets/customctf/Pasted image 20210818211844.png)

### Login Page
Login Page was a seperate page unlike the orginal version where you could login from any page.

![pic1](/assets/customctf/Pasted image 20210818212013.png)

Logging in redirects to the challenges page.

## Challenges Page
Again, challenge categories were hardcoded.

![pic1](/assets/customctf/Pasted image 20210818212155.png)

A graph at the top was added to show solve counts for each challenge.

Clicking a challenge box this time lead to a challenge page.

![pic1](/assets/customctf/Pasted image 20210818212432.png)

A graph was added to show correct/incorrect submissions and this time individual flag submission forms and hints button.

![pic1](/assets/customctf/Pasted image 20210818212552.png)

The schema for a challenge is:
```ruby
  create_table "challenges", force: true do |t|
    t.string   "title"
    t.string   "description"
    t.integer  "value"
    t.string   "hint"
    t.integer  "solves"
    t.integer  "submits"
    t.string   "category"
    t.datetime "created_at"
    t.datetime "updated_at"
  end
```

And there was a relationship with the teams table:
```ruby
  create_table "team_challenges", force: true do |t|
    t.integer  "team_id"
    t.integer  "challenge_id"
    t.datetime "created_at"
    t.datetime "updated_at"
  end
```

Notice how a challenge record does not include a flag. I don't know why I didn't create a real relationship between a challenge and a flag.

The flag structure was:
```ruby
  create_table "flags", force: true do |t|
    t.string   "grader"
    t.integer  "challenge_id"
    t.datetime "created_at"
    t.datetime "updated_at"
  end
```

A flag was associated to a challenge by its challenge id and contained a path to a grader. A grader was created for each challenge. 
An example of a grader is:
```ruby
class Grader
	def check(guess)
		guess = guess.downcase
		if guess=="flag{therac-25}"
			return true
		elsif guess == "flag{therac 25}"
			return true
		elsif guess == "flag{therac25}"
			return true
		elsif guess=="therac-25"
			return true
		elsif guess == "therac 25"
			return true
		elsif guess == "therac25"
			return true
		else
			return false
		end
	end
end
```
This allowed for multiple ways to validate if a flag could be correct.

An example of creating a challenge through ruby is:
```ruby
Challenge.create("title"=>"Song of my People","description"=>"I am a <a href='/challenges/songofmypeople.wav' target='_blank'>Robot</a>","hint"=>"I speak 1s and 0s","value"=>175,"solves"=>0,"category"=>"Misc").flag = Flag.create("grader"=>"songofmypeople.rb")
```

From the solves list on the challenge page, you can navigate to their team page.

### Team Page
Team Page contains a couple graphs and a list of the solved challenges.

![pic1](/assets/customctf/Pasted image 20210818213831.png)
![pic1](/assets/customctf/Pasted image 20210818213849.png)

The challenge links back to the challenge page.

### Scoreboard
The scoreboard shows a graph of the solve times of the top 5 players.

The admin account is shown on the graph but hidden on the scoreboard.

![pic1](/assets/customctf/Pasted image 20210818214209.png)

Clicking a team on the scoreboard links to their team page.

### News
The news schema is pretty similar to the orginal version but an author field is added:
```ruby
  create_table "news", force: true do |t|
    t.string   "author"
    t.string   "title"
    t.string   "text"
    t.datetime "created_at"
    t.datetime "updated_at"
  end
```

![pic1](/assets/customctf/Pasted image 20210818214559.png)

Not sure why I flipped it this time and newer posts were placed at the bottom.

### About
About page just had info about what is a ctf and what the rules were.

### Learn
Taking from picoCTF, where they had a learn page. We attempted to write a little about each category. Pretty much none of this information is useful.

![pic1](/assets/customctf/Pasted image 20210818214836.png)

## Lessons Learned
I hate webdev, still missing a lot of features that standard for most ctf platforms. Ruby on Rails is pretty cool and as much as I hate webdev, I sorta want to work with Rails and see what cool features they have added in the past few years.

We never ran a real ctf off this platform so who knows what bugs and edge cases I missed.  

Still need an admin panel, I actually had some code set up for an admin panel but really never implemented anything.

```ruby
<% if current_team %>
	<li><a style="color: #C90000" href="/team/<%=current_team.id%>">			<%=current_team.name%> : <%=current_team.score%> points </a></li>
	<li> <a href="/logout" class="nav_link" >logout</a></li>
	<% if current_team.is_admin==1 %>
		<li><a href="/admin">Admin Panel</a></li>
	<%end%>
<%else%>
```