# Adding a post

Put a new post in the `_posts` directory and make sure your headers at the top are all valid. Example from enabot part 3.
```
---
layout: post
author: Etch Lain3d
title:  "Enabot Hacking: Part 3"
toc: true
date:   2023-02-19 1:01:37 -0500 
categories: Hardware-series
ctf-category: PWN
tags: etch  lain3d hardware IoT re enabot
---
```

# Adding a tag

Add another tag to your post in the tags headers. Then run `generate_tags.py`. It will automatically put all missing tags from the `tags` folder and update them with the necessary content. If it fails, just put them in yourself