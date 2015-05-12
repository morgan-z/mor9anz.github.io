---
layout: post
title: "ASIS CTF Quals 2015 re100 Tera Writeup"
date: 2015-05-12 09:06:13 +0800
comments: true
#published: false
categories: [ctf, writeup, asis, 2015]
---
Running the program shows a progress bar and gives a core dump:
```
alpha@alpha-th:~/Copy/ctf/asis2015/re/100$ ./tera_85021482a68d6ed21892ea99b84f13f3
Please wait until my job be done 
%0.0000000 [                          Segmentation fault (core dumped)
```
Let's look at the output from strace (other lines are omitted):
<!-- more -->
```
alpha@alpha-th:~/Copy/ctf/asis2015/re/100$ strace ./tera_85021482a68d6ed21892ea99b84f13f3 > /dev/null 
...
open("/tmp/.tera", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
connect(6, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("134.79.129.105")}, 16) = -1 EINPROGRESS (Operation now in progress)
sendto(6, "GET /simulations/ds14_a/ds14_a_1"..., 99, MSG_NOSIGNAL, NULL, 0) = 99
recvfrom(6, "HTTP/1.1 404 Not Found\r\nDate: Tu"..., 16384, 0, NULL, NULL) = 506
write(4, "<!DOCTYPE HTML PUBLIC \"-//IETF//"..., 325) = 325
open("/tmp/.tera", O_RDONLY)            = 4
```
Segmentation fault happens right after the second open(), so something might be wrong while reading the file. From the output above we can see that the program sends GET request to 134.79.129.105 to fetch a file, and the response (starting with '<\!DOCTYPE HTML PUBLIC') is probably written to /tmp/.tera. Let's open /tmp/.tera:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /simulations/ds14\_a/ds14\_a\_1.0000ª×} was not found on this server.</p>
<hr>
<address>Apache/2.2.15 (Red Hat) Server at darksky.slac.stanford.edu Port 80</address>
</body></html>
```
As we can see, the response is indeed written to /tmp.tera, and we also know the domain of the ip address. But why is it 404 Not found?
Using gdb to set a break point before the function curl\_easy\_setopt() to examine its arguments, from which we can know the full URL of the file:
```
"http://darksky.slac.stanford.edu/simulations/ds14_a/ds14_a_1.0000\252\327}"
```
Alright, let's go to "http://darksky.slac.stanford.edu/simulations/ds14\_a/":
{% img cneter /images/asis2015/tera1.png  %}

There is indeed a file called ds14\_a\_1.0000 (we got response 404 because there are two ending non-ascii characters. We can change \252 to \0 to make the program work), and its size is 31T. Downloading the whole file doesn't seem to be realistic, so let's open IDA to see what the program does after downloading. 
Reading towards the end of sub\_400F19 routine, we can see the following code:
``` c
v39 = fopen(filename, "r");
v38 = n - 1;
v16 = n;
v17 = 0LL;
v14 = alloca(16 * ((n + 15) / 0x10));
ptr = &v16;
fread(&v16, 1uLL, n, v39);
for ( m = 0LL; v47 > m; ++m )
  printf("%c\n", (unsigned int)(char)(*((_BYTE *)ptr + v35[m]) ^ LOBYTE(v18[m])));
```
n is defined earlier in the same routine, and it is 34359739943392 (this also explains the seg fault earlier, since the file containing "404 Not found" is much smaller than this). It looks like the program wants to load the whole file into memory, and uses xor between some bytes (depends on array v35) of the file and bytes in array v18. Again, loading 31T into memory is not realistic, so we should use other ways to access the file without downloading it. After looking around at the [website](http://darksky.slac.stanford.edu/), I found that they have a bitbucket repo and [a tutorial](https://bitbucket.org/darkskysims/data_release#markdown-header-python-based-exploration) for accessing the data:
``` python
import thingking
ds14_a = thingking.HTTPArray("http://darksky.slac.stanford.edu/simulations/ds14_a/ds14_a_1.0000")
print ds14_a[10] #print the 10th byte
```
After installing python package thingking, we can access arbitrary bytes of the file without downloading it :)
Then the only thing left is to reverse the two arrays (v35 and v18 above). Luckily, they are constructed directly from the values in memory location: 4199552 and 4200064. In gdb:
``` plain
gdb-peda$ x/40gx  4199552
0x401480:	0x0000004c89617cf4	0x000000b4b5e95f83
0x401490:	0x000000e4598d686b	0x00000136a62674ef
0x4014a0:	0x000001837a65beb7	0x0000019fa831467c
0x4014b0:	0x000002a6202acd01	0x000004493f10645e
0x4014c0:	0x000004cdce6d65e4	0x000005028ec8de7e
0x4014d0:	0x0000056219504a56	0x000005bd2d191db8
0x4014e0:	0x0000072bd5d02592	0x0000073dee6d04fe
0x4014f0:	0x00000a25e5afe320	0x00000a73b464fb9e
0x401500:	0x00000b6259f6e34b	0x00000b9aa45094dc
0x401510:	0x00000bc548e0ea39	0x00000c7ac41ecc56
0x401520:	0x00000c85f073fb8b	0x00000c92536a9116
0x401530:	0x00000d930be6dabf	0x00000e61b989da40
0x401540:	0x00000f37999ca268	0x00000fb7c59b9d1f
0x401550:	0x00001018d3a3939d	0x000010202aed0369
0x401560:	0x000010e8fb926cf3	0x0000113bc38ea065
0x401570:	0x000013257504044f	0x000014fb0612dc3c
0x401580:	0x000016572370da92	0x0000173d75634441
0x401590:	0x00001b9d0f2d9374	0x00001ba90de42d8e
0x4015a0:	0x00001be9ef4c8f3e	0x00001bfda4b84e00
0x4015b0:	0x0000000000000000	0x0000000000000000

gdb-peda$ x/40wx 4200064
0x401680:	0x000000f2	0x0000009a	0x00000083	0x00000012
0x401690:	0x00000039	0x00000045	0x000000e7	0x000000f4
0x4016a0:	0x0000006f	0x000000a1	0x00000006	0x000000e7
0x4016b0:	0x00000095	0x000000f3	0x00000090	0x000000f2
0x4016c0:	0x000000f0	0x0000006b	0x00000033	0x000000e3
0x4016d0:	0x000000a8	0x00000078	0x00000037	0x000000d5
0x4016e0:	0x00000044	0x00000039	0x00000061	0x0000008a
0x4016f0:	0x000000fb	0x00000022	0x000000fa	0x0000009e
0x401700:	0x000000e7	0x00000011	0x00000039	0x000000a6
0x401710:	0x000000f3	0x00000033	0x00000000	0x40590000
```

After having the values of those 2 arrays, we can do xor operations to get the flag. There is a piece of python code for this:
{% include_code asis2015/tera.py %}

running the code:

```
alpha@alpha-th:~/Copy/ctf/asis2015/re/100$ python tera.py 
start..
A
S
I
S
{
3
1
4
9
a
d
5
d
3
6
2
9
5
8
1
b
1
7
2
7
9
c
c
8
8
9
2
2
2
b
9
3
}
```
then we get the flag: ASIS{3149ad5d3629581b17279cc889222b93}

This is my first writeup. Any comments are welcome :)
