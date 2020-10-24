# Assignment 0x02 (Total 50 pt)

For each part, the goal is to run *solve* to get your flag (hash value).
With the correct input that exploits each part, you will get to run *solve*, and it will give you the hash valued based your NETID.

```bash
Last login: Fri Oct  9 08:08:03 2020 from 10.50.126.205
Type-in your NETID: kxj190011
Welcome! kxj190011
assign0x2-p0@cs6332-x86:~$ ./part0x00
CS6332 Crackme Level 0x00
Any integer larger than 0:1
Password OK :)
your netid is kxj190011, turn in the following hash value.
8978bc45e348daf65280dfd028e8a475
```

### Disassemblers and GDB Plug-in

IDA Pro, Radare2, and Ghidra disassemblers are install at class vm.
Regarding ARM environment, you need to first run
  (1) `$HOME/bin/qemu-stretch.sh` from GUI (Gnome) console
  (2) SSH into the emulated ARM environment using local ssh.
  ```bash
  $ ssh pi@localhost -p 5022
  ```

## Assignment set-up and connection information.

We have two test servers set-up for this assignment. One for x86 and another for
ARM (Raspberry Pi).  The student will log-in with different accounts for
different parts of the assignment. 

```
10.176.150.47 CS6332-ARM
10.176.150.50 CS6332-x86
```

```bash
# For part 1
$ ssh assign0x2-p1@CS6332-{ARM|x86}
assign0x2-p1@CS6332-{ARM|x86} password:      # type in "guest"
...
# For part 2
$ ssh assign0x2-p2@CS6332-{ARM|x86}
assign0x2-p2@CS6332-{ARM|x86} password:      # type in "guest"
...
# For part 3
$ ssh assign0x2-p3@CS6332-{ARM|x86}
assign0x2-p3@CS6332-{ARM|x86} password:      # type in "guest"
...
```

### Assignment binaries

Assignment binaries are available for download. Download and study it from a
local machine first. Once you figure out how to solve, you can log in to the
submission server to get flags for each part.

#### X86 Binaries

* [part0x00_x86]
* [part0x01_x86]
* [part0x02_x86]
* [part0x03_x86]

#### ARM Binaries

* [part0x00_arm]
* [part0x01_arm]
* [part0x02_arm]
* [part0x03_arm]

## Part 0: Warm-up (5pt + 5pt)

Log in to submission server and try the following

* CS6332-x86 
  ```bash
  ssh assign0x2-p0@10.176.150.50
  assign0x2-p0@10.176.150.50's password:

  ....

  Last login: Wed Oct  7 12:12:17 2020 from 10.50.126.205
  Type-in your NETID: mynetid
  Welcome! mynetid
  assign0x2-p0@cs6332-x86:~$ ./part0x00
  CS6332 Crackme Level 0x00
  Any integer larger than 0:100
  Password OK :)
  your netid is mynetid, turn in the following hash value.
  98459e2c4552af94349e6523b3f54912
  assign0x2-p0@cs6332-x86:~$
  ```

* CS6332-arm
  ```bash
  $ ssh assign0x2-p0@10.176.150.47
  assign0x2-p0@10.176.150.47's password:
  ...

  Type-in your NETID: mynetid
  Welcome! mynetid
  assign0x2-p0@cs6332-arm:~ $ ./part0x00
  CS6332 Crackme Level 0x00
  Any integer larger than 0:123
  Password OK :)
  your netid is mynetid, turn in the following hash value.
  85ce9bf4f7b7a7ac442182e1dc7a5e3f
  assign0x2-p0@cs6332-arm:~ $
    ```  

Make sure to verify the MD5 hashvalue of each binary from [md5sum.txt].
The [md5sum.txt.asc] is the digital signature signed by a [public key].

```bash
$ md5sum part01-x86
0c7350bd28f6dcb0f574b511b708e633  part0x00_x86
```

## Part 1 (5pt + 5pt): Control flow hijacking

### Preparation

Download *part0x01_{x86|arm}* to your local Linux host (Linux and ARM) to
analyze first. Once you get ready, you can login to your submission server to
confirm your input and get your hash value.

### Description

In this assignment, we are going to hijack the control flow of *part0x01_x86*
binary by overwriting the instruction pointer (EIP for x86, CP for arm). As a
first step, let's make it prints out "Password OK :)" without providing correct
answer to the question.

In this assignment, we are going to hijack the control flow of *part0x01_x86* binary
by overwriting the instruction pointer. As a first step, let's make it prints
out "Password OK :)" without providing correct answer to the question.

```
$ objdump -d part0x01_x86 
...
    80485ad:	e8 fe fd ff ff       	call   80483b0 <strcmp@plt>
    80485b2:	83 c4 08             	add    $0x8,%esp
    80485b5:	85 c0                	test   %eax,%eax
    80485b7:	75 1c                	jne    80485d5 <main+0x7f>
    80485b9:	68 9c 86 04 08       	push   $0x804869c
 -> 80485be:	e8 1d fe ff ff       	call   80483e0 <puts@plt>
    80485c3:	83 c4 04             	add    $0x4,%esp
    80485c6:	68 ab 86 04 08       	push   $0x80486ab
    80485cb:	e8 20 fe ff ff       	call   80483f0 <system@plt>
    80485d0:	83 c4 04             	add    $0x4,%esp
    80485d3:	eb 0d                	jmp    80485e2 <main+0x8c>
    80485d5:	68 c5 86 04 08       	push   $0x80486c5
    80485da:	e8 01 fe ff ff       	call   80483e0 <puts@plt>
    80485df:	83 c4 04             	add    $0x4,%esp
    80485e2:	b8 00 00 00 00       	mov    $0x0,%eax
    80485e7:	c9                   	leave
    80485e8:	c3                   	ret
```

!!!Note
    Upon a successful control hijack will eventually call *system()* function. Try to figure out its argument!

Please craft your input to overflow stack and overwrite RIP so that main function will return to `0x80485be`, subsequently print out "Password OK :)".

What happens if you provide a long string? Like below.

    $ echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | ./part0x01_x86
    CS6332 Crackme Level 0x00
    Password: Invalid Password!
    Segmentation fault

There are a few ways to check the status of the last segmentation fault:

1. checking logging messages

        $ dmesg | tail -1
        [237413.117757] part0x01_x86[353]: segfault at 41414141 ip 0000000041414141 sp 00000000ff92aef0
        error 14 in libc-2.24.so[f7578000+1b3000]

2. running gdb

        $ echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > input
        $ gdb ./part0x01_x86
        > run <input
        Starting program: ./part0x01_x86 <input
        CS6332 Crackme Level 0x00
        Password: Invalid Password!

        Program received signal SIGSEGV, Segmentation fault.
        0x41414141 in ?? ()

The following diagram illustrates the state of stack.

 <p><img alt="stack layout 1" src="https://i.imgur.com/T6x4QNn.jpg" width="75%"/></p>  

Which portion of string in input should be changed to `0x80485be`? 

### Control EIP ###

Let's figure out which input tainted the instruction pointer.

    $ echo AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ > input
    $ ./part0x01_x86 <input
    $ dmesg | tail -1
    [238584.915883] part0x01_x86[1095]: segfault at 48484848 ip 0000000048484848 sp 00000000ffc32f80
    error 14 in libc-2.24.s

What's the current instruction pointer (ip)? You can see that CPU was trying to run instruction at 0x48484848, and is seg-faulted.  To figure out what does ascii 0x48 translate to. You can lookup ascii table:

    $ man ascii

or from GDB, run the following to print the character.

    gdb-peda$ printf "%c\n", 0x48 

You can also figure out the exact shape of the stack frame by looking at
the disassembled code and tracking `%esp` as well.

    $ r2 part0x01_x86
    ...
    8048414:       55                      push   %ebp
    8048415:       89 e5                   mov    %esp,%ebp
    8048417:       83 ec 28                sub    $0x14,%esp
    ...
    804858c:	   83 c4 04                add    $0x4,%esp
    804858f:	   8d 45 ec                lea    -0x14(%ebp),%eax
    8048592:	   50                      push   %eax
    8048593:	   68 92 86 04 08          push   $0x8048692
    8048598:	   e8 63 fe ff ff          call   8048400 <scanf@plt>
    ...

The following diagram illustrates the state of stack.

<p><img alt="stack layout 2" src="https://i.imgur.com/9ZzeLOn.jpg" width="75%"/></p> 


#### Submission

On a successful exploitation, the program will run `solve` program which will
ask you to provide your NetID to generate your hash value. For this part of
assignment, please submit the followings

* Your *input* to exploit the buffer overflow vulnerability

## Part 2 (10 pt + 10 pt): Jump to your own shellcode

### Preparation

Download *part0x02_{x86|ARM}* to your local (Linux) host to analyze first.
Once you get ready, you can login to your submission server to confirm your
input and get your hash value. Please, check its binary to ensure stack section
(*GNU_STACK*) is in `RWE` permission which mean you can write and run machine
instructions  from stack.

```bash
$ readelf -W -l ./part02_x86|grep STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```

From this part, you will save your payload as *a file* and provide it as an
argument to the vulnerable program (part02_x86).

    echo -ne "payload\xef\xbe\xad\xde" > /tmp/myinput
    ./part0x02_x86 /tmp/myinput
    CS6332 Crackme Level 0x02
    Invalid Password!

> :warning: **Note**
    The submission server (and account for each part) is shared by the entire
    class, please try to use a unique filename for your input to avoid potential
    conflict.

### Description

From this assignment, You will craft an input
to overwrite the stack with shellcode and transfer control the beginning of
shellcode as *main()* function returns. You can google for *execve()
shellcode x86* that would eventually run */bin/sh* command for you.

Create an input that would run *shellcode* and subsequently give */bin/sh*
prompt. Please note that different lengths of environment variables + arguments
can also vary the resulting stack address widely from computer to computer. A
way to mitigate this issue is doing a NOP slide (see
https://old.liveoverflow.com/binary_hacking/protostar/stack5.html).

Upon a successful exploitation, you will see the shell prompt as below.

    assign0x2-p3@cs6332-arm:~ $ ./part0x03/tmp/input2
    CS6332 Crackme Level 0x02
    Invalid Password!
    $ id
    uid=1002(part02_x86) gid=1004(part02_x86_pwn) groups=1004(part02_x86_pwn),1003(part02_x86)
    $ ./solve
    Your NetID:   # input your NetID here.

> :warning: **Info**:
    Even with ASLR, stack location may vary slightly due to environment
    variables. You may consider padding your payload with sled (NOP instruction) to
    make your exploit robust.


> :warning: **Info**:
    if you want to make your environment as similar as possible, prepend
    `env -i` before your program command, i.e. `env -i ./part02_x86`.


### Output to submit

On successful exploitation, the program will run the `solve` program, which
will ask you to provide your NetID and return your hash value. For this part of
the assignment, please submit the followings

  1. Your *input* to exploit the buffer overflow vulnerability and deliver shellcode payload.
  2. Hash value generated by *solve* as a return for your NetID.

## Part 3 (10 pt for x86 bonus 10 pt ARM) : Return-to-libc

### Preparation

Download *part0x03_{x86|ARM}*
to your local (Linux) host to analyze first. Once you get ready, you can
login to your submission server to confirm your input and get your hash
value. This time, your stack is not executable anymore. Please check its
binary to ensure stack section (*GNU_STACK*) is in `RW` permission which mean
you can overwrite a stack, but cannot run any code from there.
```
$ readelf -W -l ./*part0x03_x86*|grep STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4
```

### Description

From this part of the assignment, you can still hijack the control by
overwriting the return address, but you don’t know where to transfer the
control, to run the desired command (say */bin/sh*) using *system()* function
provided by Glibc library. For its usage, please check out `man -s 3 system`.

Please write an input that would overwrite the return address of *main()* and
transfer the control aa *main()* function returns. You need to craft your
payload to call *system()* having a string (*/bin/sh*) as the first function
argument.

#### *system()* function example

The following snippet would give you a command prompt.

```bash
$ cat << EOF > /tmp/system.c
#include <stdlib.h>
// system.c
int main() {
    system("/bin/sh");
}
EOF

$ gcc /tmp/system.c
$ ./a.out
$ whoami
part03_x86
```

## Submission

Fill in the required entries form [submission.md] and submit to eLearning. 
> :warning: **Note**
    HEXADECIMAL inputs need to be in a proper format, which can reproduce the exploit from the submission server.
    E.g,
    ```
    ...\xab\xcd\xefAAAA\x12\x34\x56...
    ```

----
[part0x00_x86]:binaries/part0x00_x86
[part0x01_x86]:binaries/part0x01_x86
[part0x02_x86]:binaries/part0x02_x86
[part0x03_x86]:binaries/part0x03_x86


[part0x00_arm]:binaries/part0x00_arm
[part0x01_arm]:binaries/part0x01_arm
[part0x02_arm]:binaries/part0x02_arm
[part0x03_arm]:binaries/part0x03_arm

[Public key]:https://keys.syssec.org/vks/v1/by-fingerprint/CF752D40FFA8FEDD2CEA97A4779F92EF57756FF8
[md5sum.txt]:binaries/md5sum.txt
[md5sum.txt.asc]:binaries/md5sum.txt.asc

[submission.md]:submission.md
