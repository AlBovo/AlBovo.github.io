---
title: "M0lecon CTF 2023 Beginner"
date: 2024-05-27T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["m0lecon", "ctf", "binary", "crypto", "web", "m0lecon2023"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Some writeups of the m0lecon Beginner ctf 2023 edition."
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
    alt: "M0lecon CTF 2023 Beginner" # alt text
    caption: "Some writeups of the m0lecon Beginner ctf 2023 edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# m0lecon CTF 2023 Beginner
![m0lecon logo](/images/m0lecon.png)

## Web 🌐
### Unguessable

This challenge was the easiest in the CTF (it had __more solves than__ the sanity check, lol). In fact, to solve it, all you had to do was understand that the website fetched the flag from an endpoint `/vjfYkHzyZGJ4A7cPNutFeM/flag`, and to obtain it we ~~opened the endpoint~~ sniffed the whole network.

```javascript
...
function update(res) { // the function used by the site to get the flag
    if (res === "wrong") {
    card.style.backgroundColor = "red";
    text.innerText = "Wrong, try again";
    } else {
    card.style.backgroundColor = "green";
    fetch("/vjfYkHzyZGJ4A7cPNutFeM/flag")
        .then((response) => response.text())
        .then((str) => {
        text.innerText = str
        });
    }

    card.removeAttribute("hidden");
}
...
```
### Secure Access
The challenge had an attachment, a Python bytecode file (.pyc), which once decompiled, resulted in this function:
```python
def generate_token(nonce: str):
    username = 'user001'
    secret = hashlib.sha256(username.encode() + nonce.encode()).hexdigest()
    bundle = {'user':username, 'secret':secret}
    return base64.b64encode(json.dumps(bundle).encode())
```

The challenge required an username (obviously `admin`) and an access token that could be calculated using a nonce provided to the endpoint `/stage2?username=admin`. Once the token was calculated using the previously mentioned function, all that was needed to obtain the flag was to send the token and automatically gain access to the admin panel.

![the beatiful home page of the challenge](/images/m0leconWeb.png)

### Piano Carriera
For those who participated in the `m0lecon CTF beginner 2021` and remembered the Exam Booking challenge, they might recall the scenario where the user had to register for an exam when all available spots were already taken.

In a similar way, this problem involves bypassing a client-side check that blocks the registration request. Once all the required data is obtained, the only thing left to do is to call the API to register and obtain the flag. The necessary parameters for this are `cod_ins` (20FWYOV), `cod_ins_padre` (29EBHOV), and `id_padre` (244355).

![the page of the challenge](/images/pianocarriera.png)

## Cryptography 🔒
### Fast RSA
This time, the challenge requires decrypting the flag encrypted in RSA where `p - q = 4`. This, of course, is very vulnerable because if `p equals q` then it's easy to calculate the square root of the modulus N and then look for a value such that `N mod v = 0`. At this point, `v` will be `p` and `q` will be calculated by dividing the modulus by `q`. The problem can be then solved by calculating the key `d`.

### AND Cipher
This challenge required decrypting a cipher that used the bitwise AND operation. Obviously, this operation is not reversible, so one way to solve this problem is to make several requests to the API endpoint to obtain the encrypted flag each time with a different key.

At this point, it's necessary to save the maximum value of the bytes for each position, and if a good bound is chosen, the flag will be found.

```python
for _ in range(250):
    json = requests.get(URL + "api/encrypt").json()
    json = bytes.fromhex(json['encrypted'])
    for i in range(26):
        flag[i] = max(flag[i], json[i])
```

### CrazyXOR
CrazyXOR provides an attachment containing source code that calculates the crazy XOR of 7 random numbers from `10^5` to `5*10^5`. It uses one of these numbers randomly to seed the random generator, which will then generate the key used to encrypt the flag.

```python
def crazy_xor(x):
	primes = prime_factors(x)
	res = 0

	for p1 in primes:
		for p2 in primes:
			if p1 <= p2:
				res = res ^ math.lcm(p1, p2) # Least common multiple

	return res
```
Once it's observed that the 7 iterations in the challenge meant to make brute-forcing the seed more complex are actually unnecessary, and that brute-forcing each x passed to the crazy XOR directly is sufficient, one just needs to emulate the various steps and check if decrypting the text yields the flag to complete this challenge as well.

### PoliTO Ch(e)atbot
After a brief study of the challenge website, the objective became clear: encrypt the token `I'm Bob Masters, gimme the flag!` using the available __AES-128 ECB tool__. 

Initially, attempts were made to split the token into two 16-byte blocks and encrypt them separately. However, this approach failed because the webpage blacklisted the second block as it was. Through experimentation, it was observed that `'a' * 16` encrypted was the same as `'a' * 16 + 'b'`. This indicated that the tool was only encrypting the first 16 bytes of the inserted plaintext.

Following this observation, to bypass the control, it was sufficient to write the second block concatenated with some random text. This action resulted in the encryption of the second block and consequently revealed the flag.

![home page of the challenge site](/images/cheatbot1.png)

### PoliTOcheatbot 2.0
In this challenge, the objective is to encrypt a password using an OTP (One-Time Pad) unknown to us. After several attempts, we noticed that the tool encrypted any plaintext we sent and sent us back the XOR between the plaintext and a key like `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (where obviously x stands for a printable ASCII character).
After several other attempts, we observed that if initially the key was `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, in the subsequent encryption it became `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.
Having made this observation, it was enough for us to calculate the key once to compute the next one and encrypt the password accordingly.
Once the encrypted password was sent, we obtained the flag as expected.

![chat with the bot](/images/cheatbot2.png)

## Binary 💻
### Polito Pay 2 Win
Probably to solve Polito Pay 2 Win, the basic idea was to __patch__ the binary/DLL provided in the challenge attachment to immediately purchase the flag. However, our idea (hopefully intended) was to open the `market.py` file to be able to see the flag in plaintext.

### Memory Wizard
Memory Wizard has attached a `64-bit x86-64 ELF` binary that requests an address from which to read data and then prints it to the standard output.

Analyzing the executable, it can be observed that both variables are declared on the stack with an 8-byte difference. Therefore, by using the leaked stack address, the flag address can be calculated like this `0xADDRESS + 8 = 0xFLAGADDRESS`.
![memory wizard](/images/memorywizard.png)

### OURsql
OURsql was one of the most interesting challenge in this CTF. It seems it was a binary that read a `database` ~~a text file~~ and used it for some queries. <br>
Upon analysis, I noticed that when the maximum number of users was reached, the program began to overwrite users at the beginning of the list. This allowed me to overwriting the password of the user with the flag. The exploit in fact involved spamming registrations until the user with the flag was overwritten. Afterward, logging in would have solved the challenge.

### The Wall
The Wall had an attachment, a 64-bit ELF file named `null_wall` (it will be useful later lol). Once decompiled, it provided approximately this result:
![the decompiled challenge elf](/images/nullwall.png)

Once decompiled, we looked at how the variables were arranged and noticed that the flag was located 20 bytes after our input pointer, preceded by a `null` byte. This null byte prevented the flag from being printed if fewer than 19 bytes were written. However, once exactly 19 bytes (`0x13 bytes`) were written, the flag was leaked.
![some sus memory place](/images/nullwall2.png)

## Miscellaneous 🧭
### Strange Extension
So, this challenge was solved simply by opening the file attached to the challenge using [this website](https://filext.com/online-file-viewer.html), immediately obtaining the flag. <br>
P.S.: Maybe it wasn't the cleanest way to resolve it but we did it anyway.

### A sky full of 5t4r5
This time, the challenge contained an image (frighteningly heavy, about `211 MB`) that resembled this screenshot: 
![the challenge foto](/images/skyfullofstars.png)

Once analyzed with ExifTool, it gave this result from which one can obviously notice the comment in the metadata of the photo which is `Some people say there is a question mark in this picture, can you find the flag near it?`
![the result of exiftool](/images/exiftool.png)
At this point, it was just a matter of looking around the photo for a while for a question mark (bottom right) to actually find the flag.

### Strangers in the Noise
"Strangers in the Noise" contained the famous Frank Sinatra song "Stranger in the Night". While analyzing it, we didn't find much until we used this website and managed to notice letters in the spectrum of the song as it progressed. Once we obtained the entire flag still encrypted as `swp{v0p3wk1qj_1q_b0xu_h4u5_z4v_vr_4qq0b1qj}`, all we had to do was use a __Caesar cipher decoder__ to obtain the final flag.

![the spectrum of the wav challenge](/images/strangerinthenoise.png)

Here you can see the first part of the flag `sw`.