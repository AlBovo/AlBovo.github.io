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
description: "Alcune writeups della m0lecon Beginner ctf edizione 2023."
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
    alt: "M0lecon CTF 2023 Beginner" # alt text
    caption: "Alcune writeups della m0lecon Beginner ctf edizione 2023." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# m0lecon CTF 2023 Beginner
![m0lecon logo](/images/m0lecon.png)

## Web 🌐
### Unguessable
Questa sfida è stata la più facile nella CTF (aveva __più risoluzioni__ del sanity check, lol). Infatti, per risolverla, tutto ciò che dovevi fare era capire che il sito web recuperava la bandiera da un punto finale `/vjfYkHzyZGJ4A7cPNutFeM/flag`, e per ottenerla abbiamo ~~aperto l'endpoint~~ enumerato l'intero sito.

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
La challenge aveva un allegato, un file di bytecode Python (.pyc), che una volta decompilato, aveva questa funzione:
```python
def generate_token(nonce: str):
    username = 'user001'
    secret = hashlib.sha256(username.encode() + nonce.encode()).hexdigest()
    bundle = {'user':username, 'secret':secret}
    return base64.b64encode(json.dumps(bundle).encode())
```
La challenge richiedeva un username (ovviamente `admin`) e un token di accesso che si poteva calcolare mediante un nonce dato dall'endpoint `/stage2?username=admin`. Una volta finito di calcolare il token usando la funzione menzionata precedentemente, tutto quello che rimaneva da fare per ottenere la flag era mandare il token e automaticamente ottenere accesso al pannello da amministratore.

![la bellissima pagina della challenge](/images/m0leconWeb.png)

### Piano Carriera
Tutti quelli che hanno partecipato alla `m0lecon CTF beginner 2021` e si ricordano la challenge `Exam Booking`, potrebbero riconoscere la situazione in cui un utente doveva registrare una data di esame già esaurita.

In un modo simile, questo problema richiede di bypassare un check client-side che blocca la richiesta di registrazione. Una volta che tutti i dati sono stati ricavati, l'unica cosa che resta da fare è fare una richiesta alle API per registrarsi e ottenere la flag. I parametri necessari per fare ciò sono `cod_ins` (20FWYOV), `cod_ins_padre` (29EBHOV), e `id_padre` (244355).

![la pagina della challenge](/images/pianocarriera.png)

## Crittografia 🔒
### Fast RSA
Questa volta, la challenge richiede di decifrare una flag encriptata usando RSA dove però `p - q = 4`. Ciò, ovviamente, è molto vulnerabile poichè se `p ugaule q` allora è facile calcolare la radice quadrata del modulo N e poi cercare un valore tale per qui `N mod V = 0`. A questo punto, `v` sarà uguale a `p` e `q` sarà il risultato della deivisione intera di N per `p`. Questa challenge può essere quindi finita calcolando la chiave privata `d`. 

### AND Cipher
Questa challenge richiede di decrittare un cifrario che usa solo operazioni bit a bit AND. Ovviamente, questa operazione non è reversibile, quindi l'unica soluzione a questo problema è fare molte richieste alle API per ottenere la flag encriptata ogni volta con una key diversa.

A questo punto, è necessario salvare il valore massimo di ogni byte, e se è stato scelto un buon bound, la flag sarà il risultato della concatenazione di ciascun bound.

```python
for _ in range(250):
    json = requests.get(URL + "api/encrypt").json()
    json = bytes.fromhex(json['encrypted'])
    for i in range(26):
        flag[i] = max(flag[i], json[i])
```

### CrazyXOR
CrazyXOR fornisce un allegato contenente il codice sorgente che calcola il crazy XOR di 7 numeri casuali compresi tra `10^5` e `5*10^5`. Utilizza quindi uno di questi numeri casuali per inizializzare il generatore random, che genererà a sua volta quindi la chiave utilizzata per criptare la flag.

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
Una volta osservato che le 7 iterazioni della challenge sono un modo per rendere il bruteforce del seed più complesso e quindi inutile, e che brutare ogni x passata al crazy XOR direattamente è sufficiente, basta solo emulare ogni passaggio e controllare se decriptando il testo si ottiene la flag per risolvere di conseguenza la challenge.

### PoliTO Ch(e)atbot
Dopo una breve analisi del sito l'obbiettivo era chiaro: cifrare il token `I'm Bob Masters, gimme the flag!` usando il tool __AES-128 ECB__.

Inizialmente, abbiamo provato a dividere il token in due blocchi da 16 bytes e cifrarli separatamente. In ogni modo però questo approccio non era corretto poiché la pagina blacklistava il secondo blocco così com'era. Facendo altri tentativi abbiamo notato che `'a' * 16` cifrato risultava uguale a `'a' * 16 + 'b'`. Questo indicava che il tool cifrava solamente i primi 16 bytes del plaintext inserito.

Seguendo quest'osservazione, per bypassare il controllo, bastava scrivere il secondo blocco concatenato con qualche testo randomico. Questo portava il tool a encriptare il secondo blocco rivelando di conseguenza la flag.

![homepage del sito della challenge](/images/cheatbot1.png)

### PoliTOcheatbot 2.0
In questa challenge, l'obiettivo era quello di cifrare una password usando un OTP (One-Time-Pad) a noi sconosciuto. Dopo diversi tentativi, abbiamo notato come il tool cifrasse tutti i plaintext da noi inseriti e mandasse indietro lo xor tra il plaintext ed una key `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (dove ovviamente le x erano caratteri ASCII printabili).
Dopo diversi tentativi, abbiamo notato come se all'inizio la chiave fosse `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, nel tentativo successivo la chiave fosse `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.
Avendo fatto quest'osservazione, per calcolare la chiave con cui cifrare l'OTP ci bastava conoscere la chiave usata in precedenza per cifrare un testo a caso.
Una volta cifrata e spedita la password, abbiamo ottenuto la flag come da aspettative. 

![la chat con il bot](/images/cheatbot2.png)

## Binary 💻
### Polito Pay 2 Win
Probabilmente per risolvere Polito Pay 2 Win, l'idea base era di __patchare__ il binario/DLL fornito negli allegati della challenge per comprare immediatamente la flag. In ogni modo, la nostra idea (forse unintended) fu di aprire il file `market.py` e poter leggere la flag direttamente in chiaro.

### Memory Wizard
Memory Wizard aveva in allegato un binario `64-bit x86-64 ELF` che richiedeva un indirizzo da qui leggere della memoria per poi printarla nello standard output.

Analizzando l'eseguibile, è possibile osservare che entrambe le variabili (flag ecc..) erano presenti nello stack a 8 bytes di distanza. A questo punto, usando l'address leakkato dalla challenge, era possibile trovare la flag calcolando `0xADDRESS + 8 = 0xFLAGADDRESS`. 
![memory wizard](/images/memorywizard.png)

### OURsql
OURsql è sicuramente una delle challenge più interessanti in questa CTF. Sembrerebbe a prima vista un binario che legge un `database` ~~file di testo~~ e lo usa per farci alcune query. 
Dopo altre analisi, ho notato che nel caso in cui il massimo numero di utenti fosse raggiunto, il programma avrebbe iniziato a sovrascrivere gli utenti all'inizio della lista. Questo mi ha quindi permesso di sovrascrivere la password dell'utente con la flag. Il mio exploit prevedeva infatti di spammare registrazioni finchè l'untente con la flag fosse sovrascritto. Questo mi permise di accedere come "admin", risolvendo la challenge.

### The Wall
The Wall aveva in allegato un ELF a 64-bit con il nome `null_wall` (ci sarà utile più tardi lol). Una volta decompilato, ci restituiva circa questo risultato: 
![il decompilato dell'elf della challenge](/images/nullwall.png)

Una volta decompilato, abbiamo osservato come erano organizzate le variabili e abbiamo notato come la flag fosse presente 20 bytes dopo l'inizio del nostro buffer, seguita da un `null` byte. Questo null byte evitava che la flag venisse printata se venivano mandati meno di 19 byte. In ogni modo, una volta scritti esattamente 19 bytes (`0x13 bytes`), la flag veniva leakkata. 
![qualche area di memoria sus](/images/nullwall2.png)

## Miscellaneous 🧭
### Strange Extension
Quindi, questa challenge era risolvibile semplicemente aprendo il file in allegato nella challenge usando [questo sito](https://filext.com/online-file-viewer.html) per poter immediatamente ottenere la flag. 
P.S.: Probabilmente non era il modo più pulito per risolvere questa challenge ma la abbiamo risolta comunque così. 

### A sky full of 5t4r5
Questa volta, la challenge conteneva l'immagine (paurosamente pesante, circa `211 MB`) che è riassunta in questo screenshot:
![la foto della challenge](/images/skyfullofstars.png)

Dopo aver analizzato la foto con ExifTool abbiamo notato come nei commenti dei metadata fosse presente questa frase `Some people say there is a question mark in this picture, can you find the flag near it?`.
![the result of exiftool](/images/exiftool.png)
A questo punto, non rimaneva che cercare in giro per la foto per un po' un punto di domanda (in alto a destra) per trovare di fatto la flag.

### Strangers in the Noise
"Strangers in the Noise" conteneva la famosa canzone di Frank Sinatra "Stranger in the Night". Analizzando la challenge non abbiamo trovato molto finché non abbiamo osservato lo spettro della canzone mentre questa era in riproduzione. Una volta osservato lo spettro abbiamo ottenuto uan sorta di flag cifrata ovvero `swp{v0p3wk1qj_1q_b0xu_h4u5_z4v_vr_4qq0b1qj}`, tutto quello che ci rimaneva per risolvere la challenge era di usare il __Cifrario di Cesare__ per decifrare la flag e risolvere la challenge.

![lo spettro della canzone](/images/strangerinthenoise.png)
Qui è visibile una parte iniziale della flag `sw`.