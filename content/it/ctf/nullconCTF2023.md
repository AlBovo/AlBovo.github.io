---
title: "nullCon CTF 2023"
date: 2024-05-28T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["nullCon", "ctf", "binary", "crypto", "web", "nullCon2023"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Alcune writeups della nullCon ctf edizione 2023."
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
math: true
cover:
    image: "https://opengraph.githubassets.com/eccdc445364e4f9dcbece7bb7f178f0756be13a48717c78ec94bf78c35861b9a/AlBovo/CTF-Writeups" # image path/url
    alt: "nullCon CTF 2023" # alt text
    caption: "Alcune writeups della nullCon ctf edizione 2023." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# nullCon CTF 2023
![logo della nullcon](/images/nullcon.png)

## Web 🌐
### TYpical Boss
In questa challenge, è possibile notare come se si accede all'endpoint '/' della challenge, il sito renderizzerà tutti i file e directory presenti nella pagina (includendo un file chiamato `database.db`, che era un database SQLite).
Appena ho trovato questo file, ho provato ad analizzare il contenuto finché non ho trovato la password hashata dell'admin. Questo hash (in SHA-1) iniziava con un prefisso molto conosciuto per delle potenziali vulnerabilità in PHP, ovvero `0e`.
Infatti, questa password verrà ogni volta interpetata da PHP come un numero, nello specifico `0`. L'unica via che avevo per bypassare quindi questo login era di trovare un plaintext che hashato in SHA-1 incominciasse anche lui per `0e`.
Questa è una repository molto utile per quanto riguarda il pentesting: [Repository](https://github.com/spaze/hashes/tree/master)

### Debugger
In debugger per ottenere la flag era necessario che l'IP dell'attaccante fosse 127.0.0.0, cosa non direttamente modificabile a causa del fatto che utilizzava `$_SERVER['REMOTE_ADDR']` per ottenere il suo indirizzo, utilizzando il seguente codice PHP:
```php
if(isset($_GET['action']) && $_GET['action']=="debug") {
    $is_admin = $_SERVER['REMOTE_ADDR'] == "127.0.0.0" ? 1 : 0;
    $debug_info = get_debug_info(extract($_GET['filters']));
    if($is_admin) {
        echo implode($debug_info, '\n');
    } else {
        echo("Only local admins are allowed to debug!");
    }
    include_once "flag.php";
}
```
La vulnerabilità a questo punto si trova nella funzione di PHP `extract()`, che [importa variabili](https://www.php.net/manual/en/function.extract.php) da un array nella tabella dei simboli corrente. Il mio exploit, nello specifico, sovrascriveva la variabile `$is_admin` con 1 usando il seguente payload in una richiesta GET `/?action=debug&filters[is_admin]=1`. In questo modo ho avuto modo di ottenere la flag. 

### Colorful
Questa challenge era particolarmente diversa dalle challenge di web security a cui sono abituato, richiedeva infatti la conoscenza di `AES` e le vulnerabilità riguardanti la mode `ECB`.
In questo caso, il codice sorgente conteneva una parte di codice molto sospetta:
```py
def parse(self, c):
    d = {}
    if c is None:
        return d
    for p in c.split("&"):
        try:
            k,v = p.split("=")
            if not k in d:
                d[k]=v
        except:
            pass
    return d

def new_session(self, r):
    id = secrets.token_hex(4)
    c = f"_id={id}&admin=0&color=ffff00&"
    return self._c(c)

def _c(self, v):
    try:
        v = v.encode()
        while len(v) % 16 != 0:
            v += b'\x41' 
        return AES.new(self.k,1).encrypt(v).hex()
    except:
        return None
```
Dopo aver guardato un po' a questo codice, ho notato che era impossibile cifrare dei blocchi arbitrari che, se creati correttamente, sarebbero mischiabili insieme per creare un cookie con privilegi da admin.
A questo punto, quello che feci fu di riempire la porzione di cookie che non potevo modificare da me, `_id={id}&admin=0&color=` (dove id è una stringa di 4 * 2 caratteri esadecimali), con dei caratteri al fondo per rendere la lunghezza totale divisibile per 16 (in altre parole, creare blocchi interi). Ho quindi scritto `admin=1` nel blocco successivo. In questo modo shiftando l'ultimo blocco all'inizio e sovrascrivendo il cookie sono riuscito ad ottenere la flag.

### IP Filters

Questo era il codice sorgente di IPFilters:
```php
function fetch_backend($ip) {
    if(is_bad_ip($ip)) {
        return "This IP is not allowed!";
    }
    return file_get_contents("http://". $ip . "/");
}
function is_bad_ip($ip) {
    if(!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip)) {
        return true;
    }
    $frontend = gethostbyname(gethostname());
    $backend = gethostbyname("ipfilter_backend");
    $subnet = long2ip(ip2long($frontend) & ip2long("255.255.255.0"));
    $bcast = long2ip(ip2long($frontend) | ~ip2long("255.255.255.0"));

    if(isset($_GET['debug_filter'])) {
        // Debugging echos that also print the backend local IP
    }

    if(inet_pton($ip) < (int) inet_pton($subnet)) {
        return true;
    }
    if(! (inet_pton($ip) < inet_pton($bcast))) {
        return true;
    }
    if($ip == $backend) {
        return true;
    }
    return false;
}
if(isset($_GET['fetch_backend']) ) {
    echo fetch_backend($_GET['bip']);
}
```
Apparentemente, non sembrano esserci bypass specifici da eseguire. Tuttavia, analizzando ogni funzione PHP utilizzata nel programma una per una, ho scoperto che `inet_pton` è vulnerabile poiché accetta anche indirizzi IPv4 contenenti zeri nell'ultimo sottogruppo. Ad esempio: `xxx.xxx.x.00x`.
In questo modo ho potuto creare un indirizzo IP nel range della subnet passando l'IP printato dal debug con dei _trailing zeros_.
Per esempio, `192.168.1.2` => `192.168.1.002`.

### Magic Cars
Questa challenge richiedeva di caricare un file `GIF` nel backend del sito in modo tale da poterlo vedere in seguito.
Questo è il codice PHP del backend del sito:
```php
$files = $_FILES["fileToUpload"];
$uploadOk = true;
if($files["name"] != ""){
    $target_dir = urldecode("images/" . $files["name"]);
    if(strpos($target_dir,"..") !== false){
        $uploadOk = false;
    }
    if(filesize($files["tmp_name"]) > 1*1000){
        $uploadOk = false;
        echo "too big!!!";
    }
    $extension = strtolower(pathinfo($target_dir,PATHINFO_EXTENSION));
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $type = finfo_file($finfo,$files["tmp_name"]);
    finfo_close($finfo);
    if($extension != "gif" || strpos($type,"image/gif") === false){
        echo " Sorry, only gif files are accepted";
        $uploadOk = false;
    }
    $target_dir = strtok($target_dir,chr(0));
    if($uploadOk && move_uploaded_file($files["tmp_name"],$target_dir)){
        echo "<a href='$target_dir'>uploaded gif here go see it!</a>";
    }
}
```
Dopo alcuni tentativi, ho notato come il backend stesse controllando alcuni parametri dei file che gli passavo, come non essere troppo pesanti, non avere percorsi con dei traversal (es: `..\` o `../`), avere l'estensione `.gif` e avere i magic bytes corretti per un file `GIF`.
Ho anche notato come dividesse usando i null byte come divisori usando la funzione `strtok()`, prendendo il primo pezzo come nome reale del file. Seguendo quest'osservazione sono riuscito a scrivere una reverse shell in PHP (che potete trovare sulla mia repository [GitHub](https://github.com/AlBovo/CTF-Writeups/tree/main/nullcon%20CTF%202023)) che ho nominato `rev.php%00.gif`. Dandogli questo nome ho bypassato tutti i controlli ottenendo quindi un endpoint a `rev.php`.  
Non appena aprii il file all'indirizzo `images/rev.php` sono riuscito a mandare comandi alla shell mediante `www-data`.

### Loginbytepass
La challenge Loginbytes permetteva di eseguire il login con gli username `admin` o `flag`. In questo caso lo username veniva iniettato nella query del database senza nessuna sanitizzazione, mentre la password veniva hashata due volte usando md5 senza venire convertita in una stringa esadecimale.

A questo punto questa parte di codice è risultata molto utile:
```php
function check_auth($username, $password)
{
    global $db;
    $username = mysqli_real_escape_string($db, $username); // preventSQLinjection
    $password = md5(md5($password, true), true);
    $res = mysqli_query($db, "SELECT * FROM users WHERE username = '$username' AND password = '$password'");
    if (isset($res) && $res->fetch_object()) {
        return true;
    }
    return false;
}
```
Io ed il mio team siamo riusciti quindi a scoprire che trovando un hash contenente `prima_parte_dell_hash'='seconda_parte_dell_hash` potevamo bypassare il login. Questo perchè PHP per colpa del type juggling trasformava entrami gli hash in `0`, risultando quindi in una query come questa:
```sql
SELECT * FROM users WHERE username='admin' AND true
```
Che ci ha quindi permesso di ottenere la flag.

## Binary 💻
### Babypwn
Finalmente un po' di pwn. Questa challenge aveva in allegato un file `ELF`. Eseguendo `checkesec` per esaminare il suo contenuto ho ottenuto questi risultati:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```
A questo punto non rimaneva che analizzare con IDA il decompilato della challenge, questo allocava un buffer da `512` caratteri in cui però tramite una read ne potevo scrivere `1024`.
```c
...
   char username[512];

   printf("You shell play a game against @gehaxelt! Win it to get ./flag.txt!\n");
   printf("Your game slot is at: %p\n", username);
   printf("What's your name?\n");
   read(1, username, 1024);
...
```
Questo ci permise di effettuare un `buffer overflow`. Siamo riusciti quindi a riempire il buffer con uno shellcode seguito da molti byte 'a' per riempire il resto del buffer. Una volta riempito il buffer era necessario solamente sovrascrivere il `RBP` e il `return pointer` con l'indirizzo dello shellcode per poter ottenere una shell sulla macchina remota. 

### Heavens Flow
Questa challenge è molto simile alla precedente ma questa volta usando checksec abbiamo `NX enabled`, non possiamo quindi utilizzare uno shellcode sullo stack poiché non è eseguibile. In ogni modo possiamo comunque sovrascrivere il `return pointer` per eseguire la funzione `heavens_secret`, che stamperà la flag su standard output.

## Cryptography 🔒
### Euclidean RSA
Questa è la prima challenge di crittografia. Il codice in sè non è molto lungo, ma le sue funzionalità sono alquanto "strane" poiché utilizza una funzione esterna per generare quattro interi a, b, c e d, che devono rispettare questa relazione `a^2 + b^2 = n`, `c^2 + d^2 = n`
```py
while True:
	try:
		key = RSA.generate(2048)
		a,b,c,d = magic(key)
		break
	except:
		pass
assert a**2 + b**2 == key.n
assert c**2 + d**2 == key.n
```
A questo punto usando il metodo di `Brahmagupta–Fibonacci` è possibile risolvere l'equazione seguendo questi passaggi:

$$
\begin{align*}
& a^2 + b^2 = c^2 + d^2 = n \\
& (a^2 + b^2)(c^2 + d^2) = n^2 = (pq)^2 \\
& (ac + bd)^2 + (ad - bc)^2 = p^2 q^2 \\
& q^2 = s^2 + t^2 \\
& (ac + bd)^2 + (ad - bc)^2 = (p \cdot s)^2 + (p \cdot t)^2 \\
& ps = a \cdot c + b \cdot d \\
& pt = a \cdot d - b \cdot c \\
& p = \text{gcd}(ps, pt) \\
& q = \frac{n}{p} \\
\end{align*}
$$

### Sebastian's Secret Sharing
In questa challenge il codice sorgente segue diversi passaggi per rendere la comprensione del codice il più difficile possibile. Osservando meglio come questo inizializza l'array contenente la flag è possibile notare un dettaglio:
```py
def _a(self):
    c = [self.s]
    for i in range(self.t-1):
        a = Decimal(random.randint(self.s+1, self.s*2))
        c.append(a)
    return c
```
In questo caso, `self.s` rappresenta la flag, e possiamo osservare come questa sia presente alla posizione `0` dell'array quando questo è ritornato alla funzione chiamante.
Se analizziamo meglio la funzione principale, la challenge ci permette di leggere un elemento alla posizione `x mod n`, dove x è il numero da noi scritto che deve essere nel range `1 <= x <= n`. Quindi, se vogliamo ottenere l'elemento alla posizione 0 non dobbiamo fare altro se non inviare un input tale per cui `x = n`, in questo modo `x mod n = 0`. 

### Counting
Finalmente questa è l'ultima challenge che il mio team ha risolto. In questa challenge il servizio cifra i messaggi usando `RSA` con una semplice modifica (praticamente minuscola) in questo codice:
```py
...
    message = b'So far we had %03d failed attempts to find the token %s' % (counter, token)
    print(pow(bytes_to_long(message), key.e, key.n))
...
```
In questo caso si può provare l'attacco [Franklin–Reiter](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin%E2%80%93Reiter_related-message_attack) bruteforceando il bit cambiato finché il messaggio decrittato dall'attaccante contiene il token da trovare. Una volta ottenuto il token si può mandare al servizio per ottenere la flag.