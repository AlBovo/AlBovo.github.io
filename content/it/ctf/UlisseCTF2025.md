---
title: "UlisseCTF 2025"
date: 2025-04-08T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["ulissectf", "ctf", "binary", "crypto", "web", "ulissectf2025"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Una raccolta di tutte le writeup delle challenges che ho scritto per la UlisseCTF 2025."
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
    alt: "UlisseCTF 2025" # alt text
    caption: "Una raccolta di tutte le writeup delle challenges che ho scritto per la UlisseCTF 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# UlisseCTF 2025 🚩
![ulisse logo](/images/ulisse.png)

## Telemetry 🌐

### Panoramica

**Telemetry** è un'applicazione web che permetteva agli utenti di caricare file (massimo 10), registrando internamente tutti gli errori e gli eventi rilevanti in file posizionati in percorsi come `logs/username/user-uuid.txt`.

L'app offriva anche un endpoint di test dei template, che consentiva agli utenti di verificare se un determinato **template Jinja2** presente nella directory `template` potesse essere renderizzato correttamente.

### Analisi

La challenge forniva un endpoint di **registrazione**, dove l’utente poteva scegliere un nome utente e un **nome personalizzato per il file di log**. Questi valori venivano poi usati per generare un `UUID` che identificava in modo univoco il file di log dell’utente.

Analizzando le route disponibili, l’endpoint più interessante era `/check`, che tenta di renderizzare un template Jinja2 all’interno di un **ambiente sandboxato**:

```python
@app.route('/check', methods=['GET', 'POST'])
def check():
    if request.method == 'GET':
        return render_template('check.html')
    
    template = secure_filename(request.form['template'])
    if not os.path.exists(os.path.join('templates', template)):
        flash('Template non trovato', 'danger')
        return redirect('/check')
    try:
        render_template(template)
        flash('Template renderizzato con successo', 'success')
    except:
        flash('Errore nel rendering del template', 'danger')
    return redirect('/check')
```

Tuttavia, questo endpoint **non è direttamente vulnerabile**: l’uso di `secure_filename` e la dipendenza esclusiva da file nella directory `templates/` (che l’utente non può modificare) impedisce exploit diretti.

Una funzione molto più interessante era quella che gestiva gli **errori 404**, registrando gli accessi a pagine non esistenti:

```python
@app.errorhandler(404)
def page_not_found(e):
    if user := session.get('user', None):
        if not os.path.exists(os.path.join('logs', user[1], user[0] + '.txt')):
            session.clear()
            return 'Page not found', 404
        with open(os.path.join('logs', user[1], user[0] + '.txt'), 'a') as f:
            f.write(f'[{time.time()}] - Error at page: {unquote(request.url)}\n')
        return redirect('/')
    return 'Page not found', 404
```

Questa funzione registra nel file di log dell’utente il percorso completo della URL richiesta, **non codificata**. Tuttavia, il percorso del log viene costruito come segue:

```python
os.path.join('logs', user[1], user[0] + '.txt')
```

Se il **nome utente** è una stringa di path traversal come `../`, il percorso risultante sarà:

```
logs/../<uuid>.txt -> <uuid>.txt
```

Questo consente effettivamente all’utente di **uscire dalla directory `logs/`** e scrivere file in percorsi arbitrari, rendendo il sistema vulnerabile a **Path Traversal** e potenzialmente a **Template Injection**, soprattutto se quei file vengono successivamente inclusi o renderizzati dall'applicazione.

### Exploit

Una volta comprese le vulnerabilità, la strada per l’exploit era piuttosto diretta.  
Un attaccante poteva registrarsi usando un **nome utente** come `../templates/` e un nome di file di log arbitrario (es. `fsafsafsasfa`).

Questo faceva sì che il file di log venisse creato in:

```
templates/<uuid>.txt
```

Poiché l’`UUID` è derivato in modo deterministico dal nome del file di log controllato dall’attaccante, quest’ultimo **conosce esattamente il nome** del file su cui sta scrivendo. A questo punto, l’attaccante ha realizzato un **path traversal** che gli permette di piazzare un file arbitrario direttamente nella directory `templates/`.

#### Sfruttamento di una SSTI Blind

Con la possibilità di scrivere in `templates/` e con l’endpoint `/check` che agisce da **oracolo**, l’attaccante può sfruttare una **Server-Side Template Injection (SSTI) blind**.

Creando payload dannosi e iniettandoli nel file di log (attraverso richieste 404), l’attaccante può forzare il rendering inviando il nome del file all’endpoint `/check`.

Per estrarre la flag, è possibile effettuare un **brute-force blind, basato su errori, carattere per carattere**. Ad esempio:

```jinja2
{{ 'lol' if config['FLAG'][x] == 'y' else raise('lol') }}
```

Questo payload accede a `config['FLAG']` e confronta il carattere all’indice `x` con il carattere ipotizzato `'y'`.  
Se l’ipotesi è sbagliata, viene sollevata un’eccezione e il rendering fallisce. Se corretta, il rendering ha successo.

Iterando su ogni posizione e su tutti i caratteri stampabili, l’attaccante può recuperare la flag **usando solo il feedback di successo/fallimento**.

## StackBank1 🌐

### Panoramica

**Stack Bank** è un'applicazione web che consente agli utenti di eseguire operazioni bancarie comuni, come trasferire denaro ad altri utenti o inviare fondi direttamente all’**amministratore** del servizio.

Dopo aver avviato una transazione, l’utente deve attendere fino a **10 secondi** per il completamento dell’operazione. Questo ritardo è dovuto a un **bot interno** che verifica asincronamente i valori e l’integrità della transazione prima di segnarla come completata.

Tuttavia, c’è un’eccezione: le **transazioni verso l’amministratore** vengono immediatamente marcate come completate, senza alcuna verifica o controllo di integrità.

### Analisi

La challenge mette a disposizione diversi servizi dietro un reverse proxy `nginx` configurato nel seguente modo:

```nginx
location /service/ {
    proxy_pass http://backend:4000/;
    ...
}

location / {
    proxy_pass http://frontend:3000;
    ...
}
```

Il **frontend** è un’applicazione web realizzata con **Next.js**, mentre il **backend** è un’applicazione **Flask** che espone diverse funzionalità. In particolare, il backend integra codice nativo C tramite **CTypes**, utilizzando una libreria condivisa chiamata `libackend.so` per implementare parte della logica principale.

La prima flag viene inserita nel database **MongoDB** durante la fase di inizializzazione del backend.  
Viene memorizzata all’interno di una **transazione** in cui sia il **mittente** che il **destinatario** sono l’utente `administrator`.

### Vulnerabilità

Poiché la flag si trova nella transazione che coinvolge l’amministratore, può essere utile analizzare l’endpoint presente nel frontend, nel file `app/api/dashboard/route.ts`. Questo file implementa il seguente codice:

```ts
const filter = searchParams.get("filter")?.trim();

const value = searchParams.get("value");

let [balance, transactions] = await Promise.all([
    db.collection("balances").findOne({ _id: userId }),
    db
    .collection("transactions")
    .find({
        $or: [{ sender_id: userId }, { receiver_id: userId }],
    })
    .toArray(),
]);

if (
    filter &&
    value &&
    !filter.startsWith("sender") &&
    !filter.startsWith("receiver")
) {
    const regex = new RegExp(`.*${escapeRegex(value)}.*`, "i");
    transactions = await db
    .collection<Transaction>("transactions")
    .find({
        $where: function () {
        let t = Object.fromEntries(
            Object.keys(transactions).map((key) => [key, ""]),
        );

        t.sender = user.username as string;
        t.receiver = user.username as string;

        for (let i = 0; i < transactions.length; i++) {
            if (regex.test(transactions[i].note)) {
                t[filter] = transactions[i].note;
            }
        }
        return this.sender === t.sender && this.receiver === t.receiver;
        },
    })
    .toArray();
}

balance = balance?.amount;
return NextResponse.json({ balance, transactions });
```

Questa funzione è **vulnerabile** perché un attaccante può manipolare i valori forniti in modo che sia il **mittente** che il **destinatario** siano impostati su `administrator`, ottenendo così la **transazione dell’admin** contenente la flag.

La vulnerabilità deriva da un problema di **prototype pollution**, possibile a causa di questo frammento di codice:

```ts
t[filter] = transactions[i].note;
```

Un attaccante potrebbe creare un payload come:

- **filter**: `__proto__`
- **nota della transazione**: `{'a': 'b'}`

Questo causerebbe la modifica dell’oggetto `t` tramite prototype pollution, aggiungendo ad esempio una proprietà `a` (`t.a = 'b'`). In questo modo, l’attaccante può alterare il comportamento dell’oggetto e accedere a dati riservati, come la flag.

L’ultimo elemento utile per completare l’exploit si trova nell’endpoint `/service/transaction` del backend:

```python
@app.route('/transaction', methods=['POST'])
@login_required
def transaction(user):
    ...
    # controlli di validazione omessi per brevità
    
    if receiver['username'] == 'administrator':
        return invest(user)

    ...

# La route seguente non è più utilizzata...
# @app.route('/invest', methods=['POST'])
# @login_required
def invest(user):
    amount = request.json['amount']
    note = request.json['note']
     
    mongo.db.balances.update_one(
        {"user_id": user[0]},
        {"$inc": {"amount": -amount}}
    )
    
    mongo.db.transactions.insert_one({
        'sender_id': user[0],
        'sender': user[1],
        'receiver_id': mongo.db.users.find_one({'username': 'administrator'})['_id'],
        'receiver': 'administrator',
        'amount': amount,
        'note': note,
        'status': 'success'
    })
    
    return jsonify({'message': 'Investment added'}), 200
```

Un attaccante può quindi inviare fondi direttamente all’account `administrator`, attivando la funzione `invest` che consente all’utente di specificare un campo `note` arbitrario (ad esempio: `{'sender': 'administrator', 'receiver': 'administrator'}`).

### Soluzioni unintended

Mi scuso sinceramente per eventuali soluzioni unintended che potrebbero aver semplificato troppo la challenge, come l’uso di payload tipo `filter=sender&value=a` o `filter=^&value=a` (che mostravano tutte le transazioni nel database).  
Per il futuro, prometto di effettuare test più approfonditi sulle prossime challenge, per garantire un’esperienza migliore ai partecipanti della prossima UlisseCTF **`ᕙ(  •̀ ᗜ •́  )ᕗ`**

## StackBank2 🌐 / 🖥️

### Panoramica

La panoramica generale della challenge è già stata trattata nel writeup di StackBank1. Se ti interessa, dagli un’occhiata! ;)

### Analisi

La seconda flag di StackBank può essere ottenuta diventando un "admin". Questo avviene quando l’utente ha almeno **10 mila** euro di saldo e invia la `ADMIN_KEY` corretta, che viene generata casualmente dal backend.

A questo punto conviene analizzare la libreria `libbackend.so`, scritta in **C** e richiamata tramite **ctypes**. Ecco uno snippet semplificato tratto dalla libreria:

```c
...

v16 = __readfsqword(0x28u);
memset(v14, 0, sizeof(v14));
v15 = 0;
dest = (char *)malloc(0x12u);

strcpy(dest, a1);
strncpy(v14, a9, 0x1F3u);

s = (char *)malloc(0x1F4u);
v13 = (char *)malloc(0x10u);
strcpy(v13, "error");

if (a7 < a8)
    return s;
if (a8 <= 0)
    return s;

format = parse(v14);

if (format)
{
    snprintf(s, 0x1F3u, format);
    *(_QWORD *)v13 = 0x73736563637573LL;
    free(format);
    free(dest);
}
```

Anche se a prima vista questa funzione può sembrare poco chiara, tutto diventa più comprensibile analizzando le struct Python usate con **ctypes** nel file `models.py`:

```python
class Transaction(Structure):
    _fields_ = [
        ('sender_balance', c_int64),
        ('amount', c_int64),
        ('note', c_char_p),
    ]
    def __init__(self, id, *args, **kw):
        super().__init__(*args, **kw)
        self.id = id
        
class Result(Structure):
    _fields_ = [
        ('note', c_char_p),
        ('status', c_char_p),
    ]
```

Nel contesto della challenge, la funzione C equivalente alla gestione della transazione ha questa logica:

```c
memset(v7, 0, sizeof(v7));
v8 = 0;
dest = (char *)malloc(0x12u);
strcpy(dest, key);
strncpy(v7, t.note, 0x1F3u);
s = (char *)malloc(0x1F4u);
s_8 = (char *)malloc(0x10u);
strcpy(s_8, "error");

if (t.sender_balance < t.amount)
    return s;
if (t.amount <= 0)
    return s;

format = parse(v7);

if (format)
{
    snprintf(s, 0x1F3u, format);
    *(_QWORD *)s_8 = 'sseccus';
    free(format);
    free(dest);
}
return s;
```

Dopo aver effettuato un po’ di reverse engineering, è chiaro che la funzione `parse` **è sicura e non vulnerabile** (lol).  
La vera vulnerabilità sta nel comportamento della funzione `handle_transaction`: il problema è la chiamata a `snprintf`, che introduce una **format string vulnerability**.

Un altro comportamento importante riguarda il bot asincrono della webapp Flask. Questo bot controlla nuove transazioni ogni 10 secondi ed esegue l’elaborazione tramite la funzione C analizzata sopra.  
Questo introduce una **race condition**, perché il bot controlla il saldo del mittente e l’importo della transazione **solo dopo** che la transazione è stata inserita nella coda.  
Un attaccante può sfruttare questa condizione inviando rapidamente molte transazioni (es. 100 da 100€), raggiungendo velocemente il saldo necessario per diventare admin (10k).

Infine, la `ADMIN_KEY` può essere ottenuta inviando una stringa di formato come `%6$s` nel campo `note` di una transazione.  
Questo permette di leggere la **prima stringa presente nello stack (rsp)**, che corrisponde proprio alla copia della `ADMIN_KEY`.

## YetAnotherOracle 🔑

### Panoramica

Questa challenge forniva un *oracolo* che cifrava un plaintext (di almeno 32 bit) usando una chiave generata casualmente tramite il modulo `random` di Python, inizializzato con il valore restituito da `time.time()` (cioè il timestamp dell'avvio del processo).

La funzione utilizzata per cifrare un plaintext con una data chiave era la seguente:

```python
def mysteriousFunction(plaintext: bytes, key: bytes):
    a = bytes_to_long(plaintext)
    b = bytes_to_long(key)
    
    c, t = 0, 0
    while a > 0 and b > 0:
        v1 = (a & 0xf) ^ ((b & (0xff - 0xf)) >> 4)
        v2 = (b & 0xf) ^ ((a & (0xff - 0xf)) >> 4)
        c += (v1 | (v2 << 4)) << t
        a, b = a >> 8, b >> 8
        t += 8
        
    if a > 0:
        c += a << t
    elif b > 0:
        c += b << t
        
    return long_to_bytes(c)
```

Questa funzione lavora byte per byte, mescolando i *nibble* (blocchi da 4 bit) del plaintext e della chiave usando operazioni di **XOR** e **bit shifting**. Il risultato è una combinazione "offuscata" dei due input.

Oltre all'oracolo, veniva anche fornita la cifratura della flag, effettuata con un’altra chiave casuale a 32 bit.

### Exploit

Dato sia il plaintext che il ciphertext corrispondente, è possibile **recuperare la chiave** usata durante la cifratura invertendo la logica della `mysteriousFunction`. Questo consente di ottenere **tutti i bit della chiave**, che sono stati generati dal PRNG **Mersenne Twister** interno di Python (`random` module).

Raccogliendo abbastanza chiavi (nello specifico, **624 valori a 32 bit consecutivi**), è possibile utilizzare librerie come [`randcrack`](https://github.com/tna0y/Python-random-module-cracker) per **ricostruire lo stato interno del PRNG**.  
Una volta ottenuto lo stato interno, è possibile anche risalire al seed originale e quindi prevedere tutti i valori futuri (e passati) generati dal modulo `random`.

Con il seed recuperato, è possibile rigenerare il valore successivo generato dal PRNG (cioè quello usato per cifrare la flag). Usando questo valore come chiave, e invertendo la `mysteriousFunction`, si ottiene la **flag originale**.


### Soluzione Unintended

La procedura sopra è quella “corretta”, ma in questa challenge era anche possibile **bruteforzare direttamente il seed**, grazie al fatto che veniva inizializzato con `time.time()`.  
Poiché `time.time()` restituisce il numero di secondi dall’epoca Unix, lo **spazio di ricerca è molto ridotto** — specialmente se si conosce con buona approssimazione l’orario in cui è stata avviata la challenge.

Provando tutti i seed possibili in una finestra temporale ristretta (es. pochi minuti), si riesce a ricostruire **esattamente** lo stato del PRNG e a predire il valore usato per cifrare la flag, senza bisogno di raccogliere 624 output.

## x864Oracle 🖥️

### Panoramica

La challenge forniva un binario ELF dinamicamente linkato, assieme alla propria `libc.so.6` e al linker. Una volta connessi al servizio remoto, il binario chiedeva all’utente di inserire la lunghezza del proprio nome, poi il nome stesso. L’input veniva mostrato dopo ogni step, incluso un prompt finale che richiedeva una breve descrizione, anch’essa mostrata.

### Analisi del Binario

Il binario era stato compilato in C usando `gcc`, con diverse mitigazioni abilitate:

- **PIE**: attivo  
- **Stack canary**: attivo  
- **NX (Non-Executable stack)**: attivo  
- **RELRO**: *Partial RELRO*

La presenza di Partial RELRO e della `libc` fornita fa pensare a una possibile tecnica di **ret2libc**, dato che la GOT è solo parzialmente protetta.

#### Funzioni rilevanti

Il binario include le seguenti funzioni:

- `main`
- `readString`
- `readSize`
- `setSecurity`
- `init`

#### main()

La `main` contiene la logica principale della challenge. In particolare, tenta ingenuamente di azzerare alcune voci della GOT per ostacolare exploit `ret2libc`.

```c
init(argc, argv, envp);

printf("Write the size of your name: ");
Size = readSize(v8);

printf("You chose a name of size %s\n", v8);
printf("Write your name: ");
readString(v7, Size);

printf("Hello %s\n", v7);

// Mapping RWX
v6 = mmap(0x13370000, 0x50, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);

printf("Write a description: ");
readString(v6, 80);

printf("Your description is: %s\n", v6);
puts("Bye");

setSecurity();

// Tentativo di wiping della GOT
for (i = 0; i <= 10; ++i)
    *(&stdin + i - 14) = 0;
```

È interessante notare che la descrizione viene salvata in una regione di memoria mappata a un indirizzo noto (`0x13370000`) con permessi **RWX**, quindi **eseguibile**.

#### readString()

Questa funzione legge `n` byte da `stdin` e rimuove il newline finale, se presente. Non effettua controlli rigorosi sui limiti del buffer.

```c
v3 = read(0, a1, a2);
if (a1[v3 - 1] == '\n')
    a1[v3 - 1] = 0;
return a1;
```

A seconda del contesto in cui viene chiamata, questa funzione può essere vulnerabile a overflow.

#### readSize()

Questa funzione contiene un bug interessante legato a un parsing incoerente dell’input:

```c
readString(a1, 17);
if ((unsigned int)atoi(a1) > 40)
{
    puts("Invalid size");
    exit(0);
}
return strtol(a1, NULL, 0);
```

La validazione viene fatta usando `atoi` (che assume **base 10**), mentre il valore viene poi ottenuto con `strtol` in **base automatica** (base 0). Questo apre la porta a una **bypass del controllo**:

- `0x100` → `atoi` ritorna 0 (valido), ma `strtol` ritorna 256  
- `040`   → `atoi` ritorna 40 (valido), ma `strtol` ritorna 32 (ottale)  
- `100`   → entrambi ritornano 100 (decimale)

Tramite questo bug è possibile passare una dimensione maggiore di 40 e causare **buffer overflow** nella funzione `main`.

#### setSecurity()

Questa funzione imposta un filtro **seccomp** che **blocca tutti i syscall**, ad eccezione di `read` e `write`, ma solo se provengono dall’area `0x13370000–0x13370050` (cioè la zona dove viene scritto il payload dell’utente):

```
 0000: A = IP
 0001: if (A < 0x13370000) -> ALLOW
 0002: if (A >= 0x13370050) -> ALLOW
 0003: A = syscall_num
 0004: if (A == read)  -> ALLOW
 0005: if (A == write) -> ALLOW
 0006: return KILL
 0007: return ALLOW
```

**Nota:** Non viene usato `PR_SET_NO_NEW_PRIVS`, rendendo il filtro meno sicuro di quanto sembri.

#### init()

Imposta solo la modalità di buffering di `stdin`, `stdout` e `stderr` su *unbuffered* tramite `setvbuf`. Niente di interessante per l’exploit.

### Colleghiamo i puntini 🧠

In sintesi, la challenge offriva:

- Un **overflow di buffer** sullo stack della `main`  
- Un **canary** visibile in output (tramite null byte corrotto)  
- Una regione RWX controllata dall’utente, a indirizzo noto  
- Un **bypass** del controllo sulla dimensione dell’input, grazie al parsing incoerente

Tutto ciò crea un contesto ideale per eseguire **shellcode** scritto nella memoria RWX.

### Exploit

L’exploit prevedeva i seguenti passaggi:

1. **Leak del canary**:  
   Inserendo un nome con dimensione superiore al previsto (es. `0x100`), si può scrivere oltre il limite del buffer e **corrompere il null byte** del canary, che viene poi mostrato in output. In questo modo si ottiene il valore completo del canary.

2. **Scrittura dello shellcode** nella memoria RWX `0x13370000` tramite il campo “description”.  
   Lo shellcode può:
   - Recuperare l’indirizzo di `__libc_start_main` dalla stack frame
   - Calcolare la base address di `libc`
   - Calcolare l’indirizzo di `system` o `execve`
   - Chiamare `execve("/bin/sh", NULL, NULL)`

3. **Overflow della return address** della funzione `main` usando il campo “name” per sovrascrivere:
   - Il padding
   - Il canary (ora noto)
   - I registri salvati
   - L’indirizzo di ritorno → `0x13370000`

In questo modo, al termine della `main`, l’esecuzione salta alla shellcode precedentemente scritta in memoria, aggirando completamente il filtro seccomp ed eseguendo un **comando arbitrario**.
