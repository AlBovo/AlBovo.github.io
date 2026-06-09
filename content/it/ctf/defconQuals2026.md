---
title: "DEF CON CTF Qualifier 2026"
date: 2026-06-02T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["jeopardy", "ctf", "reverse-engineering", "defcon"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "La writeup della challenge che ho risolto durante le DEF CON CTF Qualifier 2026."
canonicalURL: "https://albovo.github.io/ita/ctf/"
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
    alt: "DEF CON CTF Qualifier 2026" # alt text
    caption: "La writeup della challenge che ho risolto durante le DEF CON CTF Qualifier 2026." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/it"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---
# DEF CON CTF Qualifier 2026 🚩
![defcon logo](/images/defcon.png)

## myfavoriteinstructions
Abbiamo iniziato analizzando il binario, che era un ELF a 64 bit stripped (senza simboli). Il binario era composto da due funzioni principali: il **main** e una funzione che IDA non riusciva a decompilare a causa della sua lunghezza; quest'ultima era composta principalmente da istruzioni `bsr`, `bzhi` e `mov` e conteneva pochissimi controlli di flusso.

Inizialmente avevamo ipotizzato che il codice fosse stato generato da qualche algoritmo per rendere la funzione principale difficile da analizzare con i decompilatori classici (avevamo infatti osservato che la sezione `.text` era di circa **250KB**).

Analizzando inizialmente in modo statico la funzione `main`, abbiamo compreso facilmente che era necessario eseguire il binario con un argomento (la *flag*) e che questo doveva essere lungo esattamente **68 byte**.

```c
if ( a1 != 1 )
{
    if ( a1 == 2 )
    {
        v4 = a2[1];
        len = strlen(v4);
        if ( len <= 67 )
        {
            fprintf(stderr, "Flag too short (got %d, need >= 68)\n", len);
            return 1;
        }
    ...
```

Una volta compreso questo semplice dettaglio, decidemmo di passare al resto del `main` per poi affrontare la sfida vera e propria.
Nel `main` erano presenti 6 cicli diversi.

### Comprensione del main
#### Primo ciclo
Il codice del primo ciclo era il seguente (decompilato mediante IDA Pro 9.3):

```c
v6 = 4;
v7 = v4;
do
{
    v8 = *v7;
    v9 = *v7 / 3u;
    v27[v6] = *v7 % 3u;
    v27[v6 + 1] = (v9 - 3 * ((86 * v9) >> 8));
    v27[v6 + 2] = (((57 * v8) >> 9) - 3 * ((86 * ((57 * v8) >> 9)) >> 8));
    v27[v6 + 3] = (((19 * v8) >> 9) - 3 * ((86 * ((19 * v8) >> 9)) >> 8));
    v10 = (203 * v8) >> 14;
    v11 = v10 - 3;
    if ( v8 < 0xF3u )
    v11 = v10;
    v27[v6 + 4] = v11;
    v6 += 5;
    ++v7;
}
while ( v6 != 24 );
```
*(Ho deciso di nascondere i cast per rendere lo snippet il più conciso possibile)*

Questo codice, pur sembrando all'apparenza **orrendo**, non era altro che il risultato di una serie di ottimizzazioni aritmetiche applicate dal compilatore per calcolare semplicemente il resto della divisione per `3`.

La conclusione risultò evidente già dalle prime tre righe, le quali applicavano questa idea.
Eseguendo inoltre qualche prova, si poteva notare che tutti i valori hardcoded portavano esattamente al risultato citato: `86 * x >> 8 = x * 86/256 = x * 0.3359375`, valore abbastanza vicino al risultato della divisione per `3` (ossia `0.3 periodico`).

Applicando questo ragionamento a tutte le divisioni, la semplificazione più significativa è stata:

```
digit0 = (byte / 3**0) % 3
digit1 = (byte / 3**1) % 3
...
digit4 = (byte / 3**4) % 3
```

Capimmo che i primi 4 byte (`bbb{`) venivano scomposti in tuple di 5 cifre ternarie salvate in un array sullo stack.

#### Secondo, terzo e sesto ciclo 🥀
In questi cicli il codice, che inizialmente era ancora relativamente leggibile, divenne estremamente contorto...

```c
v12 = *(v4 + 4);
for ( i = 21; i != 103; i += 2 )
{
    v27[i + 3] = v12
                - (3 * ((__CFADD__(*(&v12 + 1), v12) + *(&v12 + 1) + v12) / 3)
                - (__CFADD__(*(&v12 + 1), v12)
                + *(&v12 + 1)));
    v27[i + 4] = (__CFADD__(
                    0xAAAAAAAAAAAAAAABLL
                * (3 * ((__CFADD__(*(&v12 + 1), v12) + *(&v12 + 1) + v12) / 3)
                    - (__CFADD__(*(&v12 + 1), v12)
                    + *(&v12 + 1))),
                    (__PAIR128__(
                        (v12 - ((__CFADD__(*(&v12 + 1), v12) + *(&v12 + 1) + v12) % 3)) >> 64,
                        3 * ((__CFADD__(*(&v12 + 1), v12) + *(&v12 + 1) + v12) / 3)
                    - (__CFADD__(*(&v12 + 1), v12)
                    + *(&v12 + 1)))
                    * __PAIR128__(0xAAAAAAAAAAAAAAAALL, 0xAAAAAAAAAAAAAAABLL)) >> 64)
                + ((__PAIR128__(
                    3 * ((__CFADD__(*(&v12 + 1), v12) + *(&v12 + 1) + v12) / 3)
                    - (__CFADD__(*(&v12 + 1), v12)
                    + *(&v12 + 1)),
                    3 * ((__CFADD__(*(&v12 + 1), v12) + *(&v12 + 1) + v12) / 3)
                    - (__CFADD__(*(&v12 + 1), v12)
                    + *(&v12 + 1)))
                * 0xAAAAAAAAAAAAAAABLL) >> 64))
                % 3;
    *&v12 = __udivti3(v12, *(&v12 + 1), 9, 0);
    *(&v12 + 1) = v14;
}
```

Per evitare di dover comprendere a fondo quel mattone di codice, decidemmo di analizzarlo in debug e di formulare alcune assunzioni molto semplici:

1. Il codice probabilmente faceva esattamente lo stesso lavoro del primo ciclo.
2. Il ciclo iterava con `i += 2`, quindi probabilmente generava 2 cifre o le univa in qualche modo.
3. Il ciclo compiva esattamente `(103 - 21) / 2 = 41` iterazioni.
4. Il pattern era molto simile a quello già osservato con `x - (3 * something) >> y`.

Dopo un paio di esecuzioni con gdb, notammo però che le cifre ternarie non seguivano i pattern del primo ciclo, quindi la situazione rimaneva da chiarire:

```
pwndbg> stack 50
v--- b
00:0000│ rsp 0x7fffffffd6f0 ◂— 2
01:0008│-ba8 0x7fffffffd6f8 ◂— 2
02:0010│-ba0 0x7fffffffd700 ◂— 1
03:0018│-b98 0x7fffffffd708 ◂— 0
04:0020│-b90 0x7fffffffd710 ◂— 1
v--- b
05:0028│-b88 0x7fffffffd718 ◂— 2
06:0030│-b80 0x7fffffffd720 ◂— 2
07:0038│-b78 0x7fffffffd728 ◂— 1
08:0040│-b70 0x7fffffffd730 ◂— 0
09:0048│-b68 0x7fffffffd738 ◂— 1
v--- b
0a:0050│-b60 0x7fffffffd740 ◂— 2
0b:0058│-b58 0x7fffffffd748 ◂— 2
0c:0060│-b50 0x7fffffffd750 ◂— 1
0d:0068│-b48 0x7fffffffd758 ◂— 0
0e:0070│-b40 0x7fffffffd760 ◂— 1
v--- {
0f:0078│-b38 0x7fffffffd768 ◂— 0
10:0080│-b30 0x7fffffffd770 ◂— 2
11:0088│-b28 0x7fffffffd778 ◂— 1
... ↓        2 skipped
v--- secondo ciclo (tutte b)
14:00a0│-b10 0x7fffffffd790 ◂— 2
15:00a8│-b08 0x7fffffffd798 ◂— 0
16:00b0│-b00 0x7fffffffd7a0 ◂— 0
17:00b8│-af8 0x7fffffffd7a8 ◂— 1
18:00c0│-af0 0x7fffffffd7b0 ◂— 1
19:00c8│-ae8 0x7fffffffd7b8 ◂— 2
1a:00d0│-ae0 0x7fffffffd7c0 ◂— 1
1b:00d8│-ad8 0x7fffffffd7c8 ◂— 2
1c:00e0│-ad0 0x7fffffffd7d0 ◂— 2
1d:00e8│-ac8 0x7fffffffd7d8 ◂— 0
1e:00f0│-ac0 0x7fffffffd7e0 ◂— 2
1f:00f8│-ab8 0x7fffffffd7e8 ◂— 0
20:0100│-ab0 0x7fffffffd7f0 ◂— 1
21:0108│-aa8 0x7fffffffd7f8 ◂— 0
22:0110│-aa0 0x7fffffffd800 ◂— 0
23:0118│-a98 0x7fffffffd808 ◂— 1
^--- nessun pattern preciso
```

Quel tentativo fallito ci fece perdere un po' di tempo. Tuttavia, dopo un paio di riletture del codice, ci accorgemmo di un dettaglio semplice che ci era sfuggito:

**la stringa veniva caricata come 128 bit (16 byte) senza venire mai modificata**

Ciò poteva significare che, a differenza del primo ciclo (dove c'era una corrispondenza 1:1 tra ciascun byte e 5 cifre in base 3), stavamo trattando un blocco di `(103 - 21) / 2 * 2 = 82` cifre ternarie (calcolo confermato dal fatto che `3**5` era approssimativamente uguale a `256`, mentre `3**82` era leggermente maggiore di `2**128`).

In altre parole, *16 byte* della flag venivano salvati come **un singolo blocco**.

L'idea in pseudocodice che ci formulammo fu quindi approssimativamente la seguente

```
var_128bit = pointer[X]
for with some ranges, step 2
    savevar[0] = var_128bit % 3
    savevar[1] = (var_128bit // 3) % 3

    // skip
    var_128bit /= 9
```

#### Quarto e quinto ciclo
Conclusa l'analisi dei cicli precedenti, decidemmo di ultimare l'esame del main osservando più nello specifico questi due cicli *apparentemente* molto semplici:

```c
v18 = *(v4 + 36);
for ( k = 185; ; k += 2 )
{
    v27[k + 3] = v18 % 3;
    if ( k == 225 )
    break;
    v27[k + 4] = v18 / 3 - 3 * ((0x5555555555555556LL * (v18 / 3)) >> 64);
    v18 /= 9u;
}
```

Il codice, un po' come nei cicli precedenti, iterava a passo di due sui byte della flag calcolando il resto delle divisioni per 3.

Notammo che tale codice era molto simile allo pseudocodice già mostrato, con la differenza che in questo caso il programma caricava un **intero a 64 bit** (`QWORD`) anziché uno a **128 bit** (`OWORD`).

Il valore `0x5555555555555556LL` non era nuovo e, nel contesto della nostra challenge, rappresentava la forma *floating point* dell'**inverso modulare di 3**.

Anche qui il programma caricava la porzione di flag come un singolo intero e ne estraeva le cifre ternarie a coppie.

#### Riepilogo dei cicli
Questa tabella riassume al meglio la situazione generata nel `main`:

| Ciclo | Range Byte | Tipo Dati Letto | Cifre ternarie Generate | Indici nell'array v27 |
| :--- | :--- | :--- | :--- | :--- |
| **Primo** | 0 - 3 | 4 byte singoli (char) | 20 | [4] - [23] |
| **Secondo** | 4 - 19 | Blocco da 16 byte (_OWORD) | 82 | [24] - [105] |
| **Terzo** | 20 - 35 | Blocco da 16 byte (_OWORD) | 82 | [106] - [187] |
| **Quarto** | 36 - 43 | Blocco da 8 byte (_QWORD) | 41 | [188] - [228] |
| **Quinto** | 44 - 51 | Blocco da 8 byte (_QWORD) | 41 | [229] - [269] |
| **Sesto** | 52 - 67 | Blocco da 16 byte (_OWORD) | 82 | [270] - [351]  |

### Analisi di `sub_11A0`
Questa funzione, come accennato all'inizio, era estremamente grande, motivo per cui un decompilatore normale (come IDA 🥀) non era in grado di decompilarla completamente 🥀.

#### Prima fase
Tuttavia, possiamo dedurre che elabori due blocchi da 82 cifre ternarie (per un totale di 164 cifre ternarie) per produrre un valore di controllo finale. Per analizzare questo circuito in maniera *black-box*, abbiamo costruito un oracolo dinamico tramite `libdebug` 🐍, implementando lo script risolutore riportato di seguito.

Nello script, la funzione `f10_stack_vectors` avvia il debugger disabilitando l'ASLR, recupera l'indirizzo di caricamento dell'eseguibile tramite `d.maps` e posiziona un primo breakpoint all'indirizzo `pie + 0x11A0`. A questo punto, il registro `r12` contiene l'indirizzo in memoria nel quale sono memorizzate le cifre ternarie in ingresso alla funzione. Sovrascrivendo la memoria a quell'indirizzo possiamo iniettare vettori arbitrari eludendo i vincoli sui caratteri ASCII del `main`. Successivamente, un secondo breakpoint a `pie + 0x5400` interrompe l'esecuzione subito prima della moltiplicazione. Leggendo dallo stack del processo (`rsp + 0x420` e `rsp + 0x1F80`), possiamo estrarre i due fattori effettivamente elaborati.

La funzione `f10_affine_offsets` sfrutta questa tecnica per determinare la relazione lineare affine (una traslazione modulare) tra l'input controllato e i fattori letti dallo stack. Inviando un input nullo, otteniamo i vettori di offset costanti $\alpha$ e $\beta$, tali che:
$$A_i = (x_i + \alpha_i) \pmod 3$$
$$B_i = (y_i + \beta_i) \pmod 3$$
In cui $x_i$ e $y_i$ sono le cifre ternarie della flag (dal secondo e terzo blocco), mentre $\alpha_i$ e $\beta_i$ sono gli offset affini determinati eseguendo il programma con un input nullo e leggendo i valori di base sullo stack.

Al termine di questa elaborazione, il programma confronta il risultato con una costante di 168 cifre ternarie memorizzata a partire dall'indirizzo `0x4E050` (`TARGET_F10`). Interpretando questo array come la rappresentazione in base 3 di un intero a precisione arbitraria, otteniamo il valore target:
$$T = 69315507563335000426881137137421870202776768428849895573283403915458679359157$$

Trattandosi di una moltiplicazione tra due numeri rappresentati da 82 cifre ternarie, il target $T$ deve essere il prodotto directo dei due fattori in base 3. Fattorizzando $T$, scopriamo che è composto esattamente da due fattori primi:
- $f_1 = 221815467394800111963839297593696124903$
- $f_2 = 312491767943139940981443826148003062019$

Avendo i due fattori e i vettori di offset affine $\alpha$ e $\beta$ estratti tramite debug, invertiamo la relazione per ricostruire le cifre ternarie originali della flag:
$$x_i = (f_1[i] - \alpha_i) \pmod 3$$
$$y_i = (f_2[i] - \beta_i) \pmod 3$$

Convertendo queste cifre ternarie in byte, otteniamo i due blocchi da 16 byte della flag: `kQMM2FhlSBO4fEYF` e `ho5azaRrlTdxPsRx`. Verifichiamo poi la correttezza dei blocchi a runtime mediante la funzione `f10_ok` dello script, la quale esegue il programma fino al punto di controllo a `pie + 0x17CB6` e legge dallo stack all'indirizzo `rsp + 0x1500` per confrontare il valore finale con `TARGET_F10`.

Lo script Python completo ed esatto utilizzato per estrarre gli offset affini e calcolare le cifre ternarie corrette della prima fase è il seguente; il sorgente completo è disponibile anche nella tendina [qui](#sat-stage-py):

```python
import struct
from pathlib import Path
from libdebug import debugger

F10_FACTORS = (
    221815467394800111963839297593696124903,
    312491767943139940981443826148003062019,
)

BIN = Path("myfavoriteinstructions")
BIN_DATA = BIN.read_bytes()
TARGET_F10 = struct.unpack("<168Q", BIN_DATA[0x4E050 : 0x4E050 + 168 * 8])

def flag_to_trits(s):
    assert len(s) >= 68
    out = []
    for b in s[:4]:
        x = b
        for _ in range(5):
            out.append(x % 3)
            x //= 3
    for off, ntrits in [(4, 82), (20, 82), (36, 41), (44, 41), (52, 82)]:
        size = 16 if ntrits == 82 else 8
        x = int.from_bytes(s[off : off + size], "little")
        for _ in range(ntrits):
            out.append(x % 3)
            x //= 3
    assert len(out) == 348
    return out

def trits_to_bytes_prefix(trits):
    out = bytearray()
    pos = 0
    for _ in range(4):
        x = 0
        p = 1
        for t in trits[pos : pos + 5]:
            x += t * p
            p *= 3
        out.append(x & 0xff)
        pos += 5
    for ntrits, size in [(82, 16), (82, 16), (41, 8), (41, 8), (82, 16)]:
        x = 0
        p = 1
        for t in trits[pos : pos + ntrits]:
            x += t * p
            p *= 3
        out += x.to_bytes(size, "little")
        pos += ntrits
    return bytes(out)

def get_pie_base(d):
    for m in d.maps:
        if 'myfavoriteinstructions' in (m.backing_file or ''):
            return m.start
    return 0x555555554000

def trits_of(n, length):
    out = []
    for _ in range(length):
        out.append(n % 3)
        n //= 3
    if n:
        return None
    return out

def f10_stack_vectors(trits):
    d = debugger(["./myfavoriteinstructions", "A" * 68], aslr=False)
    d.run()
    pie = get_pie_base(d)
    
    bp_start = d.breakpoint(pie + 0x11A0)
    d.cont()
    d.wait()
    trits_data = struct.pack("<348Q", *trits)
    d.memory[d.regs.r12, len(trits_data)] = trits_data
    bp_start.disable()
    
    bp = d.breakpoint(pie + 0x5400)
    d.cont()
    d.wait()
    
    rsp = d.regs.rsp
    a_data = d.memory[rsp + 0x420, 168 * 8]
    b_data = d.memory[rsp + 0x1F80, 168 * 8]
    a = list(struct.unpack("<168Q", a_data))
    b = list(struct.unpack("<168Q", b_data))
    d.kill()
    return a, b

def f10_affine_offsets():
    base = flag_to_trits(b"A" * 68)
    alpha = []
    beta = []
    for i in range(82):
        avals = []
        bvals = []
        for x in range(3):
            tr = base[:]
            tr[20 + i] = x
            tr[102 + i] = x
            a, b = f10_stack_vectors(tr)
            avals.append(a[i])
            bvals.append(b[i])
        alpha.append(avals[0])
        beta.append(bvals[0])
    return alpha, beta

def f10_ok(raw):
    d = debugger(["./myfavoriteinstructions", raw.decode("latin-1")], aslr=False)
    d.run()
    pie = get_pie_base(d)
    bp = d.breakpoint(pie + 0x17CB6)
    d.cont()
    d.wait()
    rsp = d.regs.rsp
    vec = struct.unpack("<168Q", d.memory[rsp + 0x1500, 168 * 8])
    d.kill()
    return vec == TARGET_F10

def solve_prefix_and_f10():
    print("[f10] decoding multiplication stage")
    alpha, beta = f10_affine_offsets()
    base = flag_to_trits(b"A" * 68)

    for left, right in (F10_FACTORS, F10_FACTORS[::-1]):
        ad = trits_of(left, 82)
        bd = trits_of(right, 82)
        if ad is None or bd is None:
            continue
        trits = base[:]
        trits[20:102] = [(ad[i] - alpha[i]) % 3 for i in range(82)]
        trits[102:184] = [(bd[i] - beta[i]) % 3 for i in range(82)]
        try:
            raw = trits_to_bytes_prefix(trits)
        except OverflowError:
            continue
        if all(32 <= c < 127 for c in raw[:36]) and f10_ok(raw):
            print(f"[f10] {raw[:36].decode()}")
            return raw[:36]

    raise SystemExit("f10 decode failed")
```

#### Seconda fase
Nella seconda parte della sfida (byte 36-43) è presente un'enorme tabella di `15x41` elementi e un vettore di vettori di `15` elementi chiamato "vettore target"; ogni elemento nella tabella e nel vettore è composto da array di 20 cifre ternarie e il ciclo principale funziona approssimativamente così: 

```text
for j in range(15):
    combina 41 elementi della tabella usando 41 cifre ternarie in input
    compara il risultato con il vettore target[j]
```

Ipotizziamo quindi che, poiché le operazioni devono comprimere 41 elementi in uno solo, ci troviamo di fronte a qualcosa di simile a:

```text
target_j = sum_i x_i * table[j][i]
```

Da notare che la somma e la moltiplicazione non sono "standard": una è essenzialmente la ripetizione dell'altra molte volte.

Dopo aver determinato che gli elementi che entrano nel circuito sono array di 20 cifre ternarie, ipotizziamo che l'operazione sia associativa e commutativa, così da poter trattare gli elementi come un gruppo ciclico di ordine $3^{20}$. Per testare questa idea, chiediamo a Codex di scrivere alcune funzioni per interfacciare queste operazioni con libdebug (i nomi delle funzioni sono ipotetici):

```python
class Oracle:
    def __init__(self, prefix):
        # Inizializza il debugger con la flag parziale trovata finora
        raw = prefix.ljust(68, b"A")
        self.d = debugger(["./myfavoriteinstructions", raw.decode("latin-1")], aslr=False)
        self.d.run()
        self.pie = get_pie_base(self.d)
        
        # Breakpoint all'inizio dell'operazione del gruppo (stage 3)
        bp_start = self.d.breakpoint(self.pie + 0x1C0A1)
        self.d.cont()
        self.d.wait()
        
        # Salviamo uno snapshot dello stato per poterlo ripristinare rapidamente ad ogni chiamata
        self.rsp = self.d.regs.rsp
        self.snap_path = "/tmp/group_snap_libdebug.json"
        snap = self.d.create_snapshot()
        snap.save(self.snap_path)
        
        # Breakpoint per intercettare il ciclo interno e la fine del calcolo
        self.bp_patch = self.d.breakpoint(self.pie + 0x1CFB9)
        self.bp_stop = self.d.breakpoint(self.pie + 0x1CF90)
        self.bp_patch.disable()
        self.bp_stop.disable()

    def _eval(self, custom, vals, stop):
        # Ripristina lo stato iniziale tramite snapshot
        self.d.load_snapshot(self.snap_path)
        
        # Scrive i coefficienti desiderati all'offset dello stack
        val_data = struct.pack("<41Q", *vals)
        self.d.memory[self.rsp + 0x420, len(val_data)] = val_data
        
        self.bp_patch.enable()
        self.bp_stop.enable()
        
        out = None
        while True:
            self.d.cont()
            self.d.wait()
            rip = self.d.regs.rip
            # Patcha i valori intermedi della tabella fornendo gli operandi custom
            if rip == self.pie + 0x1CFB9:
                i = self.d.regs.r14
                if i in custom:
                    row = custom[i] + (0,)
                    val_bytes = struct.pack("<21Q", *row)
                    self.d.memory[self.rsp + 0x9C0, len(val_bytes)] = val_bytes
            # Legge il risultato finale all'offset del loop desiderato
            elif rip == self.pie + 0x1CF90:
                if self.d.regs.r14 == stop:
                    out = tuple(struct.unpack("<Q", self.d.memory[self.rsp + off, 8])[0] for off in ORDER20_OFFSETS)
                    break
            else:
                raise RuntimeError(f"Unexpected RIP {hex(rip)}")
                
        self.bp_patch.disable()
        self.bp_stop.disable()
        return out

    def add(self, a, b):
        vals = [0] * 41
        vals[0] = 1
        vals[1] = 1
        return self._eval({0: a, 1: b}, vals, 2)

    def double(self, a):
        vals = [0] * 41
        vals[0] = 2
        return self._eval({0: a}, vals, 1)
```

Da lì proviamo diverse combinazioni e constatiamo che le operazioni sono effettivamente associative e che l'elemento generatore si trova in `table[0][0]`, pertanto possiamo trattare gli elementi come un gruppo ciclico.

Poiché non vogliamo occuparci dei dettagli circuitali o delle operazioni sulle cifre ternarie e dato che possiamo utilizzare l'oracolo per produrre elementi, decidiamo di applicare l'algoritmo di Pohlig–Hellman per ottenere i coefficienti degli elementi (in notazione additiva) per ciascun elemento della tabella e per il vettore target. Questo risulta particolarmente semplice, dato che gli unici stati delle cifre ternarie sono `{0, 1, 2}`. Pertanto chiediamo a Codex di implementare esattamente questa procedura (riportiamo solo la funzione di log perché il file completo è troppo grande):

```python
def log_base(
    oracle: Oracle,
    gamma: tuple[int, ...],
    gamma2: tuple[int, ...],
    gen_pows: list[tuple[int, ...]],
    point: tuple[int, ...],
) -> int:
    x = 0
    residual = point
    # Pohlig-Hellman for a cyclic group of order 3^20, additive notation.
    for k in range(20):
        probe = scalar_mul(oracle, residual, 3 ** (19 - k))
        if probe == ZERO:
            digit = 0
        elif probe == gamma:
            digit = 1
        elif probe == gamma2:
            digit = 2
        else:
            raise ValueError(("unexpected PH digit", k, probe))
        x += digit * (3**k)
        if digit:
            residual = point_sub(oracle, residual, gen_pows[k])
            if digit == 2:
                residual = point_sub(oracle, residual, gen_pows[k])
    return x
```

In questo modo otteniamo numeri normali in Z modulo $3^{20}$, il che significa che la strana operazione si riduce a:
```
sum_i x_i * log(table[j][i]) == log(target[j]) mod 3^20
```

dove `sum_i` è una somma reale e `*` la moltiplicazione tra i due log. Poiché ora la tabella e i vettori sono numeri semplici, ci riferiamo alla tabella "loggata" come `A` e al vettore target come `B`.

A quel punto l'idea è che si tratti di una combinazione lineare dei vettori `A[j,1]`, `A[j,2]`, ... `A[j,i]` pesata con i pesi `x_1, x_2, ...`. Per trovare quale combinazione lineare produce il vettore target, decidiamo di usare LLL, ed è ciò che abbiamo implementato:

```python
def solve_stage3_lll(prefix: bytes) -> bytes:
    print("[stage3] solving cyclic-group equations with LLL")
    coeffs, rhs = load_or_compute_stage3_logs()
    n, m = 41, 15
    centered_rhs = [
        (rhs[j] - sum(coeffs[j][i] for i in range(n))) % ORDER3_20
        for j in range(m)
    ]

    scale = 1000
    marker = 10
    mat = IntegerMatrix(n + m + 1, n + m + 1)
    for i in range(n):
        mat[i, i] = 1
        for j in range(m):
            mat[i, n + j] = scale * coeffs[j][i]
    for j in range(m):
        mat[n + j, n + j] = scale * ORDER3_20
        mat[n + m, n + j] = -scale * centered_rhs[j]
    mat[n + m, n + m] = marker

    LLL.reduction(mat, delta=0.99)
    mapped = None
    for row in range(mat.nrows):
        vec = [int(mat[row, col]) for col in range(mat.ncols)]
        if abs(vec[-1]) != marker:
            continue
        sign = 1 if vec[-1] == marker else -1
        centered = [sign * vec[i] for i in range(n)]
        if all(v in (-1, 0, 1) for v in centered):
            candidate = [v + 1 for v in centered]
            ok = all(
                (sum(coeffs[j][i] * candidate[i] for i in range(n)) - rhs[j]) % ORDER3_20 == 0
                for j in range(m)
            )
            if ok:
                mapped = candidate
                break
    if mapped is None:
        raise SystemExit("stage3 LLL failed")
```

In questo modo recuperiamo i logaritmi (log) degli elementi della flag che entrano nel circuito, perciò possiamo ricostruire gli elementi invertendo la mappatura logaritmica:

```python
    _maps, invmaps = s3.affine_maps()
    trits = flag_to_trits(prefix + b"A" * (68 - len(prefix)))
    for i, value in enumerate(mapped):
        trits[184 + i] = invmaps[i][value]
    raw = trits_to_bytes_prefix(trits)
    print(f"[stage3] {raw[:44].decode()}")
    return raw[:44]
```

Alla fine otteniamo la seconda parte della flag: "6ue7npnj" e la flag nota si estende a `bbb{kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx6ue7npnj`.

#### Ultime due fasi
In queste fasi conclusive ci mancano pochi byte per finire la flag; pur conoscendo il procedimento usato per generare le cifre ternarie, ci accorgiamo che:

1. Il codice non ha pattern che riusciamo a riconoscere facilmente.
2. Il codice da analizzare si trova verso la fine della funzione.

Continuando a lavorare con i prefissi, decidiamo però di spostare la nostra attenzione su un altro tipo di soluzione: **esecuzione simbolica** mediante uno script scritto con l'aiuto di un LLM.

L'obiettivo è creare uno script simile ad angr con le capacità di creare *snapshot* di memoria e di impostare vincoli (constraint) sugli input simbolici (*la flag*).

Pur non essendoci differenze significative nella soluzione dei due stage, notiamo come ovviamente la soluzione debba procedere in modo sequenziale (prima si deve risolvere il penultimo chunk per poi risolvere quello conclusivo composto da un `}` finale).

Per fare questo, partiamo dall'idea di emulare simbolicamente le istruzioni dell'eseguibile traducendole direttamente in vincoli SAT (CNF). Invece di usare angr (che per via delle istruzioni custom come `bsr` e `bzhi` usate per le porte ternarie avrebbe riscontrato difficoltà a risolvere i vincoli), con l'aiuto di un LLM scriviamo un piccolo emulatore in Python usando Capstone per disassemblare il codice dell'eseguibile e tradurlo in clausole CNF per pysat.

L'approccio basato su snapshot ci permette di evitare l'emulazione dell'intero binario dall'inizio: eseguiamo il codice concretamente con Unicorn fino all'inizio dello stage specifico, salviamo lo stato di stack e registri, e da lì avviamo l'emulatore simbolico impostando come variabili simboliche solo le cifre ternarie mancanti.

Ad esempio, per forzare i caratteri ASCII della flag, utilizziamo dei vincoli pseudo-booleani che collegano le cifre ternarie in ingresso ai corrispondenti byte:

```python
def add_byte_constraints(emu: SatEmu, trit_start: int, trit_count: int, allowed_per_byte: list[bytes]) -> None:
    carry_max = trit_count
    carries: list[list[int]] = []
    for _ in range(len(allowed_per_byte) + 1):
        vals = [emu.cnf.new_lit() for _ in range(carry_max + 1)]
        exactly_one(emu.cnf, vals)
        carries.append(vals)

    emu.cnf.add([carries[0][0]])
    emu.cnf.add([carries[-1][0]])

    for byte_index, allowed in enumerate(allowed_per_byte):
        byte_lits = [emu.cnf.new_lit() for _ in allowed]
        exactly_one(emu.cnf, byte_lits)

        lits: list[int] = []
        weights: list[int] = []
        for i in range(trit_count):
            coeff = (3**i >> (8 * byte_index)) & 0xFF
            if not coeff:
                continue
            val = emu.inputs[trit_start + i]
            assert val.lits is not None
            for digit in (1, 2):
                lits.append(val.lits[digit])
                weights.append(coeff * digit)

        for carry_value in range(carry_max + 1):
            lits.append(carries[byte_index][carry_value])
            weights.append(carry_value)

        for i, char in enumerate(allowed):
            lits.append(byte_lits[i])
            weights.append(255 - char)
        for carry_value in range(carry_max + 1):
            lits.append(carries[byte_index + 1][carry_value])
            weights.append(256 * (carry_max - carry_value))

        cnf = PBEnc.equals(
            lits=lits,
            weights=weights,
            bound=255 + 256 * carry_max,
            top_id=emu.cnf.next_var - 1,
            encoding=PBEncType.adder,
        )
        emu.cnf.clauses.extend(cnf.clauses)
        emu.cnf.next_var = max(emu.cnf.next_var, cnf.nv + 1)
```

Per il penultimo stage partiamo caricando lo snapshot all'indirizzo `pie + 0x26400`, eseguendo l'emulatore simbolico fino a `0x325BC` e imponendo che il valore nello stack all'indirizzo `rsp + 0xF08` sia uguale a 2:

```python
def solve_stage4_sat(prefix: bytes) -> bytes:
    emu, _snap = make_symbolic_emu(prefix, list(range(225, 266)), 0x26400)
    emu.run(0x325BC, start=0x26400)
    emu.cnf.force(emu.qload(emu.regs["rsp"] + 0xF08), 2)
    add_byte_constraints(emu, 225, 41, [BASE62] * 8)
    model = solve_cnf(emu.cnf, "stage4")
    raw = model_to_raw(prefix, emu, model)
    return raw[:52]
```

Questo ci fornisce la flag parziale `bbb{kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx6ue7npnjATDcm6d4`.

A questo punto ripetiamo lo stesso identico procedimento per lo stage finale, partendo dallo snapshot a `pie + 0x325BC` ed emulando fino a `0x4D881`, forzando il registro `rax` a 2 per soddisfare l'ultimo controllo della funzione di validazione:

```python
def solve_final_sat(prefix: bytes) -> bytes:
    emu, _snap = make_symbolic_emu(prefix, list(range(266, 348)), 0x325BC)
    emu.run(0x4D881, start=0x325BC)
    emu.cnf.force(emu.regs["rax"], 2)
    add_byte_constraints(emu, 266, 82, [BASE62] * 15 + [b"}"])
    model = solve_cnf(emu.cnf, "final")
    raw = model_to_raw(prefix, emu, model)
    return raw[:68]
```

Risolvendo quest'ultimo blocco SAT otteniamo gli ultimi byte mancanti e il carattere `}` finale, recuperando così la flag definitiva:

`bbb{kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx6ue7npnjATDcm6d4hPe25PNGBdT9MK0}`


{{< collapse id="sat-stage-py" summary="Mostra `sat_stage.py`" >}}
```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from pysat.solvers import Solver


CODE = Path("myfavoriteinstructions").read_bytes()
TEXT_START = 0x11A0
INPUT = 0x100000
STACK = 0x800000
MASK64 = (1 << 64) - 1

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True
INSNS = {ins.address: ins for ins in MD.disasm(CODE[TEXT_START:0x4D990], TEXT_START)}

REG64 = {}
for names, full in [
    (["rax", "eax", "ax", "al", "ah"], "rax"),
    (["rbx", "ebx", "bx", "bl", "bh"], "rbx"),
    (["rcx", "ecx", "cx", "cl", "ch"], "rcx"),
    (["rdx", "edx", "dx", "dl", "dh"], "rdx"),
    (["rsi", "esi", "si", "sil"], "rsi"),
    (["rdi", "edi", "di", "dil"], "rdi"),
    (["rbp", "ebp", "bp", "bpl"], "rbp"),
    (["rsp", "esp", "sp", "spl"], "rsp"),
]:
    for name in names:
        REG64[name] = full
for i in range(8, 16):
    for suffix in ("", "d", "w", "b"):
        REG64[f"r{i}{suffix}"] = f"r{i}"


def trits_to_bytes_prefix(trits: list[int]) -> bytes:
    out = bytearray()
    pos = 0
    for _ in range(4):
        x = 0
        p = 1
        for t in trits[pos : pos + 5]:
            x += t * p
            p *= 3
        out.append(x & 0xff)
        pos += 5
    for ntrits, size in [(82, 16), (82, 16), (41, 8), (41, 8), (82, 16)]:
        x = 0
        p = 1
        for t in trits[pos : pos + ntrits]:
            x += t * p
            p *= 3
        out += x.to_bytes(size, "little")
        pos += ntrits
    return bytes(out)


def flag_to_trits(s: bytes) -> list[int]:
    assert len(s) >= 68
    out: list[int] = []
    for b in s[:4]:
        x = b
        for _ in range(5):
            out.append(x % 3)
            x //= 3
    for off, ntrits in [(4, 82), (20, 82), (36, 41), (44, 41), (52, 82)]:
        size = 16 if ntrits == 82 else 8
        x = int.from_bytes(s[off : off + size], "little")
        for _ in range(ntrits):
            out.append(x % 3)
            x //= 3
    assert len(out) == 348
    return out


def canon(name: str) -> str:
    return REG64.get(name, name)


@dataclass(frozen=True)
class TVal:
    const: int | None = None
    lits: tuple[int, int, int] | None = None

    def is_const(self) -> bool:
        return self.const is not None


class CNF:
    def __init__(self):
        self.next_var = 1
        self.clauses: list[list[int]] = []
        self.cache: dict[tuple, TVal] = {}

    def new_lit(self) -> int:
        lit = self.next_var
        self.next_var += 1
        return lit

    def add(self, clause: list[int]) -> None:
        self.clauses.append(clause)

    def new_val(self) -> TVal:
        lits = (self.new_lit(), self.new_lit(), self.new_lit())
        self.add([*lits])
        self.add([-lits[0], -lits[1]])
        self.add([-lits[0], -lits[2]])
        self.add([-lits[1], -lits[2]])
        return TVal(lits=lits)

    def const(self, value: int) -> TVal | int:
        if 0 <= value <= 2:
            return TVal(const=value)
        return value

    def force(self, val: TVal, value: int) -> None:
        if val.is_const():
            if val.const != value:
                self.add([])
            return
        assert val.lits is not None
        self.add([val.lits[value]])

    def gate2(self, op: str, a: TVal, b: TVal, table) -> TVal:
        if a.is_const() and b.is_const():
            return TVal(const=table[a.const][b.const])
        key = (op, a, b)
        if key in self.cache:
            return self.cache[key]
        out = self.new_val()
        assert out.lits is not None
        avals = [a.const] if a.is_const() else [0, 1, 2]
        bvals = [b.const] if b.is_const() else [0, 1, 2]
        for av in avals:
            for bv in bvals:
                cond = []
                if not a.is_const():
                    assert a.lits is not None
                    cond.append(-a.lits[av])
                if not b.is_const():
                    assert b.lits is not None
                    cond.append(-b.lits[bv])
                self.add([*cond, out.lits[table[av][bv]]])
        self.cache[key] = out
        return out

    def bsr(self, old: TVal | int, src: TVal | int) -> TVal | int:
        if isinstance(src, int):
            if src == 0:
                return old
            return src.bit_length() - 1
        if isinstance(old, int):
            if 0 <= old <= 2:
                old = TVal(const=old)
            else:
                raise NotImplementedError(("nontrit old bsr", old, src))
        table = [[oldv, 0, 1] for oldv in range(3)]
        return self.gate2("bsr", old, src, table)

    def bzhi(self, src: TVal | int, idx: TVal | int) -> TVal | int:
        if isinstance(idx, int):
            if idx == 0:
                return 0
            if idx == 1:
                if isinstance(src, int):
                    return src & 1
                return self.gate2("mod2", src, TVal(const=0), [[0], [1], [0]])  # non raggiungibile
            return src
        if isinstance(src, int):
            if 0 <= src <= 2:
                src = TVal(const=src)
            else:
                raise NotImplementedError(("nontrit src bzhi", src, idx))
        table = [
            [0, 0, 0],
            [0, 1, 1],
            [0, 0, 2],
        ]
        return self.gate2("bzhi", src, idx, table)


def is_conc(x) -> bool:
    return isinstance(x, int)


class SatEmu:
    def __init__(self, fixed: list[int], symbolic: list[int]):
        self.cnf = CNF()
        self.regs = {r: 0 for r in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]}
        self.regs.update({
            "rbx": 349,
            "r9": 266,
            "r12": INPUT,
            "r13": 0x200000,
            "r14": 0xAAAAAAAAAAAAAAAB,
            "r15": 0xAAAAAAAAAAAAAAAA,
            "rsp": STACK + 0x100008,
        })
        self.mem: dict[int, TVal | int] = {}
        self.xmm: dict[str, tuple[TVal | int, TVal | int]] = {}
        self.inputs: dict[int, TVal] = {}
        symbolic_set = set(symbolic)
        for i in range(348):
            if i in symbolic_set:
                val = self.cnf.new_val()
                self.inputs[i] = val
                self.mem[INPUT + i * 8] = val
            else:
                self.mem[INPUT + i * 8] = fixed[i]
        self.last_cmp = (0, 0)
        self.steps = 0

    def reg(self, name: str):
        return self.regs.get(canon(name), 0)

    def write_reg(self, name: str, val):
        self.regs[canon(name)] = val

    def addr(self, ins, op) -> int:
        m = op.mem
        base = 0
        if m.base:
            bname = ins.reg_name(m.base)
            base = ins.address + ins.size if bname == "rip" else self.reg(bname)
            if not is_conc(base):
                raise NotImplementedError(("symbolic base", hex(ins.address), ins.op_str))
        idx = 0
        if m.index:
            idx = self.reg(ins.reg_name(m.index))
            if not is_conc(idx):
                raise NotImplementedError(("symbolic index", hex(ins.address), ins.op_str))
        return (base + idx * m.scale + m.disp) & MASK64

    def qload(self, addr: int):
        if addr in self.mem:
            return self.mem[addr]
        if 0 <= addr <= len(CODE) - 8:
            return int.from_bytes(CODE[addr:addr + 8], "little")
        return 0

    def qstore(self, addr: int, val):
        self.mem[addr] = val

    def read_op(self, ins, op):
        if op.type == X86_OP_IMM:
            return op.imm & MASK64
        if op.type == X86_OP_REG:
            return self.reg(ins.reg_name(op.reg))
        if op.type == X86_OP_MEM:
            return self.qload(self.addr(ins, op))
        raise NotImplementedError(op.type)

    def write_op(self, ins, op, val):
        if op.type == X86_OP_REG:
            self.write_reg(ins.reg_name(op.reg), val)
            return
        if op.type == X86_OP_MEM:
            self.qstore(self.addr(ins, op), val)
            return
        raise NotImplementedError(op.type)

    def copy(self, dst: int, src: int, nbytes: int):
        vals = [self.qload(src + i * 8) for i in range(nbytes // 8)]
        for i, val in enumerate(vals):
            self.qstore(dst + i * 8, val)

    def zero(self, dst: int, nbytes: int):
        for i in range(nbytes // 8):
            self.qstore(dst + i * 8, 0)

    def run(self, stop: int, start: int = TEXT_START):
        rip = start
        while rip != stop:
            ins = INSNS[rip]
            nrip = rip + ins.size
            self.steps += 1
            if self.steps % 250000 == 0:
                print("steps", self.steps, "rip", hex(rip), "vars", self.cnf.next_var - 1, "clauses", len(self.cnf.clauses), flush=True)
            m = ins.mnemonic
            ops = ins.operands
            if m in {"nop", "endbr64"}:
                pass
            elif m == "push":
                self.regs["rsp"] -= 8
                self.qstore(self.regs["rsp"], self.read_op(ins, ops[0]))
            elif m == "pop":
                self.write_op(ins, ops[0], self.qload(self.regs["rsp"]))
                self.regs["rsp"] += 8
            elif m == "mov":
                self.write_op(ins, ops[0], self.read_op(ins, ops[1]))
            elif m in {"movups", "movaps"}:
                dst, src = ops
                if dst.type == X86_OP_REG:
                    addr = self.addr(ins, src)
                    self.xmm[ins.reg_name(dst.reg)] = (self.qload(addr), self.qload(addr + 8))
                elif dst.type == X86_OP_MEM:
                    addr = self.addr(ins, dst)
                    lo, hi = self.xmm[ins.reg_name(src.reg)]
                    self.qstore(addr, lo)
                    self.qstore(addr + 8, hi)
                else:
                    raise NotImplementedError((hex(rip), m, ins.op_str))
            elif m == "xorps":
                self.xmm[ins.reg_name(ops[0].reg)] = (0, 0)
            elif m == "xor":
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                    self.write_op(ins, ops[0], 0)
                else:
                    a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                    if not (is_conc(a) and is_conc(b)):
                        raise NotImplementedError(("symbolic xor", hex(rip), ins.op_str))
                    self.write_op(ins, ops[0], a ^ b)
            elif m == "add":
                a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic add", hex(rip), ins.op_str))
                self.write_op(ins, ops[0], (a + b) & MASK64)
            elif m == "sub":
                a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic sub", hex(rip), ins.op_str))
                self.write_op(ins, ops[0], (a - b) & MASK64)
            elif m == "inc":
                a = self.read_op(ins, ops[0])
                if not is_conc(a):
                    raise NotImplementedError(("symbolic inc", hex(rip), ins.op_str))
                self.write_op(ins, ops[0], a + 1)
            elif m == "shr":
                a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic shr", hex(rip), ins.op_str))
                self.write_op(ins, ops[0], (a >> (b & 0x3f)) & MASK64)
            elif m == "shl":
                a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic shl", hex(rip), ins.op_str))
                self.write_op(ins, ops[0], (a << (b & 0x3f)) & MASK64)
            elif m == "addl":
                a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic addl", hex(rip), ins.op_str))
                self.write_op(ins, ops[0], (a + b) & MASK64)
            elif m == "lea":
                self.write_op(ins, ops[0], self.addr(ins, ops[1]))
            elif m == "imul":
                if len(ops) == 3:
                    a, b = self.read_op(ins, ops[1]), self.read_op(ins, ops[2])
                    self.write_op(ins, ops[0], a * b)
                elif len(ops) == 2:
                    a, b = self.read_op(ins, ops[0]), self.read_op(ins, ops[1])
                    self.write_op(ins, ops[0], a * b)
                else:
                    raise NotImplementedError((hex(rip), m, ins.op_str))
            elif m == "bsr":
                self.write_op(ins, ops[0], self.cnf.bsr(self.read_op(ins, ops[0]), self.read_op(ins, ops[1])))
            elif m == "bzhi":
                self.write_op(ins, ops[0], self.cnf.bzhi(self.read_op(ins, ops[1]), self.read_op(ins, ops[2])))
            elif m == "cmp":
                self.last_cmp = (self.read_op(ins, ops[0]), self.read_op(ins, ops[1]))
            elif m in {"jne", "je", "jb"}:
                a, b = self.last_cmp
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic branch", hex(rip), ins.op_str))
                take = (a != b) if m == "jne" else (a == b) if m == "je" else (a < b)
                if take:
                    nrip = int(ops[0].imm)
            elif m == "jmp":
                nrip = int(ops[0].imm)
            elif m == "cmovae":
                a, b = self.last_cmp
                if not (is_conc(a) and is_conc(b)):
                    raise NotImplementedError(("symbolic cmovae", hex(rip), ins.op_str))
                if a >= b:
                    self.write_op(ins, ops[0], self.read_op(ins, ops[1]))
            elif m == "call":
                target = int(ops[0].imm)
                if target == 0x1050:
                    self.zero(self.regs["rdi"], self.regs["rdx"])
                    self.regs["rax"] = self.regs["rdi"]
                elif target in {0x1060, 0x1090}:
                    self.copy(self.regs["rdi"], self.regs["rsi"], self.regs["rdx"])
                    self.regs["rax"] = self.regs["rdi"]
                else:
                    raise NotImplementedError(("call", hex(rip), hex(target)))
            else:
                raise NotImplementedError((hex(rip), m, ins.op_str))
            rip = nrip


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["f10"], default="f10")
    ap.add_argument("--solver", default="kissat")
    args = ap.parse_args()
    fixed = flag_to_trits((b"bbb{" + b"A" * 64))
    symbolic = list(range(20, 184))
    emu = SatEmu(fixed, symbolic)
    emu.run(0x17CB6)
    target = struct.unpack("<168Q", CODE[0x4E050:0x4E050 + 168 * 8])
    base = emu.regs["rsp"] + 0x1500
    for i, value in enumerate(target):
        val = emu.qload(base + i * 8)
        if isinstance(val, TVal):
            emu.cnf.force(val, value)
        else:
            if val != value:
                emu.cnf.add([])
    print("built", "steps", emu.steps, "vars", emu.cnf.next_var - 1, "clauses", len(emu.cnf.clauses), flush=True)
    with Solver(name=args.solver, bootstrap_with=emu.cnf.clauses) as solver:
        print("solving", flush=True)
        ok = solver.solve()
        print("sat", ok, flush=True)
        if not ok:
            return
        model = set(solver.get_model())
    trits = fixed[:]
    for i, val in emu.inputs.items():
        assert val.lits is not None
        for digit, lit in enumerate(val.lits):
            if lit in model:
                trits[i] = digit
                break
    raw = trits_to_bytes_prefix(trits)
    print(raw[:68])
    print(trits[20:184])


if __name__ == "__main__":
    main()
```
{{< /collapse >}}

{{< collapse id="solve-py" summary="Mostra `solve.py`" >}}
```python
#!/usr/bin/env python3

import multiprocessing as mp
import pickle
import struct
import time
from pathlib import Path

from fpylll import IntegerMatrix, LLL
from pysat.pb import PBEnc, EncType as PBEncType
from pysat.solvers import Solver

from sat_stage import INPUT, SatEmu
from libdebug import debugger

# --- Costanti & Helpers ---

BASE62 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
F10_FACTORS = (
    221815467394800111963839297593696124903,
    312491767943139940981443826148003062019,
)
ORDER3_20 = 3**20

BIN = Path("myfavoriteinstructions")
BIN_DATA = BIN.read_bytes()
TARGET_F10 = struct.unpack("<168Q", BIN_DATA[0x4E050 : 0x4E050 + 168 * 8])
T_F10 = sum(v * (3**i) for i, v in enumerate(TARGET_F10))


def flag_to_trits(s):
    assert len(s) >= 68
    out = []
    for b in s[:4]:
        x = b
        for _ in range(5):
            out.append(x % 3)
            x //= 3
    for off, ntrits in [(4, 82), (20, 82), (36, 41), (44, 41), (52, 82)]:
        size = 16 if ntrits == 82 else 8
        x = int.from_bytes(s[off : off + size], "little")
        for _ in range(ntrits):
            out.append(x % 3)
            x //= 3
    assert len(out) == 348
    return out


def trits_to_bytes_prefix(trits):
    out = bytearray()
    pos = 0
    for _ in range(4):
        x = 0
        p = 1
        for t in trits[pos : pos + 5]:
            x += t * p
            p *= 3
        out.append(x & 0xff)
        pos += 5
    for ntrits, size in [(82, 16), (82, 16), (41, 8), (41, 8), (82, 16)]:
        x = 0
        p = 1
        for t in trits[pos : pos + ntrits]:
            x += t * p
            p *= 3
        out += x.to_bytes(size, "little")
        pos += ntrits
    return bytes(out)


def get_pie_base(d):
    for m in d.maps:
        if 'myfavoriteinstructions' in (m.backing_file or ''):
            return m.start
    return 0x555555554000


# --- Oracolo in Libdebug per F10 / Multiplication Stage ---

def trits_of(n, length):
    out = []
    for _ in range(length):
        out.append(n % 3)
        n //= 3
    if n:
        return None
    return out


def f10_stack_vectors(trits):
    d = debugger(["./myfavoriteinstructions", "A" * 68], aslr=False)
    d.run()
    pie = get_pie_base(d)
    
    bp_start = d.breakpoint(pie + 0x11A0)
    d.cont()
    d.wait()
    trits_data = struct.pack("<348Q", *trits)
    d.memory[d.regs.r12, len(trits_data)] = trits_data
    bp_start.disable()
    
    bp = d.breakpoint(pie + 0x5400)
    d.cont()
    d.wait()
    
    rsp = d.regs.rsp
    a_data = d.memory[rsp + 0x420, 168 * 8]
    b_data = d.memory[rsp + 0x1F80, 168 * 8]
    a = list(struct.unpack("<168Q", a_data))
    b = list(struct.unpack("<168Q", b_data))
    d.kill()
    return a, b


def f10_affine_offsets():
    base = flag_to_trits(b"A" * 68)
    alpha = []
    beta = []
    for i in range(82):
        avals = []
        bvals = []
        for x in range(3):
            tr = base[:]
            tr[20 + i] = x
            tr[102 + i] = x
            a, b = f10_stack_vectors(tr)
            avals.append(a[i])
            bvals.append(b[i])
        alpha.append(avals[0])
        beta.append(bvals[0])
    return alpha, beta


def f10_ok(raw):
    d = debugger(["./myfavoriteinstructions", raw.decode("latin-1")], aslr=False)
    d.run()
    pie = get_pie_base(d)
    bp = d.breakpoint(pie + 0x17CB6)
    d.cont()
    d.wait()
    rsp = d.regs.rsp
    vec = struct.unpack("<168Q", d.memory[rsp + 0x1500, 168 * 8])
    d.kill()
    return vec == TARGET_F10


def solve_prefix_and_f10():
    print("[f10] decoding multiplication stage")
    alpha, beta = f10_affine_offsets()
    base = flag_to_trits(b"bbb{" + b"A" * 64)

    for left, right in (F10_FACTORS, F10_FACTORS[::-1]):
        ad = trits_of(left, 82)
        bd = trits_of(right, 82)
        if ad is None or bd is None:
            continue
        trits = base[:]
        trits[20:102] = [(ad[i] - alpha[i]) % 3 for i in range(82)]
        trits[102:184] = [(bd[i] - beta[i]) % 3 for i in range(82)]
        try:
            raw = trits_to_bytes_prefix(trits)
        except OverflowError:
            continue
        if all(32 <= c < 127 for c in raw[:36]) and f10_ok(raw):
            print(f"[f10] {raw[:36].decode()}")
            return raw[:36]

    raise SystemExit("f10 decode failed")


# --- Oracolo in Libdebug per il terzo Stage ---

ORDER20_OFFSETS = [
    0x1F0, 0x1F8, 0x200, 0x208, 0x170, 0x158, 0x190, 0xD0, 0xD8, 0x198,
    0x1A0, 0x1A8, 0x1B0, 0x1B8, 0x1C0, 0x1C8, 0x1D0, 0x178, 0x180, 0x188
]
ZERO = (0,) * 20


def load_table():
    vals = struct.unpack("<%dQ" % (15 * 41 * 21), BIN_DATA[0x4E590 : 0x4E590 + 15 * 41 * 21 * 8])
    return [[tuple(vals[(j * 41 + i) * 21 : (j * 41 + i) * 21 + 20]) for i in range(41)] for j in range(15)]


def load_targets():
    vals = struct.unpack("<315Q", BIN_DATA[0x67930 : 0x67930 + 315 * 8])
    return [tuple(vals[j * 21 : j * 21 + 20]) for j in range(15)]


class Oracle:
    def __init__(self, prefix):
        raw = prefix.ljust(68, b"A")
        self.d = debugger(["./myfavoriteinstructions", raw.decode("latin-1")], aslr=False)
        self.d.run()
        self.pie = get_pie_base(self.d)
        
        bp_start = self.d.breakpoint(self.pie + 0x1C0A1)
        self.d.cont()
        self.d.wait()
        
        self.rsp = self.d.regs.rsp
        self.snap_path = "/tmp/group_snap_libdebug.json"
        snap = self.d.create_snapshot()
        snap.save(self.snap_path)
        
        self.bp_patch = self.d.breakpoint(self.pie + 0x1CFB9)
        self.bp_stop = self.d.breakpoint(self.pie + 0x1CF90)
        self.bp_patch.disable()
        self.bp_stop.disable()

    def _eval(self, custom, vals, stop):
        self.d.load_snapshot(self.snap_path)
        
        val_data = struct.pack("<41Q", *vals)
        self.d.memory[self.rsp + 0x420, len(val_data)] = val_data
        
        self.bp_patch.enable()
        self.bp_stop.enable()
        
        out = None
        while True:
            self.d.cont()
            self.d.wait()
            rip = self.d.regs.rip
            if rip == self.pie + 0x1CFB9:
                i = self.d.regs.r14
                if i in custom:
                    row = custom[i] + (0,)
                    val_bytes = struct.pack("<21Q", *row)
                    self.d.memory[self.rsp + 0x9C0, len(val_bytes)] = val_bytes
            elif rip == self.pie + 0x1CF90:
                if self.d.regs.r14 == stop:
                    out = tuple(struct.unpack("<Q", self.d.memory[self.rsp + off, 8])[0] for off in ORDER20_OFFSETS)
                    break
            else:
                raise RuntimeError(f"Unexpected RIP {hex(rip)}")
                
        self.bp_patch.disable()
        self.bp_stop.disable()
        return out

    def add(self, a, b):
        vals = [0] * 41
        vals[0] = 1
        vals[1] = 1
        return self._eval({0: a, 1: b}, vals, 2)

    def double(self, a):
        vals = [0] * 41
        vals[0] = 2
        return self._eval({0: a}, vals, 1)


def stage3_affine_maps(prefix):
    fixed = flag_to_trits(prefix.ljust(68, b"A"))
    base = fixed[:]
    maps = []
    for i in range(41):
        vals = []
        for x in range(3):
            tr = base[:]
            tr[184 + i] = x
            
            d = debugger(["./myfavoriteinstructions", "A" * 68], aslr=False)
            d.run()
            pie = get_pie_base(d)
            
            bp_start = d.breakpoint(pie + 0x11A0)
            d.cont()
            d.wait()
            trits_data = struct.pack("<348Q", *tr)
            d.memory[d.regs.r12, len(trits_data)] = trits_data
            bp_start.disable()
            
            bp = d.breakpoint(pie + 0x1C0A1)
            d.cont()
            d.wait()
            val = struct.unpack("<Q", d.memory[d.regs.rsp + 0x420 + 8 * i, 8])[0]
            vals.append(val)
            d.kill()
        maps.append(vals)
        
    invmaps = []
    for vals in maps:
        inv = [0, 0, 0]
        for inp, out in enumerate(vals):
            inv[out] = inp
        invmaps.append(inv)
    return maps, invmaps


def load_or_compute_stage3_logs():
    cache_file = Path("stage3_logs.pkl")
    if cache_file.exists():
        data = pickle.loads(cache_file.read_bytes())
        return data["coeffs"], data["rhs"]
    raise SystemExit("stage3_logs.pkl not found! Computation skipped.")


def solve_stage3_lll(prefix):
    print("[stage3] solving cyclic-group equations with LLL")
    coeffs, rhs = load_or_compute_stage3_logs()
    n, m = 41, 15
    centered_rhs = [(rhs[j] - sum(coeffs[j][i] for i in range(n))) % ORDER3_20 for j in range(m)]

    scale = 1000
    marker = 10
    mat = IntegerMatrix(n + m + 1, n + m + 1)
    for i in range(n):
        mat[i, i] = 1
        for j in range(m):
            mat[i, n + j] = scale * coeffs[j][i]
    for j in range(m):
        mat[n + j, n + j] = scale * ORDER3_20
        mat[n + m, n + j] = -scale * centered_rhs[j]
    mat[n + m, n + m] = marker

    LLL.reduction(mat, delta=0.99)
    mapped = None
    for row in range(mat.nrows):
        vec = [int(mat[row, col]) for col in range(mat.ncols)]
        if abs(vec[-1]) != marker:
            continue
        sign = 1 if vec[-1] == marker else -1
        centered = [sign * vec[i] for i in range(n)]
        if all(v in (-1, 0, 1) for v in centered):
            candidate = [v + 1 for v in centered]
            ok = all((sum(coeffs[j][i] * candidate[i] for i in range(n)) - rhs[j]) % ORDER3_20 == 0 for j in range(m))
            if ok:
                mapped = candidate
                break
    if mapped is None:
        raise SystemExit("stage3 LLL failed")

    # Risolvi automaticamente gli offset con il prefisso dinamico! Niente più stringhe hardcoded.
    _maps, invmaps = stage3_affine_maps(prefix)
    trits = flag_to_trits(prefix + b"A" * (68 - len(prefix)))
    for i, value in enumerate(mapped):
        trits[184 + i] = invmaps[i][value]
    raw = trits_to_bytes_prefix(trits)
    print(f"[stage3] {raw[:44].decode()}")
    return raw[:44]


# --- Snapshot Libdebug per i stage SAT ---
def libdebug_snapshot_at(raw, address):
    d = debugger(["./myfavoriteinstructions", "A" * 68], aslr=False)
    d.run()
    pie = get_pie_base(d)
    
    bp_start = d.breakpoint(pie + 0x11A0)
    d.cont()
    d.wait()
    tr = flag_to_trits(raw.ljust(68, b"A"))
    trits_data = struct.pack("<348Q", *tr)
    d.memory[d.regs.r12, len(trits_data)] = trits_data
    bp_start.disable()
    
    bp = d.breakpoint(pie + address)
    d.cont()
    d.wait()
    
    rsp = d.regs.rsp
    snap = {
        "regs": {
            "rax": d.regs.rax, "rbx": d.regs.rbx, "rcx": d.regs.rcx, "rdx": d.regs.rdx,
            "rsi": d.regs.rsi, "rdi": d.regs.rdi, "rbp": d.regs.rbp, "rsp": d.regs.rsp,
            "r8": d.regs.r8, "r9": d.regs.r9, "r10": d.regs.r10, "r11": d.regs.r11,
            "r12": d.regs.r12, "r13": d.regs.r13, "r14": d.regs.r14, "r15": d.regs.r15,
        },
        "stack_base": rsp - 0x3000,
    }
    snap["stack"] = bytes(d.memory[snap["stack_base"], 0x18000])
    snap["trit_ptr"] = struct.unpack("<Q", d.memory[rsp + 0x358, 8])[0]
    d.kill()
    return snap


def make_symbolic_emu(prefix, symbolic, snap_addr):
    raw = prefix + b"A" * (68 - len(prefix))
    fixed = flag_to_trits(raw)
    snap = libdebug_snapshot_at(raw, snap_addr)
    emu = SatEmu(fixed, symbolic)
    emu.regs.update(snap["regs"])
    for off in range(0, len(snap["stack"]), 8):
        emu.mem[snap["stack_base"] + off] = int.from_bytes(snap["stack"][off : off + 8], "little")
    for i in range(348):
        emu.mem[snap["trit_ptr"] + i * 8] = emu.mem[INPUT + i * 8]
    return emu, snap


# --- SAT Helpers ---
def exactly_one(cnf, lits):
    cnf.add(lits[:])
    for i, a in enumerate(lits):
        for b in lits[i + 1 :]:
            cnf.add([-a, -b])


def add_byte_constraints(emu, trit_start, trit_count, allowed_per_byte):
    carry_max = trit_count
    carries = []
    for _ in range(len(allowed_per_byte) + 1):
        vals = [emu.cnf.new_lit() for _ in range(carry_max + 1)]
        exactly_one(emu.cnf, vals)
        carries.append(vals)

    emu.cnf.add([carries[0][0]])
    emu.cnf.add([carries[-1][0]])

    for byte_index, allowed in enumerate(allowed_per_byte):
        byte_lits = [emu.cnf.new_lit() for _ in allowed]
        exactly_one(emu.cnf, byte_lits)

        lits = []
        weights = []
        for i in range(trit_count):
            coeff = (3**i >> (8 * byte_index)) & 0xFF
            if not coeff:
                continue
            val = emu.inputs[trit_start + i]
            assert val.lits is not None
            for digit in (1, 2):
                lits.append(val.lits[digit])
                weights.append(coeff * digit)

        for carry_value in range(carry_max + 1):
            lits.append(carries[byte_index][carry_value])
            weights.append(carry_value)

        for i, char in enumerate(allowed):
            lits.append(byte_lits[i])
            weights.append(255 - char)
        for carry_value in range(carry_max + 1):
            lits.append(carries[byte_index + 1][carry_value])
            weights.append(256 * (carry_max - carry_value))

        cnf = PBEnc.equals(
            lits=lits,
            weights=weights,
            bound=255 + 256 * carry_max,
            top_id=emu.cnf.next_var - 1,
            encoding=PBEncType.adder,
        )
        emu.cnf.clauses.extend(cnf.clauses)
        emu.cnf.next_var = max(emu.cnf.next_var, cnf.nv + 1)


def solve_cnf(cnf, label):
    for solver_name in ("kissat404",):
        try:
            with Solver(name=solver_name, bootstrap_with=cnf.clauses) as solver:
                print(f"[{label}] solving with {solver_name}")
                started = time.time()
                ok = solver.solve()
                print(f"[{label}] {solver_name}: {ok} in {time.time() - started:.1f}s")
                if ok:
                    return set(solver.get_model())
        except Exception as exc:
            print(f"[{label}] {solver_name} failed: {exc}")
    raise SystemExit(f"{label}: no SAT solution")


def model_to_raw(prefix, emu, model):
    trits = flag_to_trits(prefix + b"A" * (68 - len(prefix)))
    for index, val in emu.inputs.items():
        assert val.lits is not None
        for digit, lit in enumerate(val.lits):
            if lit in model:
                trits[index] = digit
                break
    return trits_to_bytes_prefix(trits)


def solve_stage4_sat(prefix):
    print("[stage4] solving 41-trit SAT block")
    emu, _snap = make_symbolic_emu(prefix, list(range(225, 266)), 0x26400)
    emu.run(0x325BC, start=0x26400)
    emu.cnf.force(emu.qload(emu.regs["rsp"] + 0xF08), 2)
    add_byte_constraints(emu, 225, 41, [BASE62] * 8)
    print(f"[stage4] vars={emu.cnf.next_var - 1} clauses={len(emu.cnf.clauses)}")
    model = solve_cnf(emu.cnf, "stage4")
    raw = model_to_raw(prefix, emu, model)
    print(f"[stage4] {raw[:52].decode()}")
    return raw[:52]


def solve_final_sat(prefix):
    print("[final] solving 82-trit SAT block")
    emu, _snap = make_symbolic_emu(prefix, list(range(266, 348)), 0x325BC)
    emu.run(0x4D881, start=0x325BC)
    emu.cnf.force(emu.regs["rax"], 2)
    add_byte_constraints(emu, 266, 82, [BASE62] * 15 + [b"}"])
    print(f"[final] vars={emu.cnf.next_var - 1} clauses={len(emu.cnf.clauses)}")
    model = solve_cnf(emu.cnf, "final")
    raw = model_to_raw(prefix, emu, model)
    print(f"[final] {raw[:68].decode()}")
    return raw[:68]


def main():
    print("=== myfavoriteinstructions solver ===")
    start_time = time.time()
    
    # Iniziamo con un placeholder generico poiché gli stage si valutano indipendentemente
    flag = solve_prefix_and_f10()
    flag = solve_stage3_lll(flag)
    flag = solve_stage4_sat(flag)
    flag = solve_final_sat(flag)
    
    # Ora abbiamo il suffisso corretto, forza bruta dei primi 4 byte indipendenti!
    print(f"\n[*] FLAG: {flag.decode()}")
    print(f"[*] Risolto in {time.time() - start_time:.2f} secondi")


if __name__ == "__main__":
    mp.set_start_method("fork")
    main()
```
{{< /collapse >}}