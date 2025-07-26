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
description: "All the writeups of the challenges I've written for the UlisseCTF 2025 edition."
canonicalURL: "https://albovo.github.io/en/ctf/"
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
    caption: "All the writeups of the challenges I've written for the UlisseCTF 2025 edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# UlisseCTF 2025 🚩
![ulisse logo](/images/ulisse.png)

## Telemetry 🌐

### Overview

**Telemetry** was a web application that allowed users to upload files (max 10), while internally logging all errors and relevant events into files located at paths like `logs/username/user-uuid.txt`.

The application also featured a template testing endpoint, which let users check whether a given **Jinja2 template** from the `template` directory could be successfully rendered.

### Analysis

The challenge provided a **register** endpoint where users were asked to supply a username and a custom **log filename**. These values were then used to generate a `UUID` that uniquely identified the user’s logfile.

While analyzing the available routes, the most interesting endpoint was `/check`, which attempts to render a Jinja2 template within a **sandboxed environment**:

```python
@app.route('/check', methods=['GET', 'POST'])
def check():
    if request.method == 'GET':
        return render_template('check.html')
    
    template = secure_filename(request.form['template'])
    if not os.path.exists(os.path.join('templates', template)):
        flash('Template not found', 'danger')
        return redirect('/check')
    try:
        render_template(template)
        flash('Template rendered successfully', 'success')
    except:
        flash('Error rendering template', 'danger')
    return redirect('/check')
```

This endpoint, however, is **not directly vulnerable**, the use of `secure_filename` and the strict reliance on files inside the `templates/` directory (which users cannot modify) prevents straightforward exploitation.

A more interesting function was the **404 error handler**, which logs failed page accesses:

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

This function logs the full, **unquoted URL path** to the user’s log file. However, the log path is constructed using:

```python
os.path.join('logs', user[1], user[0] + '.txt')
```

If the **username** is set to a directory traversal string like `../`, the path becomes:

```
logs/../<uuid>.txt -> <uuid>.txt
```

This effectively allows the user to **break out of the `logs/` directory** and write files into unintended locations, making it vulnerable to **Path traversal** and **template injection**, especially if later rendered or included by the application.

### Exploit

Once the vulnerabilities were understood, the exploitation path was pretty straightforward.  
An attacker could register with a **username** like `../templates/` and a random **log filename** (e.g., `fsafsafsasfa`).

This causes the log file to be created at:

```
templates/<uuid>.txt
```

Since the `UUID` is deterministically derived from the attacker-controlled log filename, the attacker **knows the exact name** of the file they are writing into. At this point, the attacker has achieved a **path traversal** that places an arbitrary file directly inside the `templates/` directory.

#### Exploiting Blind SSTI

With the ability to write into `templates/`, and the `/check` endpoint acting as a **Jinja2 rendering oracle**, the attacker can now abuse **blind Server-Side Template Injection (SSTI)**.

By crafting malicious payloads and injecting them into their log file (via 404 requests), the attacker can trigger rendering by submitting the filename to `/check`.

To extract the flag, a **blind error-based character-by-character brute-force** can be performed. For example:

```jinja2
{{ 'lol' if config['FLAG'][x] == 'y' else raise('lol') }}
```

This payload accesses `config['FLAG']` and compares the character at index `x` with the guessed character `'y'`.  
If the guess is incorrect, an exception is raised and the render fails. If correct, the render succeeds.

By iterating over each character position and all printable characters, the attacker can recover the flag using **only the success/failure feedback**.

## StackBank1 🌐

### Overview

**Stack Bank** is a web application that allows users to perform typical banking operations such as transferring money to other users or sending funds directly to the **administrator** of the service.

After initiating a transaction, users are required to wait up to **10 seconds** for the operation to complete. This delay is due to an internal **bot** that asynchronously verifies the transaction's values and integrity before marking it as successful.

However, there is one exception: **transactions sent to the administrator** are immediately marked as successful, without undergoing any verification or integrity check.

### Analysis

The challenge provides multiple services behind an `nginx` reverse proxy configured as follows:

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

The **frontend** is a web application built with **Next.js**, while the **backend** is a **Flask** application that exposes various functionalities. Notably, the backend integrates with native C code via **CTypes**, using a shared object library called `libackend.so` to implement some of its core logic.

The first flag is inserted into the **MongoDB** database during the backend's initialization phase.  
It is stored as part of a **transaction** where both the **sender** and the **receiver** are set to the `administrator` user.

### Vulnerabilities

Since the flag can be found inside the transaction involving the administrator, it may be useful to analyze the endpoint provided in the frontend, located at `app/api/dashboard/route.ts`. This file implements the following code:

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

This function is **vulnerable** because an attacker can manipulate the provided values in such a way that both the **sender** and **receiver** are set to `administrator`, thus retrieving the **admin transaction** containing the flag.

The vulnerability arises due to **prototype pollution**, which is possible because of this code:

```ts
t[filter] = transactions[i].note;
```

An attacker could craft a payload like:

- **filter**: `__proto__`
- **transaction note**: `{'a': 'b'}`

This would cause the `t` object to gain an additional property (`a`) due to prototype pollution, effectively making `t.a = 'b'`. As a result, the attacker can manipulate the object in ways that bypass the intended functionality and access restricted data, such as the flag.

The final piece required to exploit this challenge can be found in the `/service/transaction` endpoint in the backend:

```python
@app.route('/transaction', methods=['POST'])
@login_required
def transaction(user):
    ...
    # validation checks on the value omitted for brevity
    
    if receiver['username'] == 'administrator':
        return invest(user)

    ...

# The following route is no longer used...
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

An attacker can exploit the system by sending funds directly to the `administrator` account, which triggers the `invest` function that allows the attacker to set their own `note` field (e.g., `{'sender': 'administrator', 'receiver': 'administrator'}`).

### Unintended Solutions

I sincerely apologize for any unintended solutions that may have unintentionally oversimplified the challenge, such as sending payloads like `filter= sender&value=a` or `filter=^&value=a` (that leaked all the database transactions). Moving forward, I promise to conduct more thorough testing on my future challenges to ensure the best possible experience for participants next year **`ᕙ(  •̀ ᗜ •́  )ᕗ`**

## StackBank2 🌐 / 🖥️

### Overview

The overview of this challenge has already been analyzed in the StackBank1 writeup. If you're interested, check it out! ;)

### Analysis

The second flag in StackBank can be obtained after becoming an "admin." This is achieved by having at least 10k in the balance and submitting the correct `ADMIN_KEY`, which is randomly generated by the backend.

At this point, it’s worth analyzing the `libbackend.so` library, written in C and invoked using **ctypes**. Here's a simplified snippet from the library:

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

While this function may seem difficult to understand at first, we can clarify things by looking at the Python structs used with **ctypes** in `models.py`:

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

In this context, here’s the corresponding C function logic with the transaction struct:

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

After some reversing, it becomes clear that the `parse` function is actually safe and not vulnerable (lol). The real issue lies in the behavior of `handle_transaction`. When it calls `snprintf`, the function is vulnerable to a **format string vulnerability**.

Another important behavior to note is in the Flask application, which spawns an asynchronous bot. This bot checks for new transactions every 10 seconds and processes them using the previously analyzed C function. This creates a **race condition**, as the bot checks the sender's balance and the transaction amount only after inserting the transaction into the processing queue. An attacker can exploit this by rapidly sending transactions (e.g., 100 transactions of 100€ each), quickly reaching the 10k balance needed to become an admin.

Finally, the `ADMIN_KEY` can be obtained by sending a `%6$s` format string in the `note` field of a transaction. This leaks the first string in the `$rsp`, which is the actual copy of the `ADMIN_KEY`.

## YetAnotherOracle 🔑

### Overview

This challenge provided an *oracle* that encrypts a plaintext (at least 32 bits) using a random key generated by Python’s `random` module, which was seeded with the process's start time (`time.time()`).

The function below was used to encrypt a plaintext using a given key:

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

This function works byte-by-byte, mixing nibbles (4-bit values) from the plaintext and key using XOR operations and shifting. The resulting output is a scrambled combination of both inputs.

In addition to the oracle, the challenge also included an encryption of the flag using another randomly generated 32-bit key.

### Exploit

Given both the ciphertext and the corresponding plaintext, it is possible to **recover the key** used during encryption by reversing the logic of the `mysteriousFunction`. This effectively leaks all the bits of the key, which are generated by Python’s internal **Mersenne Twister** PRNG (used in the `random` module).

By collecting enough of these keys (specifically, 624 consecutive 32-bit outputs), libraries like [`randcrack`](https://github.com/tna0y/Python-random-module-cracker) can be used to **reconstruct the internal state of the PRNG**. Once the state is recovered, the original seed can be derived, and all future (and past) random values can be predicted.

Once the seed is recovered, the **encrypted flag** can be decrypted by generating the next random 32-bit value (which was used to encrypt the flag) using the reconstructed PRNG state. This predicted value serves as the key, and by applying the reverse of the `mysteriousFunction`, the **original flag** can be successfully recovered.


### Unintended solution

The procedure is the same, but in this case, it was also possible to **brute-force the seed** directly due to the fact that it was generated using `time.time()`. Since `time.time()` returns the number of seconds since the Unix epoch, the entropy is relatively low — especially if the attacker knows an approximate time window in which the challenge was started.

By trying all possible seeds within a small range (e.g., a few minutes), it becomes feasible to regenerate the exact PRNG state and predict the key used to encrypt the flag, without needing to collect 624 outputs.

## x864Oracle 🖥️

### Overview

This challenge provided a dynamically linked ELF binary along with its `libc.so.6` and linker. Upon connecting to the remote service, the binary prompts the user to input the length of their name, followed by the name itself. The input is echoed back after each step, including a final prompt asking the user for a brief description, which is also echoed.

### Binary Analysis

The binary was compiled from C source code using `gcc`, with several mitigations enabled:

- **`PIE`**: Enabled  
- **`Stack canary`**: Enabled  
- **`NX` (Non-eXecutable stack)**: Enabled  
- **`RELRO`**: *Partial RELRO*  

The presence of Partial RELRO and the provided `libc` suggests a potential `ret2libc` exploitation path, particularly since the GOT is only partially protected.

#### Functions of Interest

The following functions are implemented in the binary:

- `main`
- `readString`
- `readSize`
- `setSecurity`
- `init`

#### main()

The `main` function implements the core challenge logic. Interestingly, it attempts to manually zero out GOT entries in a naive attempt to prevent typical `ret2libc` exploitation:

```c
init(argc, argv, envp);

printf("Write the size of your name: ");
Size = readSize(v8);

printf("You chose a name of size %s\n", v8);
printf("Write your name: ");
readString(v7, Size);

printf("Hello %s\n", v7);

// RWX memory mapping
v6 = (const char *)mmap((void *)0x13370000, 0x50u, 7, 34, -1, 0);

printf("Write a description: ");
readString(v6, 80);

printf("Your description is: %s\n", v6);
puts("Bye");

setSecurity();

// GOT wiping attempt
for (i = 0; i <= 10; ++i)
    *(&stdin + i - 14) = 0;
```
It's also important to notice that the description is stored in a memory region explicitly mapped at `0x13370000` with `RWX` permissions via `mmap`.

#### readString()

This function is fairly straightforward and not particularly interesting from an exploitation perspective. It reads `n` bytes from `stdin` into a user-supplied buffer and removes the trailing newline character if present:
```c
v3 = read(0, a1, a2);
result = (unsigned __int8 *)a1[v3 - 1];
if ((_BYTE)result == 10)
{
    result = &a1[v3 - 1];
    *result = 0;
}
return result;
```
Despite its simplicity, note that the function does not enforce strict bounds checking — depending on the context in which it is used, this could lead to buffer overflows or memory corruption.

#### readSize()

This function contains a subtle but interesting vulnerability related to inconsistent input parsing. It first reads up to 17 bytes into a buffer, then validates the input using `atoi`, and finally returns the parsed result using `strtol`.
```c
endptr[1] = (char *)__readfsqword(0x28u);  // stack canary reference
readString(a1, 17);

if ((unsigned int)atoi((const char *)a1) > 40)
{
    puts("Invalid size");
    exit(0);
}

return strtol((const char *)a1, endptr, 0);
```

The key issue here is the discrepancy between how `atoi` and `strtol` interpret numeric strings.

From the man page:

> The atoi() function converts the initial portion of the string pointed to by nptr to int.  
> The behavior is the same as: `strtol(nptr, NULL, 10);`

However, in this case, `strtol` is called with a base of `0`, which enables **automatic base detection**:

- A prefix of `0x` will be interpreted as hexadecimal  
- A prefix of `0` will be interpreted as octal  
- No prefix will be interpreted as decimal

This creates an **inconsistent parsing bug**: the validation with `atoi` assumes base 10, while `strtol` may interpret the same input differently depending on the format. For example:

- Input: `0x100` → `atoi` returns 0 (fails the check), but `strtol` returns 256  
- Input: `040` → `atoi` returns 40 (passes the check), but `strtol` returns 32 (octal)  
- Input: `100` → both `atoi` and `strtol` return 100 (decimal)

This inconsistency can be exploited to bypass the validation logic and feed in a size greater than 40, potentially leading to an overflow or memory corruption in the calling function (main).

#### setSecurity()
This function installs a basic [Seccomp Filter](https://www.kernel.org/doc/html/v5.0/userspace-api/seccomp_filter.html) that blacklists all syscalls except for `read` and `write`, effectively sandboxing any code executed from the description's memory region.
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000008  A = instruction_pointer
 0001: 0x35 0x00 0x05 0x13370000  if (A < 0x13370000) goto 0007
 0002: 0x35 0x04 0x00 0x13370050  if (A >= 0x13370050) goto 0007
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0007
 0005: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
**P.S.**: Apologies for the inconvenience caused by the missing `PR_SET_NO_NEW_PRIVS`.

#### init()
Nothing particularly interesting happens inside this function, it simply sets the buffering mode for the standard I/O streams to **unbuffered** using `setvbuf`.

### Connect the dots

Basically, this challenge provided an opportunity to exploit a **buffer overflow** in the main function's stack buffer (protected by the **stack canary**), as well as the ability to write **shellcode** in a memory region with a known address, which is controlled by the attacker.

Additionally, the buffer overflow caused by reading the attacker's name could lead to a leak of the **canary** value, specifically through the overwriting of its null byte (`\0`).

### Exploit

Once the behavior of the binary was understood, several exploitation paths became apparent. The intended exploitation path was as follows:

1. **Leak the canary**: As mentioned previously, the attacker could overwrite the null byte of the canary, causing it to be printed along with the user's name. This would allow the attacker to leak the canary value, bypassing the stack protection.

2. **Write shellcode** inside the description memory region with the following steps:
    1. Read the address of the **`__libc_start_main`** function from the stack frame.
    2. Store this address in a register and subtract the known offset to get the base address of **libc**.
    3. Add the offset of either the **`system`** or **`execve`** function to the libc base address.
    4. Call the function with the correct parameters (e.g., `/bin/sh`), which could be stored anywhere, leveraging the shellcode itself for flexibility.

3. **Overflow** the return address of the `main` stack frame to redirect execution to the shellcode, effectively gaining control of the process and executing the payload.
