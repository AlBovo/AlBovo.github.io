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
description: "Some writeups of the nullCon ctf 2023 edition."
canonicalURL: "https://albovo.tech/en/ctf/"
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
math: true
cover:
    image: "https://opengraph.githubassets.com/eccdc445364e4f9dcbece7bb7f178f0756be13a48717c78ec94bf78c35861b9a/AlBovo/CTF-Writeups" # image path/url
    alt: "nullCon CTF 2023" # alt text
    caption: "Some writeups of the nullCon ctf 2023 edition." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# nullCon CTF 2023
![nullcon logo](/images/nullcon.png)

## Web 🌐
### TYpical Boss
In this challenge, it was noticeable that if you accessed the main directory '/' of the challenge's website, the web server would render all the files and directories present on the page (including a file named `database.db`, which was an SQLite database).<br>
As soon as I found this file, I analyzed its contents until I discovered the hashed password of the admin. This hash (in SHA-1) started with a very famous prefix known for its vulnerabilities in PHP, namely `0e`.<br>
In fact, the password would be interpreted by PHP as a number, specifically `0`. The only way I had to bypass the login was to find a SHA-1 hash that also started with `0e`.<br>
This is one useful repository with a lot of these hashes: [Repository](https://github.com/spaze/hashes/tree/master)

### Debugger
Debugger to obtain the flag required your IP to be 127.0.0.0, which is not directly modifiable due to the fact that it used `$_SERVER['REMOTE_ADDR']`, using the following PHP code:
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
The vulnerability at this point lies in the PHP `extract()` function, which [imports variables](https://www.php.net/manual/en/function.extract.php) from an array into the current symbol table. My exploit, more precisely, involved overwriting the `$is_admin` variable with 1 by using the following payload in the GET request URL `/?action=debug&filters[is_admin]=1`<br> This way, I managed to obtain the flag.

### Colorful
This challenge was notably different from the standard web challenges I'm familiar with, as it required knowledge of `AES` vulnerabilities in `ECB` mode.
In this case, the source code contained a particularly suspicious section of code:
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
After looking at this code for a while, I noticed that it was possible to easily encrypt arbitrary blocks that, if crafted correctly, could be mixed together to create a cookie with admin privileges.<br>
At this point, what I did was fill the portion of the cookie that I couldn't modify myself, `_id={id}&admin=0&color=` (where id is a string of 4 * 2 hexadecimal characters), with characters at the end to make its length divisible by 16 (in other words, full blocks). Then, I wrote `admin=1` in the next block. This way, I could shift the last block to the beginning and overwrite the original cookie to obtain the flag.

### IP Filters
This was IPFilters's source code:
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
Apparently, there don't seem to be any specific bypasses to perform. However, by analyzing each PHP function used in the program one by one, I discovered that `inet_pton` is vulnerable because it also accepts IPv4 addresses containing zeros in the last subset. For example: `xxx.xxx.x.00x`.<br>
In this way, I can fit the backend's IP address within the subnet range by passing it the same IP printed by the debug, with trailing zeros.<br>
For instance, `192.168.1.2` => `192.168.1.002`.

### Magic Cars
This challenge required uploading a `GIF` file to the website's backend in order to later be able to view it.
Here's the PHP code for the backend of the website:
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
After a few attempts, I noticed that the backend was checking certain parameters of the file, such as not being too memory-intensive, not having a traversal path in its name, having a `.gif` extension, and having the correct magic numbers for a valid `GIF` file.<br>
I also observed how it used `strtok()` between the file name and a null byte, taking the first part of the string as the actual file name. Following this observation, I was able to write a PHP reverse shell (which is in my [GitHub](https://github.com/AlBovo/CTF-Writeups/tree/main/nullcon%20CTF%202023) repository) named `rev.php%00.gif`. This file name successfully bypassed all the checks, and after the function execution, the actual file name would become `rev.php`.<br>
As soon as I opened the file at the URL `images/rev.php`, I could execute commands in the shell as `www-data`.

### Loginbytepass
Loginbytes provided the opportunity to attempt logging in with the username `admin` or `flag`. In this case, the username was injected into the database query without any sanitization, while for the password it was double-hashed using md5 without being converted into a hexadecimal string.

At this point, looking at this portion of the code:
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
My team and I managed to discover that by finding a hash containing the substring `first_part_of_hash'='second_part_of_hash`, we could bypass the login. This was because PHP transformed both the first and second parts of the hash into `0`, performed the comparison, and resulted in a query like this:
```sql
SELECT * FROM users WHERE username='admin' AND true
```
This allowed us to obtain the flag.

## Binary 💻
### Babypwn
Finally, a bit of pwn. This challenge included an `ELF` file as an attachment. Running `checksec` to examine it yielded the following responses:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```
At this point, it's enough to examine it with IDA, where you have a buffer of `512` characters available and a read function that reads `1024` characters. 
```c
...
   char username[512];

   printf("You shell play a game against @gehaxelt! Win it to get ./flag.txt!\n");
   printf("Your game slot is at: %p\n", username);
   printf("What's your name?\n");
   read(1, username, 1024);
...
```
This allows us to perform a `buffer overflow`. We can fill the buffer with a shellcode at the beginning, followed by multiple 'a' characters to fill the remaining space in the buffer. Once the buffer is filled, we just need to overwrite the `RBP` register and then the `return pointer` with the address of the shellcode. This way, we can execute a shell on the remote machine.

### Heavens Flow
This challenge is very similar to the previous one, but this time we don't have `NX enabled`, so we can't use a shellcode on the stack since it's not executable. However, we can still overwrite the `return pointer` to execute the `heavens_secret` function, which will allow us to read the flag.

## Cryptography 🔒
### Euclidean RSA
This is the first cryptography challenge. The code itself is not very lengthy, but its functionality is quite "uncommon" as it utilizes an external function to generate four integers a, b, c, and d, which have a relationship with n: `a^2 + b^2 = n`, `c^2 + d^2 = n`
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
At this point, by using the `Brahmagupta–Fibonacci` method, you can solve the equation following these steps:

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
In this challenge, the source code goes through many steps to make the code's understanding difficult. However, by looking at how it initializes the array containing the flag, something can be noticed:
```py
def _a(self):
    c = [self.s]
    for i in range(self.t-1):
        a = Decimal(random.randint(self.s+1, self.s*2))
        c.append(a)
    return c
```
In this case, `self.s` represents the flag, and we can observe that it is located at position `0` within the array when it is returned to the caller.<br>
Continuing to analyze the main function, the challenge allows us to read an element at position `x mod n`, where x is the input we provide and must be within the range `1 <= x <= n`. Now, if we want to retrieve the value at position 0, we just need to send the service an input of `x = n`, so that `x mod n = 0`.

### Counting
Finally, this is the last challenge that my team solved. In this challenge, the service was encrypting messages using `RSA` with very minor differences (practically one bit) using the following code:
```py
...
    message = b'So far we had %03d failed attempts to find the token %s' % (counter, token)
    print(pow(bytes_to_long(message), key.e, key.n))
...
```
In this case, you can attempt a [Franklin–Reiter](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin%E2%80%93Reiter_related-message_attack) attack by brute-forcing the changed bit until the decrypted message from the attack contains the token you need to find. Once you've obtained the token, you can send it to the service to get the flag.