---
layout: post
title: "BuckeyeCTF – cube cipher"
date: 2025-11-09 21:30 +0300
categories: [Write-ups, crypto]
tags: [CTF, BuckeyeCTF, Crypto]
toc: true
pin: false
description: |-
  The Rubik's Cube is well known as a challenging puzzle with quintillions of possible configurations. Why not make a cipher out of it?
image: /assets/img/categories/crypto.svg
---

![](/assets/file/writeup/cube_cipher/1.png) 
# cube cipher 1

> **Category:** Crypto  
> **Prompt:** The Rubik's Cube is well known as a challenging puzzle with quintillions of possible configurations, why not make a cipher out of it?  
> **Artifact:** [⬇️ cube_cipher.c](/assets/file/writeup/cube_cipher/cube_cipher.c?raw=1) - [⬇️ cube_cipher.md](/assets/file/writeup/cube_cipher/cube_cipher.md?raw=1)  
> **Flag format:** `bctf{...}`

---

## intro

The challenge implements a “cube cipher” — a block cipher inspired by the Rubik’s Cube. It scrambles nibbles of the plaintext according to cube rotations. The encryption algorithm applies a fixed move sequence (stored in `algorithm.txt`) to a cube representation built from the flag’s bytes.

---

## Challenge Description

Each byte of the flag is split into two 4-bit nibbles, mapped to 54 cube stickers (6 faces × 9 stickers). The cube is then scrambled with a predefined algorithm (`execute_algorithm`), and the “front” face bytes are re-extracted to form the ciphertext.  
Since the program allows repeated application of the same algorithm (`option 4`), the cube eventually returns to its starting state after a fixed number of scrambles — its **cycle length**.

---

## Steps

1. **Initial observation**  
   The binary reads `flag.txt`, loads the flag into the cube using `build_cube_from_string()`, applies the scramble, then allows user interaction through a menu.

2. **Interaction logic**
   - Option `3`: outputs cube state as 54 hex digits.
   - Option `4`: re-applies the same algorithm again.

3. **Exploit idea**  
   Applying the same move repeatedly will eventually cycle the cube back to its initial state (like a Rubik’s Cube returning to solved form after enough rotations).  
   By recording the output each time and detecting when the state repeats, we can identify the period and recover the original flag before the first scramble.

4. **Solver**  
   The provided Python script (`solve.py`) automates:
   - Connecting to the challenge server.
   - Dumping the hex string after each re-apply (`option 4` + `option 3`).
   - Detecting when the cube returns to its initial ciphertext.
   - Decoding the previous state as the plaintext.

---

## Solver

```python
#!/usr/bin/env python3
import socket,ssl,re,sys,time
HEX=re.compile(rb"[0-9a-f]{54}",re.I)
def recv_until(s,token=b"Option:",t=20.0):
    s.settimeout(t);b=bytearray()
    while token not in b:
        c=s.recv(4096)
        if not c:break
        b+=c
    return bytes(b)
def sendline(s,x): s.sendall((x+"\n").encode())

ctx=ssl.create_default_context()
host="cube-cipher.challs.pwnoh.io";port=1337
with socket.create_connection((host,port)) as tcp, ctx.wrap_socket(tcp,server_hostname=host) as s:
    recv_until(s)       
    sendline(s,"3")     
    data=recv_until(s)
    m=HEX.search(data)
    if not m: sys.exit("no hex found after option 3")
    c0=m.group(0).decode(); prev=c0
    for i in range(1,3000):
        sendline(s,"4"); recv_until(s)
        sendline(s,"3"); data=recv_until(s)
        m=HEX.search(data)
        if not m: continue
        ci=m.group(0).decode()
        if ci==c0:
            flag=bytes.fromhex(prev).rstrip(b"\\x00")
            try: print(flag.decode())
            except: print(flag)
            break
        prev=ci

```

**Output:**
```
FLAG: bctf{r0t4t10n_0f_th3_cub3}
```

![](/assets/file/writeup/cube_cipher/2.png) 
## cube cipher 2

> **Category:** Crypto  
> **Prompt:** Alright, alright. That last Cube Cipher challenge was a little too easy. Here's another flag encrypted with the Cube Cipher:  
> `754477f367633676ef02347641d63d65529663b6007360f40f0ebe`   
> **Flag format:** `bctf{...}`

---

## 2 - intro

This challenge reuses the same cube-based permutation but gives only the final 54-nibble ciphertext. Rather than invert the unknown move sequence, we express the permutation constraints and known flag format as a CP-SAT model and let a constraint solver recover the plaintext.

---

## 2- Challenge description

- Input: 27 bytes → 54 nibbles → placed on cube stickers → permuted → read out as ciphertext nibbles.  
- We know the sticker layout (which indices are corners/edges/centers) and the usual flag format `bctf{...}`.  
- Model: variables for plaintext nibbles and a permutation mapping plaintext sticker indices → ciphertext sticker indices. Constrain the permutation to respect piece groups (centers↔centers, edges↔edges, corners↔corners with 3-orientation cycles) and force ciphertext equality.

---

## 2- Steps 

1. Convert the given ciphertext hex into 54 nibbles.  
2. Create integer variables (0–15) for each plaintext nibble.  
3. Add format constraints: fix prefix `bctf{`, trailing `}`, and restrict printable alphabet for body bytes.  
4. Add an all-different permutation `perm[0..53]`.  
5. Constrain `perm` by cube piece membership (centers↔centers, edges↔edges, corners↔corners with allowed orientations).  
6. For all i: `cipher_nibble[i] == plaintext_nibble[perm[i]]`.  
7. Solve with OR-Tools CP-SAT, reconstruct bytes from nibble pairs, print candidate flags.

---

## 2- Solver

```python

from ortools.sat.python import cp_model

corners = [0,2,6,8,9,11,15,17,18,20,24,26,27,29,33,35,36,38,42,44,45,47,51,53]
edges   = [1,3,5,7,10,12,14,16,19,21,23,25,28,30,32,34,37,39,41,43,46,48,50,52]
centers = [4,13,22,31,40,49]

cipher_hex = "754477f367633676ef02347641d63d65529663b6007360f40f0ebe"
cipher_bytes = bytes.fromhex(cipher_hex)
cipher_nibbles = [(b >> 4, b & 0xF) for b in cipher_bytes]
cipher_nibbles = [n for pair in cipher_nibbles for n in pair]
print(cipher_nibbles)

assert len(cipher_nibbles) == 54

prefix = "bctf{"
suffix = "}"
allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-é")

model = cp_model.CpModel()

p = [model.NewIntVar(0, 15, f"p[{i}]") for i in range(54)]

for i, ch in enumerate(prefix.encode()):
    model.Add((p[2*i] * 16 + p[2*i+1]) == ch)

suff_idx = 23
model.Add((p[2*suff_idx] * 16 + p[2*suff_idx+1]) == ord('}'))
for i in range(suff_idx + 1, 27):
    model.Add((p[2*i] * 16 + p[2*i+1]) == 0)

allowed_bytes = [ord(c) for c in allowed_chars]
allowed_domain = set(allowed_bytes)

for i in range(5, suff_idx):
    byte = model.NewIntVar(0,255,f"byte[{i}]")
    model.Add(byte == p[2*i]*16 + p[2*i+1])
    model.AddAllowedAssignments([byte], [[x] for x in allowed_domain])

perm = [model.NewIntVar(0,53,f"perm[{i}]") for i in range(54)]
model.AddAllDifferent(perm)

for idx in corners:
    model.AddAllowedAssignments([perm[idx]], [[c] for c in corners])

for idx in edges:
    model.AddAllowedAssignments([perm[idx]], [[e] for e in edges])

for idx in centers:
    model.AddAllowedAssignments([perm[idx]], [[c] for c in centers])

temp = [model.NewIntVar(0, 15, f"temp[{i}]") for i in range(54)]

for i in range(54):
    model.AddElement(perm[i], p, temp[i])
    model.Add(temp[i] == cipher_nibbles[i])

corner_groups = [
    [0, 24, 29], [2, 9, 26], [8, 38, 15], [6, 35, 36],
    [45, 42, 33], [47, 17, 44], [53, 20, 11], [51, 27, 18]
]

edge_groups = [
    [1,25], [5,12], [7,37], [10,23], [14,50], [16,41],
    [19,52], [21,28], [30,48], [34,39], [43,46], [3,32]
]

for group in edge_groups:
    a, b = group
    allowed = []
    for gi, grp in enumerate(edge_groups):
        allowed += [
            [grp[0], grp[1]],
            [grp[1], grp[0]]
        ]
    model.AddAllowedAssignments([perm[a], perm[b]], allowed)

corner_perms = [
    [0,1,2], [2, 0, 1], [1, 2, 0]
]

for group in corner_groups:
    a,b,c = group
    allowed = []
    for gi, grp in enumerate(corner_groups):
        for px in corner_perms:
            allowed += [[grp[px[0]], grp[px[1]], grp[px[2]]]]
    for gi, grp in enumerate(corner_groups):
        for px in corner_perms:
            model.AddAllowedAssignments(
                [perm[a], perm[b], perm[c]],
                allowed
            )

solver = cp_model.CpSolver()
solver.parameters.enumerate_all_solutions = True

class FlagCollector(cp_model.CpSolverSolutionCallback):
    def __init__(self, p_vars):
        cp_model.CpSolverSolutionCallback.__init__(self)
        self.p_vars = p_vars
        self.flags = []
    def on_solution_callback(self):
        flag_bytes = []
        for i in range(27):
            hi = self.Value(self.p_vars[2*i])
            lo = self.Value(self.p_vars[2*i+1])
            flag_bytes.append((hi << 4) | lo)
        flag_str = bytes(flag_bytes)
        print("Found solution:", flag_str)

result = solver.Solve(model, FlagCollector(p))
if result == cp_model.OPTIMAL or result == cp_model.FEASIBLE:
    flag = ""
    for i in range(27):
        b = solver.Value(p[2*i])*16 + solver.Value(p[2*i+1])
        flag += chr(b)
    print("Recovered flag:", flag)
else:
    print("No solution")


```

---
## 2- Output:
```
FLAG: bctf{2_m4nq_Kn_vNofIs3s}

```




