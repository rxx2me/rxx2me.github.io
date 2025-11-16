---
layout: post
title: "Platypwn – Cognitive Reminder Call"
date: 2025-11-16 09:31 +0300
categories: [Write-ups, crypto]
tags: [CTF, Platypwn, Crypto]
toc: true
pin: false
description: |-
  The server seems to be forgetful :(
  Can you help it remember?
image: /assets/img/categories/crypto.svg
---

![](/assets/file/writeup/Cognitive-Reminder-Call/1.png) 

# Cognitive Reminder Call

> **Category:** Crypto  
> **Prompt:** The server seems to be forgetful :(  Can you help it remember? 
> **Artifact:** [⬇️ crypto.cognitivereminder.zip](/assets/file/writeup/Cognitive-Reminder-Call/crypto.cognitivereminder.zip?raw=1)  
> **Flag format:** `PP{...}`

---

## Intro

CRC32 is a checksum, **not** a secure MAC. This challenge abuses CRC32 as an authenticator over `key || nonce || message` and then asks us to “remind” the server of its key via four CRC32 values of unknown 4‑byte chunks. Because CRC32 is linear over GF(2) and supports *combine/uncombine*, we can recover `CRC32(key)` from any authenticated sample and forge a valid tag for our chosen nonce and parts. Those parts also derive the AES key used to encrypt the flag, so we can decrypt the reward locally.

---

## Challenge Description

The service prints a previously-encrypted flag (AES‑CBC), then three “authenticated” log lines each with a `tag` (CRC32) and `nonce`, and finally a list of 4 target CRC32 integers (the “cognitive reminders”). We must supply **four 4‑byte parts** whose CRC32s match the given integers, plus a **fresh nonce** and a **tag** for the concatenation to pass the MAC check.

Key observations:

- The MAC is `tag = CRC32(key || nonce || parts_concat)`.  
- CRC32 has a public **combine** operation: `CRC32(A || B) = combine(CRC32(A), CRC32(B), len(B))`.  
- Hence we can **uncombine** to extract `CRC32(key)` from any authenticated `(nonce, message, tag)` sample printed by the server.  
- Because CRC32 on 4 bytes is a full‑rank linear map, each target CRC32 admits a **unique 4‑byte preimage** we can compute algebraically.

---

## Exploit Strategy

1. Parse any previously printed authenticated line, compute `crc_msg = CRC32(nonce || message)`, then recover `crc_key = uncombine(tag, crc_msg, len(nonce||message))`.
2. For each target integer `Tᵢ`, compute a 4‑byte string `Pᵢ` such that `CRC32(Pᵢ) = Tᵢ` (solve a 32×32 system over GF(2) once and reuse its inverse).
3. Pick a **new nonce** `N`. Build `payload = N || P₁||P₂||P₃||P₄` and forge a valid tag via `tag* = combine(crc_key, CRC32(payload), len(payload))`.
4. Send `P₁..P₄`, `N`, and `tag*`. The service returns an AES‑CBC ciphertext of the real flag where the **key is `SHA256(P₁||P₂||P₃||P₄)`** and IV = first 16 bytes of the ciphertext. Decrypt locally to get `PP{...}`.

---

## Steps

- Given reminders (example from our run):  
  `[1947904649, 2450251710, 1330652206, 255696126]`  
  we solved for 4‑byte parts:
  - `P1 = 517d2bcb`  
  - `P2 = 9c0dd2d9`  
  - `P3 = 8e2c6af5`  
  - `P4 = 54eedab9`  

- Chose fresh nonce: `00112233`  
- Forged tag (CRC32 over `nonce || parts_concat` combined with `CRC32(key)`): `f43f588e`  

**nc session (trimmed):**
```
Part 1 (hex): 517d2bcb
Part 2 (hex): 9c0dd2d9
Part 3 (hex): 8e2c6af5
Part 4 (hex): 54eedab9
nonce (hex): 00112233
tag of the concatenation (hex): f43f588e

Thanks for reminding me! Here is a reward:
efe0e575cae1b7340018de94009445497f4d239fb7c2a91706e1145ea033cfad53bfd7395e3002c9d2199860096bd55ccee70e3c1ed2e59989f7b3bc25a72d93f764d7552174e2d6d688acd776381dd3
```

- Decrypt `reward` with `AES‑CBC` using key `SHA256(P1||P2||P3||P4)` and IV = first 16 bytes.  
- Strip PKCS#7 padding → obtain the flag.

---

## Solver

```python

#!/usr/bin/env python3

import os
import re
import sys
import time
import socket
import hashlib
import zlib

# ---------------- Config ----------------
HOST = sys.argv[1] if len(sys.argv) >= 2 else "10.80.16.59"
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337

# -------------- CRC32 Algebra --------------
# Standard zlib CRC32 (poly 0xEDB88320, init 0xFFFFFFFF, final ^0xFFFFFFFF)
def crc32_int(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def gf2_matrix_times(mat, vec):
    s = 0
    i = 0
    while vec:
        if vec & 1:
            s ^= mat[i]
        vec >>= 1
        i += 1
    return s & 0xFFFFFFFF

def gf2_matrix_square(mat):
    sq = [0]*32
    for n in range(32):
        sq[n] = gf2_matrix_times(mat, mat[n])
    return sq

def gf2_mat_mul(A, B):
    C = [0]*32
    for j in range(32):
        C[j] = gf2_matrix_times(A, B[j])
    return C

def gf2_identity():
    cols = [0]*32
    for i in range(32):
        cols[i] = 1 << i
    return cols

def build_zeros_operator(len2):
    # Build the 32x32 operator that advances CRC by len2 zero bytes (zlib style)
    if len2 <= 0:
        return gf2_identity()
    odd = [0]*32
    odd[0] = 0xEDB88320  # reversed poly
    row = 1
    for n in range(1, 32):
        odd[n] = row
        row <<= 1
    even = gf2_matrix_square(odd)
    odd = gf2_matrix_square(even)
    E = gf2_identity()
    L = len2
    while True:
        even = gf2_matrix_square(odd)
        if (L & 1):
            E = gf2_mat_mul(even, E)
        L >>= 1
        if L == 0:
            break
        odd = gf2_matrix_square(even)
        if (L & 1):
            E = gf2_mat_mul(odd, E)
        L >>= 1
        if L == 0:
            break
    return E

def invert_matrix_gf2(cols):
    # cols: 32 columns (each 32-bit int). Return inverse as columns.
    rows = [0]*32
    for r in range(32):
        bit = 1 << r
        v = 0
        for c in range(32):
            if cols[c] & bit:
                v |= (1 << c)
        rows[r] = v
    inv_rows = [1 << r for r in range(32)]
    for col in range(32):
        piv = None
        for r in range(col, 32):
            if (rows[r] >> col) & 1:
                piv = r; break
        if piv is None:
            raise RuntimeError("non-invertible matrix")
        if piv != col:
            rows[col], rows[piv] = rows[piv], rows[col]
            inv_rows[col], inv_rows[piv] = inv_rows[piv], inv_rows[col]
        for r in range(32):
            if r != col and ((rows[r] >> col) & 1):
                rows[r] ^= rows[col]
                inv_rows[r] ^= inv_rows[col]
    inv_cols = [0]*32
    for c in range(32):
        colbits = 0
        for r in range(32):
            if (inv_rows[r] >> c) & 1:
                colbits |= (1 << r)
        inv_cols[c] = colbits
    return inv_cols

def crc32_combine(crc1, crc2, len2):
    # zlib-style combine: CRC(A||B) from CRC(A), CRC(B), |B|
    E = build_zeros_operator(len2)
    return (gf2_matrix_times(E, crc1) ^ crc2) & 0xFFFFFFFF

def crc32_uncombine(crc_ab, crc_b, len_b):
    # Recover CRC(A) given CRC(A||B), CRC(B), |B|
    E = build_zeros_operator(len_b)
    Einv = invert_matrix_gf2(E)
    x = (crc_ab ^ crc_b) & 0xFFFFFFFF
    return gf2_matrix_times(Einv, x) & 0xFFFFFFFF

# Precompute linear map for 4-byte CRC preimage
_STATE_ZERO = (crc32_int(b'\x00'*4) ^ 0xFFFFFFFF)
_cols = []
for i in range(32):
    basis = (1 << i).to_bytes(4, 'little')
    delta = (crc32_int(basis) ^ 0xFFFFFFFF) ^ _STATE_ZERO
    _cols.append(delta)
_INV_COLS = invert_matrix_gf2(_cols)

def crc32_preimage_4bytes(target_crc: int) -> bytes:
    desired_state = target_crc ^ 0xFFFFFFFF
    delta_target = desired_state ^ _STATE_ZERO
    x_bits = 0
    for i in range(32):
        if (delta_target >> i) & 1:
            x_bits ^= _INV_COLS[i]
    return x_bits.to_bytes(4, 'little')

# -------------- AES-CBC helpers --------------
def aes_cbc_decrypt(key: bytes, ct: bytes) -> bytes:
    iv, data = ct[:16], ct[16:]
    try:
        from Crypto.Cipher import AES  # pycryptodome
        return __import__("Crypto.Cipher.AES", fromlist=["AES"]).AES.new(key, __import__("Crypto.Cipher.AES", fromlist=["AES"]).AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            dec = cipher.decryptor()
            return dec.update(data) + dec.finalize()
        except Exception as e:
            raise SystemExit("[-] Need 'pycryptodome' or 'cryptography' for AES: " + str(e))

def pkcs7_unpad(b: bytes) -> bytes:
    n = b[-1]
    if n == 0 or n > 16 or b[-n:] != bytes([n])*n:
        raise ValueError("Bad PKCS#7")
    return b[:-n]

# -------------- Networking --------------
def sendline(sock: socket.socket, s: str):
    if not s.endswith("\n"):
        s += "\n"
    sock.sendall(s.encode())

def recv_until(sock: socket.socket, pat: bytes, hard_timeout=30.0) -> bytes:
    sock.settimeout(5.0)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < hard_timeout:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            chunk = b""
        if not chunk:
            time.sleep(0.05)
            continue
        buf += chunk
        if pat in buf:
            return buf
    return buf

# -------------- Parsing helpers --------------
NOTE_RE = re.compile(
    r"Note: This message was sent over an authenticated channel\. Its tag is ([0-9a-fA-F]+) with nonce ([0-9a-fA-F]+)\."
)

def parse_banner_for_samples_and_targets(text: str):
    """
    Returns:
      samples: list of dicts { 'nonce': bytes, 'tag': int, 'msg': bytes }
      targets: List[int] of 4 CRC32 targets
      used_nonces: set of nonce bytes already seen
    """
    lines = text.splitlines()
    samples = []
    used_nonces = set()

    for i, line in enumerate(lines):
        m = NOTE_RE.search(line)
        if m:
            tag_hex, nonce_hex = m.group(1), m.group(2)
            tag = int(tag_hex, 16)
            nonce_bytes = bytes.fromhex(nonce_hex)
            used_nonces.add(nonce_bytes)

            # Use the *previous* printed line as the message the note refers to
            msg_line = lines[i-1] if i > 0 else ""
            # Capture it exactly as printed (no trailing newline)
            msg_bytes = msg_line.encode()
            samples.append({"nonce": nonce_bytes, "tag": tag, "msg": msg_bytes})

    # Extract targets from the bracketed list
    m_targets = re.search(r"\[([0-9,\s]+)\]", text)
    if not m_targets:
        raise SystemExit("[-] Could not find the [ ... ] list of CRC32 targets.")
    targets = [int(x.strip()) for x in m_targets.group(1).split(",")]
    if len(targets) != 4:
        raise SystemExit("[-] Expected exactly 4 CRC32 targets, got: %d" % len(targets))
    return samples, targets, used_nonces

def choose_best_sample(samples):
    """
    Prefer the sample whose message line starts with 'Here is the flag:' (most deterministic),
    otherwise just take the first.
    """
    for s in samples:
        if s["msg"].startswith(b"Here is the flag:"):
            return s
    return samples[0]

# -------------- Main solve --------------
def main():
    print(f"[+] Connecting to {HOST}:{PORT} ...")
    s = socket.create_connection((HOST, PORT))

    # Read until the first input prompt: "Part 1 (hex):"
    banner = recv_until(s, b"Part 1 (hex):", hard_timeout=20.0)
    text = banner.decode(errors="ignore")
    # print(text)  # Uncomment for debugging

    samples, targets, used_nonces = parse_banner_for_samples_and_targets(text)
    if not samples:
        raise SystemExit("[-] No authenticated samples found in banner.")

    base = choose_best_sample(samples)
    base_nonce = base["nonce"]
    base_msg = base["msg"]
    base_tag = base["tag"]

    # Compute CRC32(nonce || message) as used by the server
    msg_bytes = base_nonce + base_msg
    crc_msg = crc32_int(msg_bytes)

    # Recover CRC32(key)
    crc_key = crc32_uncombine(base_tag, crc_msg, len(msg_bytes))
    print(f"[+] Recovered CRC32(key) = {crc_key:08x}")

    # Build the 4-byte parts matching the 4 target CRC32 values
    parts = [crc32_preimage_4bytes(t) for t in targets]
    parts_hex = [p.hex() for p in parts]
    print("[+] Parts:", ", ".join(parts_hex))

    # Choose a fresh nonce not seen before
    while True:
        my_nonce = os.urandom(4)
        if my_nonce not in used_nonces:
            break
    nonce_hex = my_nonce.hex()
    print(f"[+] Using fresh nonce = {nonce_hex}")

    # Forge tag for payload = nonce || parts_concat
    payload = my_nonce + b"".join(parts)
    crc_payload = crc32_int(payload)
    forged_tag = crc32_combine(crc_key, crc_payload, len(payload))
    tag_hex = f"{forged_tag:08x}"
    print(f"[+] Forged tag = {tag_hex}")

    # ---- Interact: send values when asked ----
    # We are currently at "Part 1 (hex):"
    sendline(s, parts_hex[0]); time.sleep(0.05)
    recv_until(s, b"Part 2 (hex):", hard_timeout=10.0)

    sendline(s, parts_hex[1]); time.sleep(0.05)
    recv_until(s, b"Part 3 (hex):", hard_timeout=10.0)

    sendline(s, parts_hex[2]); time.sleep(0.05)
    recv_until(s, b"Part 4 (hex):", hard_timeout=10.0)

    sendline(s, parts_hex[3]); time.sleep(0.05)
    recv_until(s, b"nonce (hex):", hard_timeout=10.0)

    sendline(s, nonce_hex); time.sleep(0.05)
    recv_until(s, b"tag of the concatenation", hard_timeout=10.0)

    sendline(s, tag_hex); time.sleep(0.05)

    # Read response; look for reward ciphertext
    out = recv_until(s, b"reward", hard_timeout=10.0)
    text2 = out.decode(errors="ignore")
    # If partial, try a bit more
    if "reward" not in text2:
        more = recv_until(s, b"\n", hard_timeout=3.0).decode(errors="ignore")
        text2 += more

    m = re.search(r"reward:\s*([0-9a-fA-F]+)", text2)
    if not m:
        print(text2)
        raise SystemExit("[-] Could not find reward ciphertext (maybe wrong tag?)")

    ct_hex = m.group(1).lower()
    print(f"[+] Got ciphertext ({len(ct_hex)} hex chars). Decrypting...")

    ct = bytes.fromhex(ct_hex)
    key = hashlib.sha256(b"".join(parts)).digest()
    pt = aes_cbc_decrypt(key, ct)
    try:
        flag = pkcs7_unpad(pt).decode(errors="ignore")
    except Exception:
        flag = pt.decode(errors="ignore")

    print("\nFLAG:", flag.strip())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")


```

## Output:
```text
FLAG: PP{h4sh3s_4r3_m0r3_th4n_ch3cksums::4v_sy8-LDgFv}
```
