---
layout: post
title: "0xFun CTF – MazeRunna"
date: 2026-02-14 21:30 +0300
categories: [Write-ups, Misc]
tags: [CTF, 0xFun, Misc]      
toc: true                              
pin: false
description: "Sounds simple, right? Just complete the maze... but this isn’t just any ordinary Roblox game. Something feels off."
image: /assets/img/categories/misc.svg
---

# MazeRunna  Misc  Write-up

> **Category:** Misc  
> **Prompt:** `Sounds simple, right? Just complete the maze... but this isn’t just any ordinary Roblox game. Something feels off.`  
> **Artifact:** [⬇️ chall.rbxl](/assets/file/writeup/MazeRunna/chall.rbxl?raw=1)  
> **Flag format:** `0xfun{...}`

---

## Intro

At first glance this looks like a simple Roblox maze game, but the “something feels off” hint suggests the flag isn’t meant to be earned by gameplay. The fastest path is to inspect the Roblox place file and its scripts.

![Challenge panel](/assets/img/writeup/MazeRunna/1.png)

---

## Challenge Description

The challenge links to a Roblox experience, and Roblox experiences are backed by a *place* that can be opened in Roblox Studio. Once you can inspect the place content (Explorer / scripts), you can usually spot hardcoded strings, remote events, or decoy values.

![Roblox game page](/assets/img/writeup/MazeRunna/2.png)

---

## Steps

### 1) Open the experience in Studio
Go to the game page and use **Edit in Studio**:

- https://www.roblox.com/games/75864087736017/MazeRunna

![Roblox game page](/assets/img/writeup/MazeRunna/2.png)

### 2) Find the decoy flag
In Roblox Studio, browse the Explorer and locate the script attached to the flag prompt. The first place version contains a fake flag in the script.

![fake flag in script](/assets/img/writeup/MazeRunna/03.png)

### 3) Pull another place version from Asset Delivery
Since the visible place had a fake flag, the next move is to download another **version** of the same asset using Roblox Asset Delivery:

- https://assetdelivery.roblox.com/v1/asset/?id=75864087736017&version=2

After downloading, you’ll get a file with an unhelpful name.

![Downloaded asset file](/assets/img/writeup/MazeRunna/04.png)

### 4) Rename to a proper Roblox place file
Rename the downloaded file to:

- `chall.rbxl`

![Rename to chall.rbxl](/assets/img/writeup/MazeRunna/5.png)

### 5) Open the new file and re-check the same script path
Open `chall.rbxl` in Roblox Studio, navigate to the same script location, and the real flag is hardcoded there.

![Real flag in version 2](/assets/img/writeup/MazeRunna/6.png)


---

## Output

```
0xfun{f1n1sh_l1n3_0v3r1d3d_w1th_v3rs1i0n}
```
