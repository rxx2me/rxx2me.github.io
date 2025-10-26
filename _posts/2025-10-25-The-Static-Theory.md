---
layout: post
title: "InfoSec CTF – Ep. 47 - The Static Theory"
date: 2025-10-25 21:32 +0300
categories: [Write-ups, Forensics]
tags: [CTF, InfoSec, Forensics]
toc: true
pin: false
description: |-
  Those Podcasters wanted answers. They got noise instead.
image: /assets/img/categories/forensics.svg
---

# Ep. 47 - The Static Theory Forensics Write-up

> **Category:** Forensics  
> **Prompt:** Those Podcasters wanted answers. They got noise instead.  
> **Artifact:** [⬇️ podcast_clip.mp4](/assets/file/writeup/The-Static-Theory/podcast_clip.mp4?raw=1)  
> **Flag format:** FlagY{...}

---

## Intro

This challenge hides data in **sound, not sight**. By converting the video’s audio to a WAV file and switching to a spectrogram view, text appears as a bright, narrow band around the high frequencies. 
Read it like a banner to recover the flag.

---

## Challenge Description

We’re given a podcast teaser as an MP4. The audio looks like static, but the prompt hints that “noise” contains the answer. 
This screams **spectrogram steganography**—render the frequency content over time and look for shapes or letters embedded in a thin frequency slice.

---

## Steps

1) Extract the audio as mono PCM at 44.1 kHz:

```
    ffmpeg -i "podcast_clip.mp4" -vn -acodec pcm_s16le -ar 44100 -ac 1 "podcast_clip.wav"
```

2) Open the WAV in Audacity:

   - File → Open → `podcast_clip.wav`

3) Switch the track to a Spectrogram view:

   - Click the track name (podcast_clip) → **Spectrograms** → **Spectrogram Settings…**

4) Use these settings :

![](/assets/file/writeup/The-Static-Theory/1.png)


---

## Output:

```
FlagY{5fb89de8314ae7ab21b53d24ea358b1b9}
```

---
