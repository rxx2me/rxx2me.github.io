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

I pressed play and heard… nothing useful—just hiss and a few harsh bursts. Scrubbing the video frames didn’t help either. But the “noise” line in the prompt nagged at me. 
So I stopped *listening* and started *looking* at the sound. The moment I flipped the audio into a spectrogram, a neon ribbon near the upper frequencies turned into letters. 
That’s where the flag .


---

## Challenge Description

We’re given a short podcast teaser as an MP4. At first pass it’s just broadband static—no melody, no clear tones, no obvious Morse. 
But the clip is “drawn” to be seen rather than heard: the author etched text into a thin horizontal band around ~10 kHz so that the letters only show up when you visualize frequency. 

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
