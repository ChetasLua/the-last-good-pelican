# The Last Good Pelican

A sixty-second animated short about a pelican who has passed a test and the little bird who hasn't. When the launch bell rings again, he has to decide whether to keep riding.

**The entire film is [pelican.html](pelican.html).** Download that file, open it in a desktop browser, and click the hand-lettered title card to start picture and sound. It runs offline: no install, build step, local server, or account. GitHub's file viewer shows the source; use its download button to play the film locally.

## At the projector

| Control | Action |
| --- | --- |
| Click or Space | Play, pause, or resume |
| Left / Right arrow | Step one 60 fps frame backward / forward |
| M | Mute or unmute |
| Home | Return to the title card |
| N | Show the exposure sheet, colour script, model sheet, technical audit, and verbatim blind reviews while paused or on the title card |

Append **?t=23.5** or **?frame=1410** to the local file URL to inspect the same moment without starting playback. The console entry point is **window.render(seconds)**.

## What is in the file?

The HTML contains the original JavaScript, inline styles, and plain-text production notes. Canvas 2D draws the coastline, characters, bicycles, and lettering. Poses are exposed 12 times a second; the 16:9 camera and finished projection run at 60 fps. Web Audio synthesizes the bell, score, sea, and bicycle Foley from oscillators, filtered procedural noise, and envelopes. There are no libraries, external fonts, image or audio files, videos, or encoded media.

To repeat the source audit with Python 3.8 or newer:

    python3 tools/audit.py

The audit checks the film's markup, executable source, resource-loading policy, and common binary/media signatures. The film itself does not need Python. The original offline browser and screening results are available in the projection notes.

## License

[MIT](LICENSE).
