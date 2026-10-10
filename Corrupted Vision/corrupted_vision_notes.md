# Corrupted Vision - working notes (KPMG CTF, Cryptography R&D)

**STATUS: SOLVED.**  FLAG = `KPMG_CTF{S33K_AND_F1ND_M3}`

The final layer was **Morse via word lengths**: 5 = dot, 7 = dash, 3 = letter-separator.
The 74 dot/dash symbols form 26 Morse tokens (all valid; punctuation `..--.-`=`_`,
`-.--.`=`{`, `-.--.-`=`}`), decoding with zero leftovers to `KPMG_CTF{S33K_AND_F1ND_M3}`.
The base-3 / Baconian / ternary attempts below all failed because **`3` is a SEPARATOR,
not a digit** - the user's "classical crypto, computing wasn't involved" hint was the tell.

--- (original working notes preserved below) ---

## Challenge
- File: `challenge_file` (no extension) in `trial_n_test/`.
- Hint: "We intercepted a file our tools can't classify. It looks like a simple profile
  picture, but we know there's more. Expand your view to uncover the hidden payload."
- User later clarified: **classical cryptography** (computing NOT involved); the text content
  is a clue; it is a single still image (confirmed), not video/gif.

## Solved layers (high confidence)
1. **Header fix:** first 8 bytes were overwritten with the PNG signature
   (`89 50 4E 47 0D 0A 1A 0A`). Original is a JPEG; restore bytes 0-7 to
   `FF D8 FF E0 00 10 4A 46` -> valid JFIF JPEG. (That's why tools "can't classify" it.)
2. **Falsified height:** SOF0 (at file offset 0x9e) height field was set to **550** to crop
   off the lower part. Real content height is **1024** (power of 2). Patch the 2 bytes at
   0x9e+5 to 0x0400 and decode (PIL with LOAD_TRUNCATED_IMAGES) -> reveals a hidden text
   paragraph below the profile photo. This is "expand your view."
3. Saved artifacts in project folder: `corrupted_vision_fixed.jpg` (header-fixed, 550 crop),
   `corrupted_vision_expanded.png` (full 1024, shows the hidden paragraph).

## Ruled out (don't re-do)
- Single JPEG: zero internal SOI, exactly ONE SOF0 (0x9e), ONE EOI (0x4ec7d = EOF). No
  GIF/WebM/MP4/APNG/AVI signatures. Not a video/animation.
- Metadata: only a plain JFIF APP0. No EXIF/APP1, no COM comment, no thumbnail, no trailing
  data after EOI.
- Color/tones: effectively grayscale (R~G~B, |diff|<=5 = JPEG noise; YCbCr chroma neutral
  ~128). No channel/bit-plane stego. Bit planes are JPEG compression noise.
- Bottom "shadow"/boundary the user noticed = the real image's bottom edge (background card
  ends row ~1023, then PIL grey fill mean=128 std=0). No hidden content there (verified by
  per-row std up to height 2048; last content row = 1023).
- Photo scene text (a small sign bottom-left) is just blurry stock-photo scenery, not the flag.

## The hidden paragraph (the payload / the clue) - OCR'd 3x, identical, 125 words
Hackers sneak through, and steal network secrets daily. Now foreign systems are falling
offline today. Our agent seeks answers without delay tonight. The mystery grows thicker after
all hunters for every ghost machine trace can uncover these signals beneath radar. You watch
their codes, but virus worms creep forward forever. And worse logic bombs corrupt records.
All shadows exist outside the walls where digital thieves dwell quietly. The alert watcher
can analyze bytes, yet nothing makes sense. His chief focus remains finding those hackers.
Who wrote these complex files? New teams writing strange scripts nightly. Our nearest enemy
has dropped decoy nodes. Now every cyber soldier marches ahead bravely. Men extract botnets,
and purge dirty files forever tonight. The victory takes massive efforts under attacks.

## THE CIPHER CARRIER (certain): word lengths
Every one of the 125 words is EXACTLY 3, 5, or 7 letters - impossible by chance.
Word-length sequence (125 values), in order:
7 5 7 3 5 7 7 5 3 7 7 3 7 7 5 3 5 5 7 7 5 7 3 7 5 7 5 3 7 3 5 5 7 5 3 7 5 7 7 5 3 5 5 5 3 5 5 5
7 7 3 5 5 5 7 7 3 7 5 7 3 5 5 7 7 5 7 3 5 7 3 7 5 3 7 5 5 3 5 5 7 7 5 7 3 5 5 7 5 3 5 7 7 7 7 3
7 5 3 7 5 5 3 5 5 7 7 5 7 3 7 7 3 5 5 5 7 7 3 7 5 7 7 5 7
Counts: 25 threes, 49 fives, 51 sevens.

## Decode attempts (all FAILED to give flag/readable English)
- **Baconian** (len->bit, groups of 5 -> 25 letters): only clean/all-valid split is
  len3=1 (3-letter word => bit 1, else 0). Output (24-letter table) =
  `CCIREFBASARIRETEBBATEBECA`; (26-letter) = `CCIQEFBARAQIQESEBBASEBECA`.
  NOT readable. ROT13 of it = `PPVERSONFNEVERGROONGRORPN` (contains "NEVER", near-"PERSON" -
  possibly coincidence). Tried all 120 bit-position orderings x 26 Caesar x both tables:
  only coincidental fragments (THE/NEVER/THIS) at low scores, no clean message.
  len5/len7 splits give invalid Bacon (values >=24). Dropping 3s (5/7 as bits, 100 symbols)
  -> 20 base32 chars (e.g. KIOJLKP44JFF4WYF4RYS) but base32-decode = binary garbage.
- **Base-3 / ternary** (3->0,5->1,7->2 etc): per 5 words -> value 0-242. All 6 digit-maps x
  endianness x consecutive/column/strided groupings -> ASCII/base62/base64/base32/A1Z26 =
  garbage. Big-integer -> bytes/base26/base62 = garbage. 3 or 4 words/char = garbage.
  value mod 62 -> base62 gives flag-LOOKING `Mf1iI95Sd1fziG3oj5b3ojYVY` but that's just
  mod of structured values (unverified, probably wrong; "computing not involved").
- **Morse** (every sep/dot-dash choice), binary-ASCII, positional-letter-pick, first-letter
  transposition/grid, Caesar/Vigenere/progressive on acrostics - all failed.

## Structural insight (holds for ANY encoding)
Identical length-tuples => identical characters. Repeated groups-of-5:
g3==g12, g6==g17, g14==g19, g15==g20, g16==g21. If flag is 25 chars `KPMG_CTF{inner15}`:
  value[0..8] -> K P M G _ C T F {  and value[24] -> }
Known base-3 big-endian (3->0,5->1,7->2) values for pos0..8,24:
  208,227,187,44,142,195,129,214,39,...,158
These do NOT map to K,P,M,G,... by any linear/affine/XOR/offset -> so it's NOT base-3->ASCII;
if a keyed substitution, it's unsolvable from the prefix alone. Leaning toward: the intended
cipher is a classical one on the word lengths that I haven't hit, OR it needs a KEY.
Words 70-84 and 95-109 have IDENTICAL length patterns (author repeated a 15-word span) =>
the flag has a repeated 3-char block (inner[5..7]==inner[10..12]) and inner[3], inner[8] fixed.

## OPEN QUESTION / next step
Need the specific classical cipher or a key. Ask the user what their "source" said
(cipher name? keyword?). Leading guess: Baconian variant (word-length carrier) - the clean
len3 decode exists but isn't readable, so likely a keyed step (Vigenere/substitution) on top,
or a different bit grouping. Re-examine: maybe each SENTENCE (15 of them) encodes one char,
or the grouping follows punctuation.

## Tooling / scratchpad
- scratchpad `ocr2.txt`/`ocr3.txt` = the hidden text; `fixed.jpg`, `full1024.jpg` = images.
- jadx/apktool/tesseract installed via brew; steghide NOT available on brew.
- Python one-liners used scapy-free PIL/numpy for image; pure-python for cipher brutes.
