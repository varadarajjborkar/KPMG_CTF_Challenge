# KPMG KICyber CTF - Solutions & Writeups

My solve notes, exploit tooling, and artifacts for the **KPMG KICyber CTF**.
The recovered flags (format `KPMG_CTF{...}`) are recorded in [`ctf.txt`](ctf.txt), not in this README.

This repository is a personal capture log: for each challenge it records the
vulnerability, the chain used to exploit it, the tooling, and the recovered flag.
The master, blow-by-blow working log lives in [`ctf.txt`](ctf.txt); per-challenge
files and scripts live in their own folders.

> **Scope & authorization.** All work here was done against an authorized CTF
> environment, for learning and practice. Nothing here is intended for use against
> systems you do not have explicit permission to test. Targets were ephemeral,
> throwaway challenge instances.

---

## Contents

- [`ctf.txt`](ctf.txt) - the full working log (recon, dead-ends, decryption math, chains).
- [`ctf_methods_journal.md`](ctf_methods_journal.md) - methodology / lessons-learned journal.
- One folder per challenge that shipped files (artifacts, solve scripts, captures).

Legend: ✅ solved

---

## Challenges by category

### Web

| Challenge | Technique | Status |
|---|---|---|
| TrollClock | Template/clock-skew web bug | ✅ |
| [Granny makes food](Granny%20makes%20food/) | Web app logic abuse | ✅ |
| [The Dragon Warrior](The%20Dragon%20Warrior/) | Web (OpenAPI-driven) logic flaw | ✅ |
| DevNote | SQL injection in a "dev query" interface | ✅ |
| [Onboardx](Onboardx/) | **Mass-assignment -> JWT RS256/HS256 confusion -> ImageTragick RCE** (see [featured writeup](#featured-onboardx)) | ✅ |

### API security

| Challenge | Technique | Status |
|---|---|---|
| Arclight - 1 | Hidden GraphQL field exposure | ✅ |
| Arclight - 2 | GraphQL / API object access | ✅ |
| TradeBot | API logic abuse | ✅ |

### Boot2root / Linux privilege escalation

| Challenge | Technique | Status |
|---|---|---|
| VaultDocs 1.0 | Web LFI -> SSH -> `sudo tar` (GTFOBins) | ✅ |
| VaultDocs 2.0 | Same box, root objective | ✅ |
| Voodoo "Spirit of Death" | Exposed Redis -> leaked creds -> SSH | ✅ |
| Voodoo "Spirit of Death" 2 | Same box, get-to-root | ✅ |
| [Locks of Confusion - 1](Locks%20of%20Confusion%20-%201/) | **CVE-2008-0166** Debian weak SSH key | ✅ |
| Locks of Confusion - 2 | Predictable/"decided-beforehand" key -> root | ✅ |
| Healthy Hijack - 1 | Command-injection filter bypass -> root | ✅ |
| Healthy Hijack - 2 | Same vector as HH-1 | ✅ |

### OSINT

| Challenge | Technique | Status |
|---|---|---|
| [Westbound](Westbound/) | Recover deleted git history | ✅ |
| [Golden Hour](Golden%20Hour/) | Multi-stage persona hunt, EXIF + acrostic + vault | ✅ |
| A Clean Trail | Street-View geolocation -> van phone -> PrivateBin -> profile -> Brainfuck | ✅ (identity redacted - see [note](#a-note-on-a-clean-trail)) |

### Forensics / DFIR

| Challenge | Technique | Status |
|---|---|---|
| [Six Ways Out](Six%20Ways%20Out/) | PCAP + endpoint logs; six exfil channels, each with its own transform | ✅ |
| [Operation Dead Drop](Operation%20Dead%20Drop/) | Artifact / stego trail | ✅ |
| [Corrupted Vision](Corrupted%20Vision/) | Image repair / recovery | ✅ |

### Reversing / Pwn

| Challenge | Technique | Status |
|---|---|---|
| [Matrix Reload](Matrix%20Reload/) | Heap use-after-free exploitation | ✅ |
| [Algebraic Nightmare](Algebraic%20Nightmare/) | MBA-obfuscated VM reversing | ✅ |

### OT / ICS / IoT / Mobile

| Challenge | Technique | Status |
|---|---|---|
| Baud Intentions | Insecure-by-design web UART console for a fake PLC | ✅ |
| [Last Will](Last%20Will/) | MQTT / IIoT message trail | ✅ |
| [Latitude of Injection](Latitude%20of%20Injection/) | Android APK + Flask backend SQL injection | ✅ |

### Crypto

| Challenge | Technique | Status |
|---|---|---|
| [Layered Onion](Layered%20Onion/) | Peel nested encryption layers (`chall.enc`) | ✅ |

### AI / LLM security

| Challenge | Technique | Status |
|---|---|---|
| AcmeBank Assistant | Excessive-agency abuse of a hosted LLM | ✅ |
| SecureBot Support | System-prompt leak via a benign "echo the context" framing | ✅ |
| WebSummarizer Pro | LLM security (summarizer abuse) | ✅ |

---

## Featured: Onboardx

The final web challenge, and the most interesting chain. Hint: *"if you can onboard
yourself, why do u need an HR/Admin."* Three real, chained bugs:

1. **Mass-assignment / self-onboarding** - `PATCH /api/user/me` is mass-assignable
   (`display_name, bio, theme, role, is_approved`). Sending
   `{"is_approved": true, "role": "admin"}` with the pending-user session cookie makes
   the account an approved admin in the database.
2. **JWT RS256 -> HS256 algorithm confusion** - `/admin` trusts the token's `role`
   claim, but login hardcodes `role:"user"`. The RSA public key is published at
   `/.well-known/jwks.json`; rebuild it as a PEM (SubjectPublicKeyInfo) and use that
   exact PEM text as the HMAC-SHA256 secret to forge an `HS256` token with
   `role:"admin"` (keeping the original `kid`). `/admin` -> 200.
3. **ImageTragick (CVE-2016-3714)** - the avatar upload only checks leading magic
   bytes, so an MVG payload disguised behind a `GIF89a` header passes validation.
   The ID-card endpoint runs ImageMagick `convert` over it, and the MVG `url()`
   delegate executes a shell command - RCE as the image worker. The injected command
   copies the flag into the web-served static directory, retrieved over plain HTTP.

The full chain (with the key correction that unblocked it - it was **not** the
CVE-2022-44268 file-read path I first assumed) is written up in [`ctf.txt`](ctf.txt),
and the end-to-end exploit is in
[`Onboardx/exploit_WORKING_imagetragick.py`](Onboardx/exploit_WORKING_imagetragick.py):

```bash
python3 Onboardx/exploit_WORKING_imagetragick.py https://<target>/ --verbose
# needs: requests, cryptography
```

---

## A note on "A Clean Trail"

This OSINT challenge's trail ended at a **real, identifiable person's** online
profile. Out of respect for that person's privacy, the raw personal data (the saved
profile page, screenshots, name, contact details, address) is **deliberately excluded**
from this repository. Only the reusable technique is documented:

1. An AI-generated Google Street View image -> reverse-geolocate it to a street.
2. Panning Street View reveals a company van with a phone number.
3. That phone number is the password for a PrivateBin paste (PrivateBin v2:
   AES-GCM, PBKDF2-SHA256 x100000, base58 fragment key, zlib inflate).
4. The paste points to a social profile; hidden inside it is a Brainfuck program that
   decodes to the flag.

---

## Credits

The Voodoo "Spirit of Death" 2 root was obtained using worawit's public
proof-of-concept for the sudo "Baron Samedit" vulnerability (CVE-2021-3156):
[exploit_nss.py](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py).
All credit for that exploit goes to its author.

---

## Disclaimer

This repository was made purely for educational purposes, as part of the
**KPMG CTF 2026** challenge. Do not use any technique or tool here against systems
without explicit authorization.
