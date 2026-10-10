# KPMG KICyber CTF - Solutions & Writeups

My solve notes, exploit tooling, and artifacts for the **KPMG KICyber CTF**.
Every flag is in the format `KPMG_CTF{...}`.

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

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| TrollClock | Template/clock-skew web bug | `KPMG_CTF{H8PT5O8sUTVaw87yk5XCzeR0fu630unpLyr1WsofvfYF}` | ✅ |
| [Granny makes food](Granny%20makes%20food/) | Web app logic abuse | `KPMG_CTF{Wk6uvuhHMb2U3dCL-tDTUOC365OYNNFWhFpfKRzdu8EJ}` | ✅ |
| [The Dragon Warrior](The%20Dragon%20Warrior/) | Web (OpenAPI-driven) logic flaw | `KPMG_CTF{LC0Z9cjBA3yGd_geR1M-dbxKmfj7gNVZMNluLNgrzOF4}` | ✅ |
| DevNote | SQL injection in a "dev query" interface | `KPMG_CTF{IVQtP6rDVaCc4GTZEoQZyLCet9XOYkO66dhXENV6C1dZ}` | ✅ |
| [Onboardx](Onboardx/) | **Mass-assignment -> JWT RS256/HS256 confusion -> ImageTragick RCE** (see [featured writeup](#featured-onboardx)) | `KPMG_CTF{-I3OHbxv4qDtW4EuQvmAiQeU4JL78f9Sim4RGA5alSK9}` | ✅ |

### API security

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| Arclight - 1 | Hidden GraphQL field exposure | `KPMG_CTF{h1dd3n_f13ld_n0t_s0_h1dd3n}` | ✅ |
| Arclight - 2 | GraphQL / API object access | `KPMG_CTF{moWZClsXWrvQiUkeWzwVKy-DUTlfk1QXg5zYZrOmBd15}` | ✅ |
| TradeBot | API logic abuse | `KPMG_CTF{_FjPCdGoJh92C_SUijOMM4wOsOH6P7T8GGtSGaXPwX0L}` | ✅ |

### Boot2root / Linux privilege escalation

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| VaultDocs 1.0 | Web LFI -> SSH -> `sudo tar` (GTFOBins) | `KPMG_CTF{In1T6PPEk2TYp_oWjcf6EkePXu2dxELwnRuPNU-k_gV2}` | ✅ |
| VaultDocs 2.0 | Same box, root objective | `KPMG_CTF{z33IDn2KIal29o20gt_T606CyGMpWNo2m7_p8_dAp9_k}` | ✅ |
| Voodoo "Spirit of Death" | Exposed Redis -> leaked creds -> SSH | `KPMG_CTF{UJgwFKurnt3ui-Ev92ltHlXlNXvZM5RP1CnldWcbTldG}` | ✅ |
| Voodoo "Spirit of Death" 2 | Same box, get-to-root | `KPMG_CTF{V3qscJrUP3_Sqah9j_duAtqn3IflX0fEE7iaFwMgU3dg}` | ✅ |
| [Locks of Confusion - 1](Locks%20of%20Confusion%20-%201/) | **CVE-2008-0166** Debian weak SSH key | `KPMG_CTF{_JcozTookX36JtKATPIQVoRTNKdqytFr0BjDBk2dcsdb}` | ✅ |
| Locks of Confusion - 2 | Predictable/"decided-beforehand" key -> root | `KPMG_CTF{kZoWg1UzoKPYzXyf69Aad7EKaBxs-gUgJaQfWkil7Utj}` | ✅ |
| Healthy Hijack - 1 | Command-injection filter bypass -> root | user `KPMG_CTF{E6vuGz3BkSC7pAo7uCWUIw1nAqNxVkIf_Se8dXDjh6e_}` / root `KPMG_CTF{f44284ea179691a9abf03ea7d0b97ffb}` | ✅ |
| Healthy Hijack - 2 | Same vector as HH-1 | user `KPMG_CTF{b84a3cbaa2c0432b8dcc8ad0a32a007e}` / root `KPMG_CTF{UimO5SDel_BgsnCVjRz_OKZjNWfuSv80pS-ZHLle9rKl}` | ✅ |

### OSINT

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| [Westbound](Westbound/) | Recover deleted git history | `KPMG_CTF{g1t_r3m3mb3r5_wh4t_y0u_d3l3t3}` | ✅ |
| [Golden Hour](Golden%20Hour/) | Multi-stage persona hunt, EXIF + acrostic + vault | `KPMG_CTF{n0va_dr1ft3d_h0m3}` | ✅ |
| A Clean Trail | Street-View geolocation -> van phone -> PrivateBin -> profile -> Brainfuck | `KPMG_CTF{3th31c4L_H$ck3r}` | ✅ (identity redacted - see [note](#a-note-on-a-clean-trail)) |

### Forensics / DFIR

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| [Six Ways Out](Six%20Ways%20Out/) | PCAP + endpoint logs; six exfil channels, each with its own transform | `KPMG_CTF{Q7k2mLpk91Xv2QaHncfuEY92kLxP83LmQa7vQm91XeLm92Qx7P}` | ✅ |
| [Operation Dead Drop](Operation%20Dead%20Drop/) | Artifact / stego trail | `KPMG_CTF{tr4ce_the_intrud3r_follow_the_tr4il}` | ✅ |
| [Corrupted Vision](Corrupted%20Vision/) | Image repair / recovery | `KPMG_CTF{S33K_AND_F1ND_M3}` | ✅ |

### Reversing / Pwn

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| [Matrix Reload](Matrix%20Reload/) | Heap use-after-free exploitation | `KPMG_CTF{Matrix_Escaped}` | ✅ |
| [Algebraic Nightmare](Algebraic%20Nightmare/) | MBA-obfuscated VM reversing | `KPMG_CTF{jQqvGkQ2hCwGodTZSLYoCEW24njncKwz8y67iliFpxTE}` | ✅ |

### OT / ICS / IoT / Mobile

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| Baud Intentions | Insecure-by-design web UART console for a fake PLC | `KPMG_CTF{QiiTo4I0_RvPqN8p_fO1l_xQlK-mW-JpEds_MoBWap7a}` | ✅ |
| [Last Will](Last%20Will/) | MQTT / IIoT message trail | `KPMG_CTF{MvAZjnsrRAcXtU8TnlihJ_X93BTjVf0AMpVevFfC95Q_}` | ✅ |
| [Latitude of Injection](Latitude%20of%20Injection/) | Android APK + Flask backend SQL injection | `KPMG_CTF{1YpkEDDKbqZIZbjTMW_emNbGwWmmdZh1EZrhdnTahVU_}` | ✅ |

### Crypto

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| [Layered Onion](Layered%20Onion/) | Peel nested encryption layers (`chall.enc`) | `KPMG_CTF{p33l_th3_l4y3rs_l1k3_4n_0n10n}` | ✅ |

### AI / LLM security

| Challenge | Technique | Flag | Status |
|---|---|---|---|
| AcmeBank Assistant | Excessive-agency abuse of a hosted LLM | `KPMG_CTF{7HOXQW3WEDBjlIFuUdaaIGgacWMCyDpONnA1pmRwfAq2}` | ✅ |
| SecureBot Support | System-prompt leak via a benign "echo the context" framing | `KPMG_CTF{P7FlbtvaKXBowK_Oy5sVrWOd25-rCZCSHOJnMPDMPXXh}` | ✅ |
| WebSummarizer Pro | LLM security (summarizer abuse) | `KPMG_CTF{ZPaeEp2W-unQsL6LbxluBbPRDP-yZh-XOLFF6ejjpSDc}` | ✅ |

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

## Disclaimer

Educational security research against an authorized CTF. Do not use any technique or
tool here against systems without explicit authorization.
