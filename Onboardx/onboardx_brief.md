# OnboardX - Technical Brief for Review

**Context:** authorized CTF web challenge. Goal is a `KPMG_CTF{...}` flag. The full
chronological session log is in `ctf.txt` / `share.txt` (already shared); the working
exploit tooling is `onboardx_solve.py` (attached). **This brief is deliberately
non-redundant with the log** - it collects the concrete request/response captures, the
exact code, and the precise open problem, so you have what you need to advise without
re-reading the whole journal.

> You raised four things so far - (1) the Flask backend not exposing the output path,
> (2) that a `200` / `processed` response proves nothing about the exploit, (3) you
> wanted the core file I used, and (4) whether the flag path is actually confirmed.
> Those are addressed directly in **§5, §6, §7, §8** respectively. Short version up front:
> you're right on all four - the read-back is the whole blocker, `processed` only means
> `convert` exited 0, and the flag's path/existence is **unverified** (we have a blind,
> write-only file-read with no oracle).

---

## 1. TL;DR of the blocker

The privilege-escalation chain is fully solved and reproducible: we reach HR-admin and can
drive the one admin action - an ImageMagick 6 "ID card" generator - into reading an
arbitrary server file (CVE-2022-44268, PNG `profile` chunk -> arbitrary file read). **The
problem is exfil.** The generated card is written to
`/app/app/static/uploads/idcard_<sub>_<uuidv4>.png`, the backend returns only
`{"status":"processed","stderr":""}` (no URL, no name), the name is a fresh random UUIDv4
every call, and Flask serves that directory with the stock safe static handler (no autoindex,
`safe_join`, no traversal). So we have a **write-only** file-read primitive whose output sink
is unreachable. We cannot even confirm the read fires (no observable oracle). Everything
funnels to: *how is the generated card (or the read result) meant to come back?*

---

## 2. Target & stack

- Flask + gunicorn (Python). Responses carry `Server: gunicorn`.
- `X-Powered-By: ImageMagick/6` is present on **HTML pages too** (`/admin`, `/directory`,
  `/profile`), not just image responses - so it's a global/`after_request` header, **not**
  proof that each page shells out to IM. The real IM touchpoint is only the ID-card endpoint.
- ImageMagick **6**, invoked as the `convert` CLI (error strings cite
  `error/png.c/MagickPNGErrorHandler` and `error/deprecate.c/ConvertImageCommand` - the IM6
  legacy `convert` command).
- App root on disk is `/app/app/` (nested package); uploads live in
  `/app/app/static/uploads/`, web-served at `/static/uploads/<name>`.
- Base URL is per-instance and rotates; set `B` at the top of `onboardx_solve.py`. Instances
  also **reset periodically** (DB wiped), which deletes your user -> you must re-`arm()`.

---

## 3. Confirmed exploit chain (compact - detail is in the code, §9)

Three real bugs; the hint ("if you can onboard yourself, why do you need an HR/Admin")
maps to the first two.

1. **Mass-assignment / self-approval.** `POST /register` makes a *pending* account (login
   then issues only a Flask `session` cookie `{"pending_user_id":N}`, no JWT).
   `PATCH /api/user/me` (JSON) is mass-assignable - **writable set is exactly
   `{display_name, bio, theme, role, is_approved}`**. Sending
   `{"is_approved":true,"role":"admin"}` persists both. (`avatar_path` and everything else
   are ignored.)
2. **JWT RS256->HS256 algorithm confusion.** The login JWT is RS256,
   header `{"alg":"RS256","kid":"prod-rsa-key-2026","typ":"JWT"}`, and the public key is
   published at `/.well-known/jwks.json`. Login **hardcodes `role:"user"`** into the token
   (DB `role=admin` does *not* carry into the token), so `/admin` (which checks the **token's**
   role claim) 403s on a real login token. Forge: rebuild the RSA pubkey, PEM-encode as
   **SubjectPublicKeyInfo (with the trailing `\n`)**, use that exact PEM text as the HMAC-SHA256
   secret, sign HS256 with `{"role":"admin"}` (keep the `kid`, long `exp`). -> `/admin` = 200.
   *(alg:none, PKCS1/DER encodings, and SPKI-without-trailing-newline all FAIL - only
   SPKI-with-newline works.)*
3. **ImageMagick file read (the payload).** `/admin` exposes one action,
   `POST /admin/idcard/<int:id>`, which runs `convert` over the target user's uploaded avatar.
   Upload a PNG carrying a `tEXt` chunk `keyword="profile", value="<server path>"` ->
   CVE-2022-44268 makes IM read that file into the **output** image's "Raw profile type"
   metadata. See §5-§7 for why that output is unreachable.

**Upload validator** (`POST /profile`, multipart field `avatar`): extension must be in
`{png,jpg,jpeg,gif}`; file must **start with** a PNG/GIF/JPEG magic (prefix check only - a
`PNG-magic + garbage` file is accepted; TIFF/BMP/PDF/PS/WEBP magics rejected). Stored name is
`<sub>_<uuidv4>.<ext>`; original filename/basename is discarded; ext normalized. IM selects
the coder by **magic**, so coder-confusion is confined to png/gif/jpeg (MVG/MSL/SVG - i.e.
ImageTragick CVE-2016-3714 - appears unreachable; not fully disproven, see §8 open Qs).

---

## 4. The ID-card endpoint - exact behaviour (captured live)

`GET /admin/idcard/<id>` -> **405**, `Allow: POST, OPTIONS`. Only POST exists.

**Success** (valid image avatar):
```
POST /admin/idcard/47   Cookie: token=<forged HS256 admin>
-> 200  Content-Type: application/json  (35 bytes)
   {"status":"processed","stderr":""}
   (headers: Server: gunicorn, X-Powered-By: ImageMagick/6 - no Location/X-* name leak)
```

**Error** (PNG-magic + garbage avatar -> 0 images read):
```
-> 200
{"status":"error","stderr":
 "convert: AGE[5F]: bad header (invalid type) `/app/app/static/uploads/13_b106...821.png'
    @ error/png.c/MagickPNGErrorHandler/1493.\n
  convert: no images defined `/app/app/static/uploads/idcard_13_8a3c...3e9.png'
    @ error/deprecate.c/ConvertImageCommand/3371.\n"}
```

Two things leak **only in the error path**: the input avatar path (which we already know),
and the output `idcard_<sub>_<uuidv4>.png` name. The `AGE[5F]` is IM echoing 4 bytes of **our
own** input at the chunk-type offset (`...GARB|AGE_...`, `[5F]` = `_`).

Output name is a textbook UUIDv4 (13th hex nibble `4`, 17th in `{8,9,a,b}`): e.g.
`4775d4b5dd2642358f1791f4a293bc79`, `01956265dbb3428dada291d87e688834`,
`a60af26c154f4dc282ab7a2280166da0` - different every request, so **os.urandom-backed, not
predictable**, and (being uuid4, not a `random`-module draw) **not MT-state recoverable**.

---

## 5. The read-back problem (you flagged: "Flask isn't letting out the URL/path")

Confirmed, from every angle:

- The `/admin` page's own JS (`genIDCard`) does `fetch('/admin/idcard/<id>',{method:'POST'})`
  then `if (d.preview_url) { show <img src=preview_url> }`. **The server never includes
  `preview_url`.** We tried: query (`?preview=1`, `?format=png`), JSON bodies
  (`{"preview":true}`, `{"format":"preview"}`, `{"return_url":true}`), headers
  (`Accept: application/json`, `X-Requested-With`), real PNG/JPEG/GIF photos vs synthetic,
  forged HS256 token vs real RS256 login token. **Always the same 35-byte body.** This was
  also **reproduced in a real browser** (DevTools Network) with a valid admin token - same
  result, no image renders.
- No name anywhere else: not in response headers, not in a cookie, not added to
  `/api/user/me` after a gen, not in `/settings/export` (`{"status":"queued"}`).
- The file **is** written on success, but the name is random uuid4 and there is **no
  directory listing** (`/static/uploads/` -> 404) and **no path traversal** (Flask default
  static = `safe_join`; `../`, `%2e%2e`, `....//`, double-encoding all 404 on both
  `/static/uploads/<x>` and `/static/<x>`).
- The success-path name is **not** derived from anything we know - tested
  `idcard_<sub>_<avataruuid>`, `idcard_<avataruuid>`, md5/sha1 of avatar_path/basename, etc.
  (all 404). On error the name leaks but **no file is written** - we fetched a freshly
  error-leaked `idcard_50_651e...94.png` **live -> 404**. So: *you can have the name, or the
  file, never both.*

**Open framing for you:** is `preview_url` (a) simply stripped in this build (a regression -
frontend contract and backend diverged), or (b) is there a retrieval route/condition we
haven't recognized? The `convert` write clearly succeeds; the Flask layer just never returns
a handle to it.

---

## 6. What "200 / processed" actually means (you flagged this - agreed)

- **HTTP 200 is returned for both success and failure.** The success/failure signal is the
  JSON `status` field: `processed` (convert exit 0) vs `error` (convert exit != 0, with
  `stderr` populated).
- `"processed"` with empty `stderr` only means **`convert` ran and didn't complain**. It does
  **not** confirm CVE-2022-44268 read anything. We have **zero positive confirmation** the file
  read fires (see §7).

---

## 7. Is the read even working? (unverified - important)

We have **no oracle**. A differential sweep of the `profile` target produced *identical*
responses for every case:

```
profile = /etc/passwd | /etc/hostname | /etc/shadow | /flag | /flag.txt | /app/flag.txt
        | /app/app/flag.txt | /root/flag.txt | /proc/self/environ | /proc/1/environ
        | /proc/self/cmdline | /nonexistent_xyz | /          (a directory)
-> ALL: 200, {"status":"processed","stderr":""}, ~1.0s each
```

No stderr difference, no status difference, no timing difference between an existing file, a
non-existent path, `/dev`/`/proc` specials, `/etc/shadow` (unreadable), or a directory. So we
can't confirm the read happened, can't tell which paths exist, and can't tell what UID the
`convert` worker runs as. CVE-2022-44268's result is **write-only to the unreadable card** -
there is no reflected side effect anywhere we can see.

---

## 8. Flag location - unverified (you asked "are you sure it's `/root/flag.txt`?")

**We are not sure.** Every path in §7 is a *guess*; none is confirmed (no oracle to confirm
with). Two concrete reasons to doubt the obvious guesses:

- The `convert`/gunicorn worker is almost certainly **non-root** (typical for these images),
  so `/root/flag.txt` (mode-700 `/root`) would be **unreadable** even if the read primitive
  works - making it an unlikely intended target. More plausible: `/flag`, `/app/flag.txt`,
  `/app/app/flag.txt`, or world-readable.
- **It may not be a file at all.** The sibling challenge in this set ("Locks of Confusion")
  writes its flag from a **`$FLAG` environment variable** (`entrypoint.sh`), not a static
  file. If OnboardX does the same, the read target would be **`/proc/self/environ`** (the
  gunicorn worker's env) rather than `/flag*`. Worth prioritizing that target if/when we have
  a working read-back.

So before chasing a path, the live question is the §5 read-back channel; once that exists, we
sweep `{/flag, /app/flag.txt, /app/app/flag.txt, /proc/self/environ}` and hex-decode the
"Raw profile type" chunk from the returned card.

---

## 9. Core code (highlights; full file = `onboardx_solve.py`)

The attached solver is self-contained (`pip install cryptography`; Pillow optional). Jump to:

- **`forge(sub, role, username)`** + the module-level JWKS->SECRET block (the alg-confusion).
  The critical detail is the secret:
  ```python
  SECRET = rsa.RSAPublicNumbers(e, n).public_key().public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo)   # SPKI, INCLUDES trailing '\n'
  # token = HMAC_SHA256(SECRET, b64(header)+'.'+b64(payload)), header keeps kid=prod-rsa-key-2026
  ```
- **`arm()`** - the full chain in one shot: register -> login (no-redirect) capture `session`
  cookie -> decode `pending_user_id` -> `PATCH /api/user/me {is_approved,role:admin}` via the
  **session cookie** -> `forge()` the HS256 admin token for that `sub`.
- **`make_cve_png(target_path)`** - the CVE-2022-44268 payload:
  ```python
  ptext = png_chunk(b"tEXt", b"profile\x00" + target_path.encode())   # keyword 'profile'
  return sig + IHDR + ptext + IDAT + IEND
  ```
- **`extract_raw_profile(png)`** - parses `tEXt/zTXt/iTXt`, finds the "Raw profile type"
  block, and hex-decodes it (this is what we'd run on a *retrieved* card).
- **`IMG_ROUTES` / `FLAG_PATHS`** - the route-probe and candidate-path lists; `main()`
  arms, uploads a `/etc/passwd` proof avatar, and hunts a reprocessed-image route. It finds
  none (see §5).

Scratchpad probes (throwaway, but the interesting ones, in case you want to reproduce a
specific negative): `ob_preview.py` (preview trigger variants), `ob_leakname.py` (output-path
leak + uuid analysis), `ob_diff.py` (the §7 profile differential), `ob_fetchleak.py` (fetch an
error-leaked path -> 404, + partial-write attempts), `ob_derive.py` (success-name derivation
attempts), `ob_inject.py` (username/display_name shell & `@file` injection - all null),
`ob_sqli.py` (SQLi + JWT `kid` injection - all null).

---

## 10. Everything ruled out (de-duped; method in parens)

- **No `preview_url`** under any method/query/body/header/image/token variant (also
  browser-confirmed). JS guard `if (d.preview_url)` never fires.
- **No traversal / no listing** on `/static/uploads/<x>` or `/static/<x>` (Flask `safe_join`;
  encoded + `....//` variants all 404). `/static/<name>` (no `uploads/`) in the `/directory`
  template is just a **broken link** (404), not a second IM route. `/static/uploads/<name>`
  serves the **raw avatar verbatim** (NOT reprocessed - confirmed by byte-identical size +
  our own `profile` chunk present, no `root:`).
- **No SQLi** (login auth-bypass/union/`SLEEP`/`pg_sleep` -> no delay, no error, no session;
  PATCH stores values literally - parameterized/SQLAlchemy).
- **No JWT `kid` injection** (`kid=/dev/null` empty-key, `/proc/*`, `../` traversal,
  `/etc/hostname` -> all 401; server doesn't load the verify key from a `kid` path).
- **No injection via name fields** - `username` (set at register) and `display_name` with
  `$(cat /flag)`, backticks, `;`/`|`, `@/etc/passwd`, `caption:@`, `label:@`, `%[pixel...]` ->
  all `processed`, empty stderr (names are rendered **safely** onto the card; not in a shell,
  not `@`-expanded).
- **No `/profile` URL-avatar** (upload-only `<input type=file>`; no server-side fetch -> no
  SSRF/LFI there).
- **No alternate admin surface** - `/api` returns the same 617-byte doc to user and admin
  ("Admin endpoints... Discover them through the UI"), and the only UI admin action is the
  idcard POST. `/api/v1`, `/api/admin*`, `/api/docs`, `/openapi.json`, etc. -> 404. The
  "legacy PHP admin" comment on every page + `robots.txt` (`/legacy-admin/`, `/internal/`)
  are 404 rabbit holes (Alice-in-Wonderland theme).
- **No flag on any page/cookie/header**, and seeded users (IDOR via forged `sub`:
  1 `alice.hr`/Alice Chen/People Ops, 2 `bob.dev`/Bob Martins/Backend Engineer,
  3 `carol.sales`/Carol Diaz/Sales) carry nothing encoded; `sub` 0 and > existing -> 401.

---

## 11. Open questions for you

1. **Read-back channel.** Given IM6 `convert` writes to a uuid4-named file in a static dir
   with no listing and the handler returns no URL - is there an IM6 primitive that leaks file
   **content to stderr** (the one reflected field), rather than to the output image? Our read
   of IM6 says raster coders don't; is there one we're missing (a profile/`-write`/delegate
   path reachable from a PNG/GIF/JPEG-magic input)?
2. **preview_url.** Does the missing `preview_url` read to you like an intended alternate
   solve, or a build regression where we should flag the instance? Is there a condition that
   makes an IM6 card pipeline emit a retrievable handle that we haven't hit?
3. **MVG/MSL.** Any way to reach the MVG/MSL/SVG coders (ImageTragick) when the validator
   enforces a PNG/GIF/JPEG **magic prefix** and IM picks the coder by magic? (We believe no;
   want a second opinion.)
4. **Flag target.** File vs env var (`/proc/self/environ`) - any way to decide *before* we
   have a working read-back, or is the read-back strictly prerequisite?

**Repro quickstart:** set `B` in `onboardx_solve.py` to the current instance URL ->
`python3 onboardx_solve.py` (arms the chain, uploads a `/etc/passwd` proof avatar, probes for
a readable reprocessed-image route). Then iterate from `arm()` / `make_cve_png()` /
`extract_raw_profile()`.

---

## 12. Your two latest notes

**(a) "Probably that's the only issue - give me the Flask source if provided."**
Agreed that §5 (read-back) is *the* issue. On the source: **we don't have it.** This has been
fully **black-box** - nothing of the challenge's own Flask code (`app.py`, templates,
Dockerfile, `entrypoint.sh`) was provided to us, and the app runs with `DEBUG` off (malformed
`PATCH`/huge-int `idcard` -> generic 500, **no Werkzeug traceback**, so no source leaks that
way either). To be unambiguous: the **attached `onboardx_solve.py` is our *attacker* tooling,
not the challenge source** - don't mistake it for the backend. The challenge's Flask source /
image is the single highest-value artifact; if it can be obtained, it immediately settles two
things at once: (i) whether `preview_url`/retrieval is a real route or a dropped build
contract (§5), and (ii) the exact flag target (§8). We can request it from the challenge
owner; short of that, the source is not currently available to attach.

**(b) "If there's no issue in the source code, your location of flag.txt might be incorrect."**
Exactly the right fork, and it's the §7/§8 point: **the flag path is unverified** - we have a
blind, write-only read with *no* file-existence oracle (every target in §7 returns byte- and
timing-identical). So if the source shows the read-back works as intended, then our failure is
**target selection**, not mechanism. In that case, priority order for the read target:
1. **`/proc/self/environ`** - if the flag is a `$FLAG` **env var** (the sibling "Locks"
   challenge does exactly this via `entrypoint.sh`), this is where it is, and `/flag*` would
   simply not exist.
2. **`/flag`, `/app/flag.txt`, `/app/app/flag.txt`** - world-readable file candidates.
3. **De-prioritize `/root/flag.txt`** - the gunicorn/`convert` worker is near-certainly
   non-root, so a mode-700 `/root` target would be unreadable even with a perfect read-back
   (i.e. "incorrect location" in two senses: wrong path *and/or* wrong privilege assumption).

Net: the two live unknowns are **(1) is the read-back a route or a regression** (source
answers this instantly) and, if it's a regression we work around, **(2) which of the above is
the real flag target** (we sweep them the moment any read-back exists).

---

## 13. Re-deploy + "confirm the flag location first" (update)

The instance was **redeployed** (same URL). Result: **identical build.** Chain re-arms
(fresh DB, `sub` back to low numbers); `gen` still returns only
`{"status":"processed","stderr":""}` - **no `preview_url`** - so the missing read-back is the
*shipped* behavior, not a one-off bad deploy.

On "confirm the location of `flag.txt` first": **we tried, and black-box it is not possible.**
There is no oracle. We pointed the CVE `profile=` target at a wide spread and got **byte- and
timing-identical `processed` for every single one**:

- huge/special: `/dev/zero`, `/dev/urandom`, `/dev/mem`, `/proc/kcore`,
  `/proc/self/pagemap`, `/proc/self/maps`, `/sys/kernel/debug`
- real large files: `/usr/bin/python3`, `/usr/lib/x86_64-linux-gnu/libc.so.6`, `/bin/bash`,
  `/usr/bin/convert`, `/var/log/dpkg.log`, `/usr/lib/locale/locale-archive`
- exist vs not: `/etc/passwd`, `/etc/hostname` vs `/nonexistent_aaa`, `/also/not/here`

All -> `status=processed`, empty `stderr`, ~1.0s. No error, no delay, no stderr difference for
*anything* - existing, missing, giant, special, or unreadable (`/etc/shadow` too, from §7).

**Implication (please sanity-check):** with zero observable difference we cannot (a) locate
the flag, nor (b) even confirm CVE-2022-44268's read *fires* on this build - "read fires but
output is unreachable" and "read never fires (patched IM6 / `-strip`'d pipeline)" are
**indistinguishable** from outside. Either way, confirming the flag path requires **the Flask
source** (pins both the read-back mechanism and the exact flag target) or some output channel
we haven't found. So the dependency order your note implies is inverted here: we can't confirm
the location *before* a channel exists - getting the source is the step that unblocks both.

---

## 14. MAJOR UPDATE - the ImageMagick file-read does NOT fire (so it's a diversion)

Your "preview_url could be a diversion" instinct turned out bigger than expected: the **whole
ImageMagick CVE-2022-44268 path appears non-functional on this build**, which means every
earlier session (and this brief up to §13) was chasing a read primitive that was never
actually confirmed to work.

**Timing proof** (staged a large blob as one user's avatar, then CVE-`profile=`'d it from an
admin user; 3 reps each, median):

```
baseline (valid PNG, no profile chunk) : 1.19s
CVE profile = /etc/hostname (tiny)     : 1.14s
CVE profile = 20 MB file               : 1.54s
CVE profile = /nonexistent/path        : 1.49s
```

Reading a **20 MB** file is statistically indistinguishable from reading a **nonexistent**
path (both ~1.5s, within noise of baseline). If the vulnerable code were opening the file,
reading 20 MB off disk + hex-encoding it (-> ~40 MB) + writing it into the output PNG would add
**seconds**, not ~0. (Also tested: no write-stage warning for a huge embedded profile; the
only warnings we can raise cite the *input* during read - `iCCP: too short`,
`bKGD: invalid`, JPEG `Premature end of file` - never a write/output path.)

**Conclusion:** the `profile` tEXt filename-read is not triggered here - IM6 patched for
CVE-2022-44268, or the `convert` pipeline never hits that code path (e.g. a `-strip`/thumbnail
command that doesn't carry profiles). Either way, **the ID-card generator does not give
arbitrary file read**, and `preview_url`/the unreadable card are a rabbit hole (fits the
Wonderland theme).

*Confirmed across encodings:* re-ran the 20 MB-vs-nonexistent timing for `tEXt`, `zTXt`,
`iTXt`, the `Raw profile type` keyword, and `profile:icc` - **none scale with file size**
(all deltas within +/-0.5 s noise). If it were merely `-strip`, the 20 MB would still be read
into memory during parse and cost disk time; it doesn't, so the filename->read path is gone
(patched), not just stripped. Triple-confirmed dead: (1) flat existence differential (§7),
(2) 20 MB single-encoding timing, (3) 5-encoding timing.

**Re-hunt after the reframe (all null):** `/directory` as admin shows only avatar'd users (no
hidden/flag user, no per-user detail route); idcard for seeded users 1-3 -> `404 {"error":"no
avatar on file"}`, forged non-existent sub -> `403 {"error":"forbidden"}`; an HR/onboarding
admin endpoint sweep (`/admin/*`, `/hr/*`, `/onboarding/*`, `/api/admin/*` x ~35 nouns x
GET/POST) returned only the known `/dashboard`. Real login token for a mass-assigned admin
still carries `role:"user"` (so the HS256 forge stays mandatory) and exposes no flag.
Net: black-box, there is **no reachable flag-disclosure vector** - which is why the Flask
source is the unblocker (it pins the real `convert` invocation + the flag location at once).

**Where that leaves the real flag path.** The two *genuine* bugs are mass-assignment and the
JWT RS256->HS256 confusion - but on their own they only land us on the HR queue (`/admin`),
whose one action (idcard) is the diverted path. So either (a) there's an admin-gated data
endpoint we haven't found, or (b) the intended read primitive is something other than
CVE-2022-44268 on that same idcard endpoint (a different IM/`convert` injection that *does*
fire), or (c) a bug we haven't identified. We're actively re-hunting (b)/(a); the single
fastest resolver remains the Flask **source** - it would immediately say what `convert` is
actually invoked with (confirming the diversion), and where the flag lives. Re-stating the ask
from §12: that source is the highest-value artifact.

---

## 15. Fresh full re-sweep (latest redeploy) - the output filename is the whole problem

Re-ran everything black-box on the current deploy and pinned the mechanics exactly:

- **The `convert` invocation is now known** (leaked verbatim via a forced error stderr - upload
  an avatar that IM accepts but then fails on, e.g. a 30000x30000 IHDR / a corrupt 2-frame GIF):
  ```
  convert /app/app/static/uploads/<id>_<uuid>.png  <opts>  /app/app/static/uploads/idcard_<id>_<uuid4>.png
  ```
  App root is `/app/app/`. The output **is** web-served at
  `/static/uploads/idcard_<id>_<uuid4>.png`. The `convert` is a plain input->output (display_name
  and bio do **not** appear in the argv when probed, so no annotate/label arg-injection surface).

- **The blocker, stated precisely:** `<uuid4>` is a fresh random `uuid.uuid4().hex` per call
  (verified over 10 samples: version-4 nibble present, no shared prefix, no time/counter pattern
  -> unguessable). It is **hidden on success** - a successful gen returns only
  `{"status":"processed","stderr":""}`, with **no `preview_url`** on *any* input we tried
  (minimal PNG, real PIL PNG up to 512^2, CVE payload, clean image, generating *another* user's
  card, forged-JWT admin vs session admin). On **error** the output name *does* appear in stderr,
  but then the file is never written (`no images defined`). So: success => file exists but name
  unknown; error => name known but no file. We could not break that deadlock black-box.

- **CVE-2022-44268 never observably fires** (stderr stays empty for profile targets
  `/etc/passwd`, `/etc/shadow`, `/root`, `/etc`, `|id`, ...; and the timing tests from §14 hold).

- **Also newly ruled out:** `/static` alias/path traversal (openresty front, every variant 404);
  `avatar_path` is **not** mass-assignable (whitelist = `is_approved, role, bio, display_name,
  theme`), so no traversal/arg/shell injection into the convert input; `/admin/idcard/<id>` is an
  int converter (no path injection); Flask **debug is off** (generic 265 B 500 pages, no
  traceback); no directory listing; `sub`-claim impersonation (ids 1-11) exposes no flag field;
  `robots.txt` (`/legacy-admin/`, `/internal/`) and `main.js` (staging key, `/api/auth/public-key`)
  are self-described dead ends; `/settings/export` only queues.

### Two hypotheses worth a second pair of eyes (and the exact thing to check in source)
1. **Recover the output filename on success.** If the handler ever returns `preview_url` or logs
   the output path, or if `uuid4` is actually seeded/derived from something we can observe, the
   CVE (or any render) becomes readable. *In source, look at the idcard view: is `preview_url`
   built unconditionally and then dropped by the frontend only, or never set? Is the output name
   `uuid.uuid4()` or something reproducible (hash of avatar, timestamp, row id)?*
2. **A different, firing read/write primitive on the same endpoint.** Since 44268 is patched here,
   the intended primitive may be another `convert` behavior that writes somewhere *predictable*
   (e.g. if any part of the output path is derived from attacker-controlled data). *In source,
   confirm the full `convert` arg list and how the output path is constructed.*

The single highest-value artifact remains the **Flask source** - it resolves both hypotheses at
once (how the output name is built, whether `preview_url` is recoverable, and the flag location).
