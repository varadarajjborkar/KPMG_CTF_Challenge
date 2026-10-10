#!/usr/bin/env python3
import re, io, json, subprocess, tempfile, os, sys
import urllib.request, ssl
from PIL import Image, ImageOps

B = "https://kicyber-4bfe3faed6a6-locks-of-confusion1-0-0.chals.io"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def req(path, data=None, headers=None):
    r = urllib.request.Request(B+path, data=data, headers=headers or {})
    return urllib.request.urlopen(r, context=ctx, timeout=20).read()

def ocr_tsv(img):
    g = img.convert("L")
    g = g.point(lambda p: 255 if p > 90 else 0)   # white text -> white
    g = ImageOps.invert(g)                          # -> black text on white
    g = g.resize((g.width*2, g.height*2))
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        g.save(f.name); fn = f.name
    try:
        out = subprocess.run(["tesseract", fn, "stdout", "--psm", "11", "tsv"],
                             capture_output=True, text=True).stdout
    finally:
        os.unlink(fn)
    words = []
    for line in out.splitlines()[1:]:
        c = line.split("\t")
        if len(c) >= 12 and c[11].strip():
            left,top,w,h = map(int, c[6:10])
            words.append((c[11].strip().lower(), left//2, top//2, w//2, h//2))
    return words

for attempt in range(80):
    html = req("/verify").decode()
    nonce = re.search(r'nonce = "([0-9a-f]+)"', html).group(1)
    img = Image.open(io.BytesIO(req(f"/verify/image/{nonce}")))
    words = ocr_tsv(img)
    labs = [w[0] for w in words]
    print(f"[{attempt}] nonce={nonce[:8]} words={labs}", flush=True)
    for text, lx, ly, lw, lh in words:
        norm = text.replace(" ", "")
        if "cache-02" in norm or (norm.startswith("cache") and "2" in norm):
            # label center x ; circle sits ~30px ABOVE the label
            cx = lx + lw//2
            cy = max(0, ly - 30)
            body = json.dumps({"nonce": nonce, "x": cx, "y": cy}).encode()
            try:
                resp = req("/verify/check", data=body,
                           headers={"Content-Type":"application/json"}).decode()
            except Exception as e:
                resp = "ERR:"+str(e)
            print(f"  cache-02 label@({lx},{ly}) -> click ({cx},{cy}) resp={resp}", flush=True)
            if '"ok":true' in resp.replace(" ",""):
                print("UNLOCKED", flush=True); sys.exit(0)
print("gave up", flush=True)
