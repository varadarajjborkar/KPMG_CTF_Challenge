#!/usr/bin/env python3
import re, io, json, subprocess, tempfile, os, sys
import urllib.request, ssl, http.cookiejar
from PIL import Image, ImageOps

B = "https://kicyber-4bfe3faed6a6-locks-of-confusion1-0-0.chals.io"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx))

def req(path, data=None, headers=None):
    r = urllib.request.Request(B+path, data=data, headers=headers or {})
    resp = opener.open(r, timeout=30)
    return resp.read(), dict(resp.getheaders())

def ocr_tsv(img):
    g = img.convert("L").point(lambda p: 255 if p > 90 else 0)
    g = ImageOps.invert(g).resize((img.width*2, img.height*2))
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        g.save(f.name); fn=f.name
    try:
        out = subprocess.run(["tesseract", fn, "stdout", "--psm", "11", "tsv"],
                             capture_output=True, text=True).stdout
    finally: os.unlink(fn)
    words=[]
    for line in out.splitlines()[1:]:
        c=line.split("\t")
        if len(c)>=12 and c[11].strip():
            l,t,w,h=map(int,c[6:10]); words.append((c[11].strip().lower(), l//2,t//2,w//2,h//2))
    return words

def blue_centers(img):
    import numpy as np
    a=np.asarray(img.convert("RGB")).astype(int); R,G,Bc=a[:,:,0],a[:,:,1],a[:,:,2]
    m=(Bc>90)&(Bc<230)&(Bc>R+20)&(Bc>G+10)&(R>30)
    ys,xs=np.where(m); cl=[]
    for x,y in zip(xs.tolist(),ys.tolist()):
        for c in cl:
            if abs(x-c[3])<40 and abs(y-c[4])<40:
                c[0]+=x;c[1]+=y;c[2]+=1;c[3]=c[0]/c[2];c[4]=c[1]/c[2];break
        else: cl.append([x,y,1,x,y])
    return [(int(c[3]),int(c[4])) for c in cl if c[2]>150]

def solve_once():
    html,_=req("/verify"); html=html.decode()
    nonce=re.search(r'nonce = "([0-9a-f]+)"',html).group(1)
    png,_=req(f"/verify/image/{nonce}"); img=Image.open(io.BytesIO(png))
    words=ocr_tsv(img); centers=blue_centers(img)
    print("nodes:",[w[0] for w in words],"circles:",len(centers),flush=True)
    for text,lx,ly,lw,lh in words:
        if "cache-02" in text.replace(" ",""):
            lcx=lx+lw//2
            # pick the blue circle whose center is just ABOVE this label, nearest in x
            cand=[c for c in centers if c[1]<ly and abs(c[0]-lcx)<45]
            if cand:
                cx,cy=min(cand,key=lambda c:abs(c[0]-lcx)+abs(c[1]-(ly-35)))
            else:
                cx,cy=lcx,max(0,ly-38)
            body=json.dumps({"nonce":nonce,"x":cx,"y":cy}).encode()
            r,_=req("/verify/check",data=body,headers={"Content-Type":"application/json"})
            r=r.decode(); print(f"  cache-02 click ({cx},{cy}) -> {r} cookies={[c.name for c in cj]}",flush=True)
            return '"ok":true' in r.replace(" ","")
    return False

ok=False
for i in range(80):
    try:
        if solve_once(): ok=True; break
    except Exception as e: print("err",e,flush=True)
if not ok: print("FAILED to verify"); sys.exit(1)
print("VERIFIED; downloading archives with session cookie...",flush=True)
for name,path in [("provisioning","/archive/provisioning/legacy-03-2007.tar.gz"),
                  ("keyspace","/archive/keyspace/legacy-keys-2007.tar.gz")]:
    data,hdr=req(path)
    open(f"dl/{name}.tar.gz","wb").write(data)
    print(f"{name}: {len(data)} bytes, magic={data[:4].hex()}",flush=True)
