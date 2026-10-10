#!/usr/bin/env python3
import sys, json, z3

P = json.load(open(sys.argv[1]))
N1, N2, L = P["N1"], P["N2"], P["exp_len"]
ops, idxs, exps = P["ops"], P["idxs"], P["exps"]
MASK = (1 << 64) - 1
maxneed = max(idxs)

# 56 symbolic flag bytes
b = [z3.BitVec(f"b{i}", 8) for i in range(L)]
# 7 input words, little-endian packing of 8 bytes each
words = []
for j in range(7):
    w = z3.BitVecVal(0, 64)
    for k in range(8):
        w = w | (z3.ZeroExt(56, b[8*j+k]) << (8*k))
    words.append(w)

val = [None] * (maxneed + 1)
for i in range(maxneed + 1):
    opc, f4, f8, fC = ops[i]
    if opc == 1:     r = z3.BitVecVal(fC & MASK, 64)
    elif opc == 2:   r = words[fC % 7]
    elif opc == 3:   r = val[f8] + val[f4]
    elif opc == 4:   r = val[f4] - val[f8]
    elif opc == 5:   r = val[f4] ^ val[f8]
    elif opc == 6:   r = val[f4] & val[f8]
    elif opc == 7:   r = val[f4] | val[f8]
    elif opc == 8:   r = ~val[f4]
    elif opc == 9:   r = val[f4] << (fC & 63)
    elif opc == 10:  r = z3.LShR(val[f4], (fC & 63))
    elif opc == 11:  r = z3.RotateLeft(val[f4], (fC & 63))
    elif opc == 12:  r = z3.RotateRight(val[f4], (fC & 63))
    elif opc == 13:  r = z3.BitVecVal(fC & MASK, 64) * val[f4]
    elif opc == 14:  r = -val[f4]
    else:            r = z3.BitVecVal(0, 64)
    val[i] = z3.simplify(r)

s = z3.Solver()
for k in range(N2):
    s.add(val[idxs[k]] == z3.BitVecVal(exps[k] & MASK, 64))

USE_FORMAT = ("--fmt" in sys.argv)
if USE_FORMAT:
    pref = b"KPMG_CTF{"
    for i, c in enumerate(pref):
        s.add(b[i] == c)
    s.add(b[L-1] == ord("}"))
    for i in range(len(pref), L-1):
        s.add(b[i] >= 0x20, b[i] <= 0x7e)

print("solving...", "fmt=", USE_FORMAT, "constraints on val idx:", idxs)
r = s.check()
print(r)
if r == z3.sat:
    m = s.model()
    out = bytes((m[b[i]].as_long() if m[b[i]] is not None else 0) for i in range(L))
    print("ascii:", out.decode("latin1"))
    print("hex  :", out.hex())
