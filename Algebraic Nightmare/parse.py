#!/usr/bin/env python3
import sys, struct

path = sys.argv[1]
data = open(path, "rb").read()

# --- minimal ELF64 section-header parse to map vaddr -> file offset ---
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]
secs = []
for i in range(e_shnum):
    off = e_shoff + i*e_shentsize
    name, stype, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
    secs.append((name, addr, offset, size))
# section header string table
shstr_off = secs[e_shstrndx][2]
def secname(n):
    end = data.index(b"\0", shstr_off+n)
    return data[shstr_off+n:end].decode()
rodata = None
for name, addr, offset, size in secs:
    if secname(name) == ".rodata":
        rodata = (addr, offset, size)
assert rodata, "no .rodata"
ro_addr, ro_off, ro_size = rodata
def va2off(va):
    return ro_off + (va - ro_addr)

# --- extract encrypted blob + key ---
BLOB_VA = 0x2040
BLOB_LEN = 0x4462c
KEY_VA = 0x46670
enc = data[va2off(BLOB_VA):va2off(BLOB_VA)+BLOB_LEN]
key = data[va2off(KEY_VA):va2off(KEY_VA)+8]
print("key:", key.hex())

blob = bytearray(BLOB_LEN)
blob[0] = 0x41  # 'A'
for i in range(1, BLOB_LEN):
    blob[i] = enc[i] ^ key[i & 7]
blob = bytes(blob)

print("header:", blob[:8])
N1 = struct.unpack_from("<I", blob, 0x08)[0]
N2 = struct.unpack_from("<I", blob, 0x0c)[0]
exp_len = struct.unpack_from("<I", blob, 0x10)[0]
print(f"N1(ops)={N1}  N2(constraints)={N2}  expected_input_len={exp_len}")

ops_off = 0x18
# each op 20 bytes: opcode(1) @+0, pad, field4(dword)@+4, field8(dword)@+8, fieldC(qword)@+0xc
opcnt = {}
ops = []
for i in range(N1):
    o = ops_off + i*20
    opcode = blob[o]
    f4 = struct.unpack_from("<I", blob, o+4)[0]
    f8 = struct.unpack_from("<I", blob, o+8)[0]
    fC = struct.unpack_from("<Q", blob, o+0xc)[0]
    ops.append((opcode, f4, f8, fC))
    opcnt[opcode] = opcnt.get(opcode, 0) + 1
print("opcode histogram:", dict(sorted(opcnt.items())))

con_off = ops_off + N1*20
idxs = [struct.unpack_from("<I", blob, con_off + 4*k)[0] for k in range(N2)]
exps = [struct.unpack_from("<Q", blob, con_off + N2*4 + 8*k)[0] for k in range(N2)]
print("first 8 constraint (idx -> expected):")
for k in range(min(8, N2)):
    print(f"   val[{idxs[k]}] == {exps[k]:#018x}")
print("sample ops [0:12]:")
for i in range(min(12, N1)):
    print("  ", i, ops[i])

# save parsed structures for the solver
import json
open(sys.argv[2], "w").write(json.dumps({
    "N1": N1, "N2": N2, "exp_len": exp_len,
    "ops": ops, "idxs": idxs, "exps": exps,
}))
print("saved parsed ->", sys.argv[2])
