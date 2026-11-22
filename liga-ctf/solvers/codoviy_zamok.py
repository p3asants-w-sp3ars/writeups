from pathlib import Path
from struct import unpack_from, pack
from zlib import crc32
from hashlib import sha256
from itertools import product
from math import prod

data = Path(__file__).with_name("locker.exe").read_bytes()
mask = (1 << 64) - 1

def rol(value, n, width):
    value &= (1 << width) - 1
    return ((value << n) | (value >> (width-n))) & ((1 << width)-1)

def evaluate(state, code):
    r = list(state)
    for i in range(12):
        op, d, s, n, k = unpack_from("<4BI", code, i*8)
        if max(d, s) > 4 or not 1 <= n <= 31:
            break
        op ^= (r[0] ^ rol(r[2], 7, 32) ^ (185*i)) & 255
        if op == 0x1b: r[d] ^= rol(k*r[s], n, 32)
        elif op == 0x2e: r[d] ^= k
        elif op == 0x47: r[d] += r[s]
        elif op == 0x69: r[d] *= k
        elif op == 0x83: r[d] += k
        elif op == 0xb4: r[d] ^= r[s]
        elif op == 0xd1: r[d] = rol(r[d], n, 32)
        elif op == 0xf0: r[d], r[s] = r[s], r[d]
        r[d] &= 0xffffffff
    return r

seed = 0x7335356c
code = bytearray(data[0x8514:0x8514+0x46e60])
for i in range(len(code)):
    seed = (1664525*seed + 1013904223) & 0xffffffff
    code[i] ^= seed >> 24

rows = []
for row in range(55):
    state = unpack_from("<5I", data, 0x7cc0+20*row)
    a,b = unpack_from("<2Q", data, 0x810c+16*row)
    options = []
    for col in range(55):
        off = (55*row+col)*96
        r = evaluate(state, code[off:off+96])
        if crc32(pack("<4I", *r[:4])) == r[4]:
            x = rol(r[1]<<32 | r[2], r[3]&63, 64) ^ a
            y = ((r[3]<<32 | r[0])*b) & mask
            options.append((row,col,r,x,y))
    rows.append(options)

groups = []
paired = set()
for i in range(19):
    a,b,k = unpack_from("<BB2xI", data, 0x847c+i*8)
    paired.update((a,b))
    groups.append([(p,q) for p,q in product(rows[a], rows[b]) if p[2][0]^q[2][0] == k])
groups += [[(p,) for p in rows[i]] for i in range(55) if i not in paired]
print("CRC candidates:", [len(o) for o in rows])
print("group sizes:", [len(g) for g in groups])

def half_sums(part):
    sums = [(0,0,0)]
    for i,g in enumerate(part):
        new = []
        for choice,nodes in enumerate(g):
            dx = sum(p[3] for p in nodes)
            dy = sum(p[4] for p in nodes)
            new.extend(((x+dx)&mask, (y+dy)&mask, bits | choice<<i) for x,y,bits in sums)
        sums = new
    return sums

target_x,target_y = unpack_from("<2Q", data, 0x7c60)
left = {(x,y):bits for x,y,bits in half_sums(groups[:18])}
for x,y,right_bits in half_sums(groups[18:]):
    key = ((target_x-x)&mask, (target_y-y)&mask)
    if key not in left:
        continue
    bits = left[key] | right_bits << 18
    nodes = sorted(p for i,g in enumerate(groups) for p in g[(bits>>i)&1])
    indices = bytes(p[1] for p in nodes)
    states = b"".join(pack("<5I", *p[2]) for p in nodes)
    message = b"L55/route/3\0" + indices + states
    digest = sha256(message).digest()
    receipt = bytes(a^b for a,b in zip(data[0x7ca7:0x7cc0],digest))
    alphabet = data[0x7c70:0x7ca7]
    print("Route:", bytes(alphabet[i] for i in indices).decode())
    print("SHA-256:", digest.hex())
    print("Receipt:", receipt)
