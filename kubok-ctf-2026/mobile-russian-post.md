---
title: "Russian Post: Trust Level"
ctf: "Кубок CTF 2026"
author: "citr0n"
date: 2026-10-31
category: mobile
difficulty: medium
points: 337
flag_format: "ctfcup{...}"
---

# Russian Post: Trust Level

## Summary

Вся логика APK вынесена в нативную Go-библиотеку (gomobile, `libgojni.so`).
Экспортированные функции `fF1..fF12` и анти-рут проверки — decoy, собирающие
фальшивый `ctf{cup}` для тех, кто просто прогонит `strings`. Настоящая функция
`mobilelib.VerifySealedParcel` не вызывается из Java и реверсится вручную: это не
AES (хотя импорты AES/HMAC/SHA-256 присутствуют как отвлекающие), а самодельная
CBC-подобная схема на чистом XOR: `P[0]=C[0]⊕key⊕iv`, `P[n]=C[n]⊕key⊕C[n-1]`.

## Solution

### Шаг 1: реверс VerifySealedParcel (Ghidra)

Декомпиляция нативной библиотеки (стандартный Go-анализатор Ghidra падал
StackOverflow'ом на этой функции, разбирал вручную) показала описанную выше
XOR-схему и то, что результат должен расшифровываться в `ctfcup{...}` с
корректным PKCS7-паддингом.

### Шаг 2: получить parcel/key/iv с бэкенда и расшифровать

```python
#!/usr/bin/env python3
"""Russian Post: Trust Level (Кубок CTF 2026) — полное решение от бэкенда до флага."""
import base64
import requests

BASE = "https://nrbwps8fy43iba0i.ctfcup.online"  # из task card инстанса
s = requests.Session()

cfg = s.get(f"{BASE}/api/config").json()
session = cfg["session"]

r1 = s.post(f"{BASE}/api/parcel",
            json={"session": session, "device": {"rooted": False}}).json()
parcel = base64.b64decode(r1["parcel"])   # 32 байта = 2 блока по 16
iv = base64.b64decode(r1["iv"])           # 16 байт
receipt = r1["receipt"]

r2 = s.post(f"{BASE}/api/key",
            json={"session": session, "device": {"rooted": False},
                  "receipt": receipt}).json()
key = base64.b64decode(r2["key"])         # 16 байт

# реверснутая в VerifySealedParcel XOR-схема (НЕ настоящий AES-CBC):
# P[0]      = C[0] XOR key XOR iv
# P[n, n>=1]= C[n] XOR key XOR C[n-1]
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

blocks = [parcel[i:i+16] for i in range(0, len(parcel), 16)]
plain = xor(xor(blocks[0], key), iv)
for n in range(1, len(blocks)):
    plain += xor(xor(blocks[n], key), blocks[n-1])

pad_len = plain[-1]                        # снять PKCS7
flag = plain[:-pad_len].decode()
print(flag)
```

Вывод: `ctfcup{p4rcel_v1_unl0ck3d}`

## Flag

```
ctfcup{p4rcel_v1_unl0ck3d}
```
