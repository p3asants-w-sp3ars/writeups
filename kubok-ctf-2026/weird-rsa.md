---
title: "Weird RSA"
ctf: "Кубок CTF 2026"
team: "p3asants w/ sp3ars"
author: "citr0n"
date: 2026-10-31
category: crypto
difficulty: easy
points: 100
flag_format: "ctfcup{...}"
---

# Weird RSA

## Summary

Текстбук-RSA реализован не над целыми числами, а над кольцом многочленов `GF(257)[x]`.
Факторизация многочленов над конечным полем — полиномиальная задача (в отличие от
факторизации целых чисел), поэтому модуль `N = P·Q` раскладывается напрямую, и дальше
это обычное учебное RSA: `φ(N) = (257^deg(P) − 1)(257^deg(Q) − 1)`, `d = e⁻¹ mod φ(N)`.

## Solution

### Шаг 1: факторизовать N и расшифровать

`output.txt` даёт `p=257`, `e=65537`, коэффициенты `N` и `c` (многочлены над `GF(257)`,
младший коэффициент первым). Раскладываем `N` на неприводимые множители `P`, `Q`,
считаем аналог функции Эйлера, обращаем `e`, расшифровываем `c^d mod N` — коэффициенты
результата (младший первым) и есть байты флага.

```python
#!/usr/bin/env python3
"""Weird RSA (Кубок CTF 2026) — полное решение от output.txt до флага."""
from sympy import Poly, GF, symbols, invert
from sympy.polys.galoistools import gf_factor

x = symbols('x')
p = 257

with open('output.txt') as f:
    ns = eval(f.readline().split('=', 1)[1])
    es = int(f.readline().split('=', 1)[1])
    Ns = eval(f.readline().split('=', 1)[1])
    cs = eval(f.readline().split('=', 1)[1])

# коэффициенты в output.txt идут младший-первым -> для sympy Poly нужен старший-первым
N = Poly(list(reversed(Ns)), x, modulus=p)
c = Poly(list(reversed(cs)), x, modulus=p)

# факторизация N над GF(257) -- полиномиальное время, в отличие от факторизации целых
_, factors = gf_factor(N.all_coeffs(), p, GF(p))
(P_coeffs, _), (Q_coeffs, _) = factors
P = Poly(P_coeffs, x, modulus=p)
Q = Poly(Q_coeffs, x, modulus=p)

phi = (p ** P.degree() - 1) * (p ** Q.degree() - 1)
d = pow(es, -1, phi)

# m = c^d mod N -- модульное экспоненцирование многочленов
def polymulmod(a, b, mod):
    return (a * b).rem(mod)

m = Poly(1, x, modulus=p)
base = c
dd = d
while dd:
    if dd & 1:
        m = polymulmod(m, base, N)
    base = polymulmod(base, base, N)
    dd >>= 1

flag_bytes = bytes(reversed(m.all_coeffs()))
print(flag_bytes.decode())
```

Вывод: `ctfcup{862b7b348272087bd9cc0613646db566}`

## Flag

```
ctfcup{862b7b348272087bd9cc0613646db566}
```
