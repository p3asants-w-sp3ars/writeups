---
title: "Iso"
ctf: "Кубок CTF 2026"
author: "citr0n"
date: 2026-11-01
category: crypto
difficulty: hard
points: 736
flag_format: "ctfcup{...}"
---

# Iso

## Summary

Флаг — j-инвариант стартовой эллиптической кривой над `GF(p)`, из которой делается 64 случайных 2-изогении; на выходе только `a4, a6` итоговой кривой (центрированные), а `p` скрыт. Решение: возвраты в графе изогений дают предсказуемый масштаб модели, из этого получается целое число, кратное `p`; `p` находится ECM, затем j и флаг восстанавливаются решёткой.

## Solution

### Шаг 1: обратные шаги сокращаются, остаётся путь длины L

Модель Sage для `j`: `a4 = -3jk`, `a6 = -2jk²`, `k = j-1728`. Кодомен 2-изогении с ядром в корне `r` кубики (формулы Велю): `A' = -4A-15r²`, `B' = -22r³-8Ar`. Шаг и сразу обратный к нему возвращают исходную кривую, но модель умножается на `u=2` (т.е. `(A,B) -> (16A, 64B)`). После 64 случайных шагов почти все возвраты сокращаются, остаётся путь без возвратов длины `L` (чётная; у нашего экземпляра `L=2`), а модель отличается от «чистой» на `u = 2^((64-L)/2)`.

Проверено на настоящем Sage: для малых `p` случайные 64-шаговые прогулки дают `L=0` в ~59% случаев, `L=2` в ~24%, `L=4` в ~8%. Для `L=0` (проверено, не наш случай) условие `4A³+27B²+31104·2⁶⁴·AB ≡ 0 (mod p)` раскладывалось целиком без 124-битного простого.

### Шаг 2: целое число, кратное p

Идём от итоговой кривой `L` шагов назад по несокращаемому пути (корень `r` кубики, затем корень `ρ` квадратики `ρ²-2rρ-4A-11r²`). В конце получаем модель `(A'',B'')` стартовой кривой, умноженную на `u²=s=2^(64+L)`; она обязана удовлетворять

`g = -31104·s·A''·B'' - 27·B''² - 4·A''³ ≡ 0 (mod p)`.

Норма `g` по башне `Q(r)(ρ)` — целое `F` (~2400 бит), кратное `p`. Мелкие множители (до 1e7) выбрасываем и запускаем gmp-ecm с `B1=3e6`: за ~2 ч на 10 ядрах (~2400 кривых) находится `p = 78390170948882985413083708539615087041` (126 бит, простое, `p > 2·|a4|`).

### Шаг 3: j и флаг

Обратная цепочка по модулю `p` даёт единственное `j = 1728 + 3B''/(2·s·A'')`. Флаг — это `int.from_bytes(flag,'little') mod p`; его 216 бит не помещаются в `p`, но известны `ctfcup{` (младшие 7 байт), `}` (старший) и остальные 19 байт печатные. Получается задача о близком векторе в решётке размерности 19 (`Σ d_i·256^(7+i) ≡ t (mod p)`); CVP даёт одного кандидата, а перебор в шаре радиуса ~190 вокруг него (+ фильтр «печатные ASCII») оставляет два варианта, один из которых читаем.

Полный скрипт (Sage/passagemath + `fpylll` + `gmp-ecm`; `P` подставлен, чтобы не ждать ECM, `P = None` пересчитывает его; с подставленным `P` работает ~4 с):

```python
# Запуск: python solve.sage.py  (нужны passagemath/Sage, fpylll и gmp-ecm в PATH)
from sage.all import *
from fpylll import IntegerMatrix, LLL, BKZ, CVP
import re, subprocess

# --- данные из output.txt ---
out = open('files/iso/output.txt').read()
A, B = [Integer(v.replace(' ', '')) for v in
        re.match(r'x\^3 \+ (-?\d+)\*x ([+-] \d+)', out).groups()]
L = 2                      # длина пути без возвратов (для этого экземпляра)
s = 2**(64 + L)            # масштаб модели после L обратных шагов

# --- 1. целое число F, делящееся на p ---
x = polygen(QQ)
K1 = NumberField(x**3 + A*x + B, 'r'); r = K1.gen()
K2 = K1.extension(x**2 - 2*r*x - 4*A - 11*r**2, 'w'); w = K2.gen()
Ap = -4*A - 15*r**2
App = -4*Ap - 15*w**2
Bpp = -22*w**3 - 8*Ap*w
g = -31104*s*App*Bpp - 27*Bpp**2 - 4*App**3
F = abs(Integer(g.absolute_norm()))

# --- 2. p: ECM на F (B1=3e6, ~2400 кривых, ~2 ч на 10 ядрах) ---
P = 78390170948882985413083708539615087041   # результат ECM (чтобы не ждать ~2 ч); поставьте None, чтобы пересчитать
if P is None:
    for q in prime_range(10**7):
        while F % q == 0: F //= q
    procs = [subprocess.Popen(['ecm', '-c', '300', '-one', '-q', '3e6'], stdin=subprocess.PIPE,
             stdout=subprocess.PIPE, text=True) for _ in range(10)]
    for pr in procs: pr.stdin.write(f'{F}\n'); pr.stdin.close()
    for pr in procs:
        f = Integer(pr.stdout.read().split()[0])
        if 1 < f < F and is_prime(f) and f > 2*max(abs(A), abs(B)):
            P = f; break
p = Integer(P); assert is_prime(p) and p.nbits() <= 128

# --- 3. j стартовой кривой = флаг mod p ---
Fp = GF(p); X = PolynomialRing(Fp, 'X').gen()
j = None
for r0, _ in (X**3 + Fp(A)*X + Fp(B)).roots():
    a1 = -4*Fp(A) - 15*r0**2
    for r1, _ in (X**2 - 2*r0*X - 4*Fp(A) - 11*r0**2).roots():
        a2 = -4*a1 - 15*r1**2; b2 = -22*r1**3 - 8*a1*r1
        if -31104*s*a2*b2 - 27*b2**2 - 4*a2**3 == 0:
            j = Integer(1728 + 3*b2/(2*s*a2))

# --- 4. решётка: x = j (mod p), известны "ctfcup{" и "}", остальное печатное ASCII ---
pre, suf, n = b'ctfcup{', b'}', 19
mid, rad = 79, 47
K = int.from_bytes(pre + bytes([mid])*n + suf, 'little')
wgt = [pow(256, len(pre) + i, p) for i in range(n)]
t = (j - K) % p; w0 = pow(wgt[0], -1, p)
rows = [[p] + [0]*(n-1)] + [[(-wgt[i]*w0) % p] + [1 if k == i else 0 for k in range(1, n)] for i in range(1, n)]
M = IntegerMatrix.from_matrix(rows); LLL.reduction(M); BKZ.reduction(M, BKZ.Param(block_size=20))
v = CVP.closest_vector(M, tuple([(t*w0) % p] + [0]*(n-1)))
d0 = [((t*w0) % p if k == 0 else 0) - v[k] for k in range(n)]     # маленький представитель цели
Bn = [[float(M[i, k]) for k in range(n)] for i in range(n)]
Q, mu, nb = [], [[0.0]*n for _ in range(n)], []                   # Грам-Шмидт (float)
for i in range(n):
    q = Bn[i][:]
    for k in range(i):
        mu[i][k] = sum(a*b for a, b in zip(Bn[i], Q[k]))/nb[k]
        q = [a - mu[i][k]*b for a, b in zip(q, Q[k])]
    Q.append(q); nb.append(sum(a*a for a in q))
c = [sum(a*b for a, b in zip(d0, Q[i]))/nb[i] for i in range(n)]
R2, xs, sols = 190.0**2, [0]*n, []
def rec(i, part):                                                  # перебор по Шнорру-Эйхнеру в шаре
    if i < 0: sols.append(xs[:]); return
    cen = c[i] - sum(xs[k]*mu[k][i] for k in range(i+1, n))
    wd = (max(R2 - part, 0)/nb[i])**0.5
    for xi in range(ceil(cen - wd), floor(cen + wd) + 1):
        xs[i] = xi; rec(i-1, part + (xi - cen)**2*nb[i])
rec(n-1, 0.0)
for sol in sols:
    d = [d0[k] - sum(sol[i]*int(M[i, k]) for i in range(n)) for k in range(n)]
    if all(32 <= mid + e <= 126 for e in d):
        print(pre + bytes(mid + e for e in d) + suf)
```

Вывод:

```
b"ctfcup{1t's_y0ou_4Nd__Me!!}"
b'ctfcup{}TwyUq?vJ3tx[$($i$O}'
```

Проверка: `int.from_bytes(b"ctfcup{1t's_y0ou_4Nd__Me!!}", 'little') % p == j` — совпадает.

## Flag

```
ctfcup{1t's_y0ou_4Nd__Me!!}
```
