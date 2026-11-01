---
title: "mmm"
ctf: "Кубок CTF 2026"
author: "citr0n"
date: 2026-10-31
category: reverse
difficulty: easy
points: 100
flag_format: "ctfcup{...}"
---

# mmm

## Summary

Бинарник проверяет, что 40-байтовый вход — **собственный вектор (eigenvector)**
зашитой в `.rodata` целочисленной матрицы 40×40: `check()` сравнивает
`buf[i]·(M·buf)[j] == buf[j]·(M·buf)[i]` для всех пар `i,j` (кросс-умножение вместо
деления), что эквивалентно `M·buf = λ·buf`. Подсказка "зеркало… своё отражение…
одна линия" — это и есть eigenvector. Собственное значение `λ = 1337` даёт
рациональный eigenvector со знаменателем 125; после умножения на 125 все 40
компонент превращаются в печатаемый ASCII.

## Solution

### Шаг 1: извлечь матрицу и найти флаг-эйгенвектор

```python
#!/usr/bin/env python3
"""mmm (Кубок CTF 2026) — полное решение от бинарника до флага."""
import struct
import numpy as np
import sympy as sp

with open('mmm', 'rb') as f:
    data = f.read()

# MATRIX (_ZL6MATRIX) лежит в .rodata по смещению 0x3220, 40x40 int64 (найдено
# через readelf/objdump -t по символу)
off, n = 0x3220, 40 * 40
vals = struct.unpack_from('<%dq' % n, data, off)
M = np.array(vals, dtype=np.int64).reshape(40, 40)

# численно ищем собственные значения -> среди них ровно 1337 (намёк "elite/leet")
w, _ = np.linalg.eig(M.astype(np.float64))
assert any(abs(w.real - 1337) < 1e-6)

# точный рациональный eigenvector через nullspace(M - 1337*I)
Ms = sp.Matrix(M.tolist())
vec = (Ms - 1337 * sp.eye(40)).nullspace()[0]

# общий знаменатель компонент -- 125; после умножения получаем печатаемый ASCII
scaled = [int(c * 125) for c in vec]
flag = ''.join(chr(v) for v in scaled)
print(flag)
```

Вывод: `ctfcup{99aeaf6c1fb1d156e4194be638825e6f}`

### Шаг 2: проверка на реальном бинарнике

Бинарник — x86-64 Linux ELF; на Apple Silicon запускал через Docker/OrbStack с
`--platform linux/amd64`. Правильный вход даёт сообщение об успехе
`"The seal breaks. Carry what you brought to the gate."` (неверный — другое
сообщение, `"The mirror shows a stranger..."`), что подтверждает флаг без
необходимости разбирать отдельную проверку SHA-256.

## Flag

```
ctfcup{99aeaf6c1fb1d156e4194be638825e6f}
```
