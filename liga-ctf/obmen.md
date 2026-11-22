---
title: "Обмен"
ctf: "Студенческая лига CTF — Раунд 1"
author: "anci31d"
date: 2026-11-21
category: crypto
points: 304
flag_format: "flag{...}"
---

# Обмен

## Условие

Восстановить сообщение сеанса `beta` по модулю вычислителя, журналу обменов и контрольным запускам. Вложения: [capture.json](files/capture.json), [exchange.wasm](files/exchange.wasm), [note.txt](files/note.txt). Скрипт запускается из каталога `liga-ctf`. Нужны Python 3 и SymPy.

## Summary

В журнале записаны старшие 20 бит показателя предыдущего вызова `run`, хотя метка принадлежит текущему вызову. У порядка группы есть достаточно большая гладкая часть: логарифм по ней вместе с утечкой позволяет восстановить показатель сеанса `beta` ограниченным поиском.

## Solution

В `exchange.wasm` по адресу 0 лежит простое число `p = 0x7bf45333234d47dd18d1823272bd2085`, а по адресу 16 — генератор `g = 2`. Контрольные вызовы с известными показателями показывают, что регистратор начинает писать со второго вызова: слово `0x45230100` при метке второй операции соответствует старшим 20 битам `0x12345` показателя первой. Байты диагностического слова читаются в little-endian; последние три байта полученной последовательности образуют искомый префикс в big-endian.

Поэтому запись с меткой `beta-right` раскрывает префикс `0x70f65` показателя `a` операции `beta-left`. Для открытого значения `A = 2^a mod p` вычисляем дискретные логарифмы по простым степеням гладкого делителя `M` числа `p − 1` и объединяем их китайской теоремой об остатках. Получаем `a = r + M·k`. Из известного префикса следует диапазон возможных `k`; оставшийся поиск выполняем методом baby-step giant-step. Найденный показатель проверяем равенством `2^a mod p = A`.

Далее общий ключ равен `B^a mod p`, где `B` — открытое значение `beta-right`. Его 16 байт повторяются при XOR с шифртекстом. Для запуска нужны Python 3 и библиотека SymPy; находясь в каталоге задачи, выполните следующий скрипт:

```python
import json, math
from sympy import discrete_log
from sympy.ntheory.modular import crt

d=json.load(open('files/capture.json'))
p=0x7bf45333234d47dd18d1823272bd2085
g=2
factors=[4,27,25,7,11,13,17,19,23,29,31,37,41,43,47,53]
M=math.prod(factors)
op=d['operations'][4]
y=int(op['result'],16)
res=[]
for q in factors:
    res.append(int(discrete_log(p,pow(y,(p-1)//q,p),pow(g,(p-1)//q,p),order=q)))
r=int(crt(factors,res)[0])
w=d['trace_words'][4]['word']
prefix=int.from_bytes(w.to_bytes(4,'little')[1:],'big')
lo=prefix<<108
hi=(prefix+1)<<108
k0=max(0,(lo-r+M-1)//M)
kmax=(hi-1-r)//M
N=kmax-k0+1
base=pow(g,M,p)
target=y*pow(pow(g,r+M*k0,p),-1,p)%p
step=math.isqrt(N)+1
print('smooth modulus bits:',M.bit_length(),'prefix:',hex(prefix),'interval size:',N,'BSGS table:',step,flush=True)
table={}
v=1
for j in range(step):
    table.setdefault(v,j);v=v*base%p
factor=pow(pow(base,step,p),-1,p)
v=target
for i in range((N+step-1)//step):
    if v in table:
        k=k0+i*step+table[v]
        a=r+M*k
        if a<hi and pow(g,a,p)==y:
            print('public value check: OK')
            b=int(d['operations'][5]['result'],16)
            key=pow(b,a,p).to_bytes(16,'big')
            ct=bytes.fromhex(d['ciphertext'])
            msg=bytes(c^key[i%16] for i,c in enumerate(ct))
            print('plaintext:',msg.decode())
            break
    v=v*factor%p
else: raise RuntimeError('no matching exponent')
```

Сохранённый вывод решения:

```text
smooth modulus bits: 72 prefix: 0x70f65 interval size: 110642982999 BSGS table: 332631
public value check: OK
plaintext: flag{lagged_limb_9d2f31}
```

## Flag

```text
flag{lagged_limb_9d2f31}
```

[← К райтапам соревнования](README.md)
