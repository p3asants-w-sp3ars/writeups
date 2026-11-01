---
title: "Ровный робот"
ctf: "Кубок CTF 2026"
author: "citr0n"
date: 2026-11-01
category: misc
difficulty: hard
points: 642
flag_format: "ctfcup{...}"
---

# Ровный робот

## Summary

On-chain нарды против бота: нужно выиграть 15 партий подряд, кости
«честно» генерируются VRF-оракулом. Параметр `P` в VRF (`H = G^s mod P`)
оказался с полностью гладким `P-1`, поэтому секрет оракула `s`
восстанавливается за доли секунды через Pohlig–Hellman. Зная `s`, можно
офлайн вычислить **все будущие кости любой партии** ещё до `commit()`, а
`skip()` бесплатен — значит остаётся перебирать `gameId`, пока офлайн-
симуляция (та же сеть `model.fly` + тот же детерминированный алгоритм
хода мухи) не покажет гарантированную победу, и повторить 15 раз.

## Solution

### Step 1: ломаем VRF — восстанавливаем секрет оракула

`VRF.sol` строит кости как `y = u^s mod P`, где
`u = keccak256("flygammon-vrf-u", gameId, turn) mod P` — зависит только
от номера партии/хода, не от доски. `H = G^s mod P` публична
(`VRF.H()`), и если `P-1` B-smooth, `s` находится тривиально:

```python
P = 68146630276205992337013404353048769284923450494323212465724311145688545306763
G = 2
H = 30153528606358300971390323772675472983038186886852946498010491002429631379159

def factorize_smooth(n, bound=5_000_000):
    factors, d, m = {}, 2, n
    while d <= bound and d * d <= m:
        while m % d == 0:
            factors[d] = factors.get(d, 0) + 1
            m //= d
        d += 1 if d == 2 else 2
    if 1 < m <= bound:
        factors[m] = factors.get(m, 0) + 1
        m = 1
    return factors, m          # m == 1  =>  P-1 полностью гладкое

factors, cofactor = factorize_smooth(P - 1)
assert cofactor == 1           # P-1 = 2 * 14 простых чисел < 2^20

from sympy.ntheory.residue_ntheory import discrete_log
s = discrete_log(P, H, G)      # Pohlig-Hellman, <1с
assert pow(G, s, P) == H
```

Дальше кости любой партии `gameId` предсказуемы офлайн:

```python
from Cryptodome.Hash import keccak

def keccak256(*chunks):
    h = keccak.new(digest_bits=256)
    for c in chunks: h.update(c)
    return h.digest()

def dice(gameId, turn, s=s, P=P):
    u = int.from_bytes(keccak256(b"flygammon-vrf-u",
                                  gameId.to_bytes(32, "big"),
                                  turn.to_bytes(32, "big")), "big") % P
    u = max(u, 2)
    y = pow(u, s, P)
    hh = int.from_bytes(keccak256(b"flygammon-vrf-dice", y.to_bytes(32, "big")), "big")
    return (hh % 6) + 1, ((hh >> 8) % 6) + 1
```

### Step 2: офлайн-симуляция партий + доигрыш on-chain

Имея все будущие кости, бот перестаёт быть источником случайности —
`choose_2ply` детерминирован (та же модель `model.fly`, те же веса, тот
же 2-ply алгоритм, что в `agent.rs`/`oracle-daemon`). Берём у себя
полный лёгкий lookahead по реальным костям (не слепое усреднение на 21
расклад, как у бота), симулируем партию целиком офлайн и проверяем,
выиграна ли она — а поскольку `skip()` ничего не стоит, перебираем
`gameId`, пока не найдём выигрышный, параллельно по ядрам:

```python
# полный движок/модель/агент/VRF/chain-клиент — см. приложенный play.py
from play import (Chain, recover_secret, find_winning_game,
                   DiceSource, FlyNet, legal_ends, current_won,
                   find_model_path)

ch = Chain(RPC_URL, CHALLENGE_ADDR, PLAYER_PRIVATE_KEY)
P, G, H = ch.P(), ch.G(), ch.H()
s = recover_secret(P, G, H)
net = FlyNet(find_model_path(), hidden=80)

while ch.streak() < ch.N():
    if not ch.committed():
        gid, _ = find_winning_game(P, G, H, s, find_model_path(), 80, ch.gameId())
        while ch.gameId() < gid:
            ch.skip()                       # бесплатно
        ch.commit()                         # платим 1 токен за гарантированную победу
    ds = DiceSource(P, G, H, s, gid)
    while ch.committed():
        while not ch.dicePosted():
            pass
        turn = ch.turn()
        d1, d2 = ch.dice()
        assert (d1, d2) == ds.dice(turn)    # сверяем с офлайн-предсказанием
        ends = legal_ends(ch.boardPacked(), (d1, d2))
        eq = net.equities([k for k, _ in ends])
        best_path = ends[int(eq.argmax())][1]
        ch.player_move([m[0] for m in best_path], [m[1] for m in best_path])

print("isSolved():", ch.isSolved())
```

15 побед подряд → `isSolved() == true` → забираем флаг через `GET /flag`.

## Flag

```
ctfcup{003816047f29fb09c876d4a81a7248d2}
```
