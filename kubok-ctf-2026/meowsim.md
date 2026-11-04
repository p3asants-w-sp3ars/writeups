---
title: "MeowSim: Schrodinger Edition"
ctf: "Кубок CTF 2026"
author: "anci31d"
date: 2026-10-31
category: mobile
difficulty: medium
points: 100
flag_format: "ctfcup{...}"
---

# MeowSim: Schrodinger Edition

## Summary

В APK есть зашифрованный флаг и вся формула его ключа. Условие открытия требует одновременно живого и мёртвого кота, но эти признаки хранятся раздельно. Восстанавливаем допустимое состояние, считаем SHA-256-ключ и снимаем XOR-поток офлайн.

## Solution

APK декомпилируется через JADX. `QuantumState.canOpenFlagVault()` требует `catAlive && catDead && superposition && stability >= 90 && !observed && !tampered`. Условие не противоречиво: `catAlive` приходит из `PetStore`, а `catDead` — из `BoxStore`.

В `FlagVault.java` находятся массив `ENCRYPTED_FLAG` и две операции. Ключ получается так:

```java
sha256(observerToken + "|" + boxSeal + "|" + stability + "|" +
       catAlive + "|" + catDead + "|" + superposition + "|" +
       observed + "|meowsim-v1")
```

Печать коробки задаётся в `BoxStore.sealFor()`:

```java
sha256("box|" + catDead + "|" + superposition + "|" + stability + "|meowsim-v1")
```

Поток для XOR-а состоит из последовательных SHA-256 блоков `SHA256(key || counter)`. Счётчик — четырёхбайтное big-endian число. После XOR с `ENCRYPTED_FLAG` получается открытый текст.

Токен наблюдателя берётся из `ObserverStore.DEFAULT_TOKEN`. Стабильность проверяем в диапазоне `90..100` и принимаем только результат с префиксом `ctfcup{`. Ключевые преобразования:

```python
seal = sha256(f"box|true|true|{stability}|meowsim-v1".encode()).hexdigest()
key = sha256(f"{token}|{seal}|{stability}|true|true|true|false|meowsim-v1".encode()).digest()
stream = b"".join(sha256(key + counter.to_bytes(4, "big")).digest()
                  for counter in range((len(flag) + 31) // 32))
plain = bytes(cipher ^ stream_byte for cipher, stream_byte in zip(flag, stream))
```

Правильные входы дают `stability=92` и строку ниже. SHA-256 здесь не ломается: все входы детерминированной формулы находятся в APK, поэтому ключевой поток можно воспроизвести.

## Flag

```text
ctfcup{cat_0bserv3r_92}
```
