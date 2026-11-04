---
title: "Burmalda"
ctf: "Кубок CTF 2026"
author: "anci31d"
date: 2026-10-31
category: reverse
difficulty: medium
points: 100
flag_format: "ctfcup{...}"
---

# Burmalda

## Summary

Godot-игра показывает флаг после достижения баланса `13371337`, но флаг уже лежит в PCK-файле в зашифрованном виде. Декомпилируем PCK, находим `_decode_flag()` в `main.gd` и повторяем его офлайн.

## Solution

PCK извлекается GDRE Tools. После извлечения в `main.gd` интересны константы `_SA`, `_SB`, `_LC`, `_LA`, массив `_EF` и функция:

```gdscript
state = (_SA ^ _SB) & 0xffffffff
for i in range(_EF.size()):
    state = (_LC * state + _LA) & 0xffffffff
    kb = (state >> 13) & 255
    out[i] = ((_EF[i] ^ kb) - i) & 255
```

Состояние LCG обновляется для каждого байта. Байтом ключевого потока служит `state >> 13`, после чего байт `_EF[i]` XOR-ится с ним и из результата вычитается индекс.

Достаточный фрагмент Python-повтора выглядит так; значения констант и `_EF` берутся прямо из `main.gd`:

```python
state = (SA ^ SB) & 0xffffffff
plain = bytearray()
for i, encrypted in enumerate(EF):
    state = (LC * state + LA) & 0xffffffff
    plain.append(((encrypted ^ (state >> 13 & 0xff)) - i) & 0xff)
print(plain.decode("utf-8"))
```

Получается строка ниже. Проверка полезна из-за кириллицы: результат содержит 87 Unicode-кодовых точек и 151 байт UTF-8. Игровой процесс для извлечения флага не нужен: условие баланса только скрывает уже имеющиеся в клиенте данные.

## Flag

```text
ctfcup{Сначала_ДЭП_Потом_Додэп_Потом_ласт_Дэп_потом_Ультра_Ласт_Дэп_и_всё_будет_чётко!}
```
