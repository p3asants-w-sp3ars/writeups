---
title: "Puzzle"
ctf: "Кубок CTF 2026"
author: "anci31d"
date: 2026-10-31
category: forensics
difficulty: medium
points: 380
flag_format: "ctfcup{...}"
---

# Puzzle

## Summary

Задача на восстановление удалённых данных из дампа памяти. В памяти остались части файла `DATX`; разные клиенты применяли разные преобразования, а CRC32 позволяет отсеять неверные находки. После сборки частей получается QR-код с флагом. Категория: forensics/misc; сложность средняя; инструменты: Python 3 и `zbarimg`.

## Solution

### Разведка

Входной артефакт — снимок памяти `puzzle.vmem`. Ищем сигнатуру `DATX`, читаем поля заголовка и проверяем номер фрагмента, клиента, канал, длину и CRC.

Ключевой фрагмент декодера:

```python
def decode(client, data, key):
    if client == 0:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if client == 1:
        return bytes((((b - 0x5a) & 255) << 5 | ((b - 0x5a) & 255) >> 3) & 255 for b in data)
    if client == 2:
        return rc4(data, key)
    state, out = 0xb037bf34 ^ 0x6a9b701c, bytearray()
    for b in data:
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        state &= 0xffffffff
        out.append(b ^ (state & 255))
    return bytes(out)

while (pos := memory.find(b"DATX", pos)) != -1:
    chunk, client, channel, size, crc = struct.unpack_from("<IHHII", memory, pos + 4)
    if chunk < 4096 and client < 4 and client == chunk % 4 and 1 <= size <= 128:
        plain = decode(client, memory[pos + 20:pos + 20 + size], key)
        if zlib.crc32(plain) == crc:
            fragments[chunk] = plain
    pos += 1
```

Фрагмент применяет декодер, соответствующий клиенту. Для типа 0 используется ключ `ea8e2bbc5e2ec467bc6268b0de893f6d`; тип 2 получает RC4-ключ как XOR 16-байтовых областей `cl2.exe` по offset `0xe528` и `0xe540`. Среди преобразований есть XOR с ключом, циклический сдвиг, RC4 и XOR-поток xorshift. CRC32 проверяет целостность распакованного содержимого. Функции `rc4`, чтение `memory`, начальное `pos = 0` и запись результата в PNG опущены для краткости.

Успешная контрольная точка — `missing=[]` и `png_signature=True`.

### Решение и проверка

Склеенный файл — PNG 343×343, однобитный grayscale. Одного корректного PNG недостаточно, чтобы утверждать, что флаг найден: изображение оказалось QR-кодом, его нужно декодировать.

```bash
file recovered-flag.png
zbarimg --quiet --raw recovered-flag.png
```

`file` проверяет формат изображения. `zbarimg` читает QR/штрихкоды; `--raw` убирает подпись типа символики, `--quiet` сокращает служебный вывод.

```text
ctfcup{4lpc_r3mn4nts_0f_th3_br0k3r_7hru_p1x3l5}
```

## Почему это работает

Дамп памяти содержит не только активные объекты, но и оставшиеся копии данных. Сигнатура помогает найти кандидата, но не доказывает его правильность. Структурные ограничения заголовка и CRC дают проверяемый фильтр; после него фрагменты упорядочиваются по номеру и склеиваются. QR-код — лишь финальная упаковка уже восстановленного флага.

## Воспроизведение и границы

Для CRC-проверки клиентского типа 2 нужен ключ RC4 из образа процесса `cl2.exe`: он строится как XOR двух 16-байтовых фрагментов по смещениям `0xe528` и `0xe540`. После сортировки по `chunk` фрагменты склеиваются. Отсутствие номеров означает ошибку извлечения; в этом образе `missing=[]`.

Контрольная сумма проверенного PNG: `4e8263932b6e99afebc359bcb3e9c2bf2d983a38e3eee1050cb96d84b82ce6da`.

Термины: **дамп памяти** — сохранённое содержимое оперативной памяти; **CRC32** — контрольная сумма для обнаружения повреждения данных; **сигнатура** — характерная последовательность байтов или структура формата.

## Flag

```text
ctfcup{4lpc_r3mn4nts_0f_th3_br0k3r_7hru_p1x3l5}
```
