---
title: "Mobile Treasure Hunters"
ctf: "Кубок CTF 2026"
author: "anci31d"
date: 2026-10-31
category: mobile
difficulty: medium
points: 327
flag_format: "ctfcup{...}"
---

# Mobile Treasure Hunters

## Summary

В образе телефона приложение Burnt Note очистило таблицу сообщений, но старые страницы SQLite остались в WAL и в удалённых ячейках. После восстановления записей нужно собрать цепочку AES-GCM-ключей: следующий ключ зависит от полного дополненного текста предыдущего сообщения.

## Solution

Из архива извлекаем файлы телефона и читаем диагностический журнал, WhatsApp-базу, EXIF фотографии, историю Chrome и Android ID. Нужные фрагменты seed в порядке времени:

```text
5a1b2ef44061-64574c90358d-3d91968bd7ed-ae4fa6e83015
```

Соль — ASCII-строка Android ID:

```text
426079c78484367a
```

Декомпиляция APK показывает схему:

```text
master = PBKDF2-HMAC-SHA256(seed, android_id, 100000, 32)
key_0 = HMAC-SHA256(master, "burnt-note/root")
plaintext = AES-GCM(key_i, nonce, frame, aad="burnt-note/msg/<id>")
key_(i+1) = HMAC-SHA256(key_i,
    plaintext_padded + "|burnt-note/step|<id+1>")
```

`plaintext_padded` имеет 1400 байт: нулевые байты можно убрать только при печати, но не перед вычислением следующего ключа.

### Восстановление SQLite

У `messages.db` есть `messages.db-wal`. Размер страницы читается из WAL по offset 8 и равен 4096. Первые пять WAL-кадров имеют заголовки по 24 байта; содержимое кадра копируется на страницу `(page_number - 1) * 4096`. После применения кадра с commit `8` получается согласованный снимок до финальной очистки.

Для строк 2 и 4 ссылки на ячейки были удалены, но сами ячейки сохранились на страницах 4 и 5 в offset `1206`. Ключевая проверка перед восстановлением:

```python
for page, rowid in ((4, 2), (5, 4)):
    offset = (page - 1) * 4096
    assert db[offset] == 0x0d
    assert db[offset + 1206:offset + 1210] == bytes([0x8b, 0x22, rowid, 0x07])
    db[offset + 3:offset + 5] = (2).to_bytes(2, "big")
    db[offset + 5:offset + 7] = (1206).to_bytes(2, "big")
    db[offset + 10:offset + 12] = (1206).to_bytes(2, "big")
```

После этого `PRAGMA integrity_check` возвращает `ok`, а запрос к таблице даёт ID от 1 до 12.

### Расшифрование

AES-GCM проверяет и ключ, и AAD, поэтому ошибочный seed или ID сразу дают `InvalidTag`. Ключевая часть цепочки:

```python
master = hashlib.pbkdf2_hmac("sha256", seed, salt, 100000, 32)
key = hmac.digest(master, b"burnt-note/root", "sha256")
for message_id, nonce, frame in rows:
    padded = AESGCM(key).decrypt(
        nonce, frame, f"burnt-note/msg/{message_id}".encode()
    )
    print(padded.rstrip(b"\0").decode())
    key = hmac.digest(
        key, padded + f"|burnt-note/step|{message_id + 1}".encode(), "sha256"
    )
```

Финальные сообщения расшифровываются так:

```text
8: Вторая — двор за школой, у синих гаражей.
10: Последняя самая важная. Сделаешь — сожги все переписки.
11: Готово. Три из трех. Сейчас все сожгу.
12: Подтверждаю приём. Контрольная фраза: ctfcup{ch41n_0f_4sh3s}. Сожги и это.
```

Все 12 GCM-тегов проходят проверку, поэтому результат подтверждён криптографически. Условие задачи обещает адрес финальной точки, но последнее сообщение содержит только контрольную фразу; дополнительный адрес из имеющихся данных восстановить нельзя.

## Flag

```text
ctfcup{ch41n_0f_4sh3s}
```
