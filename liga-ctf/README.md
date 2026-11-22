# 🏆 Студенческая лига CTF — Раунд 1

| | |
|---|---|
| **Даты** | 21.11.2026 |
| **Формат флага** | `flag{...}` |
| **Результат** | 11 решённых тасков · 5324 очка |
| **Райтапов** | 11 |

Очки приведены по [борде](https://xn--r1aee.xn--80afol2bmm.xn--p1acf/teams/17) на 22.11.2026. Сложность оценена по очкам: easy — до 399, medium — 400–699, hard — от 700.

## 📝 Райтапы

| Таск | Автор | Категория | Сложность | Очки | Суть решения |
|---|---|---|---|---:|---|
| [Momentum](momentum.md) | citr0n | 🌐 web | 🔴 hard | 842 | Слепая SQL-инъекция при проверке промокода |
| [Обмен](obmen.md) | anci31d | 🔐 crypto | 🟢 easy | 304 | Утечка показателя → дискретный логарифм → XOR |
| [я просто хотел майнкрафт / Q1](minecraft-q1.md) | anci31d | 🔍 forensics | 🟡 medium | 481 | HTTP-трафик раскрывает сервер эксфильтрации |
| [Can YOU handle it?](CAN_YOU_handle_it?_.md) | zx689abn74y | 🔍 forensics | 🟡 medium | 481 | В дампе pinned-строка указывает на XOR-зашифр. telemetry.bin; берём 37 байт со смещения 7434 и xor-им 0xFC |
| [я просто хотел майнкрафт / Q2](minecraft-q2.md) | anci31d | 🔍 forensics | 🟡 medium | 521 | LD_PRELOAD скрывает артефакты атаки |
| [я просто хотел майнкрафт / Q3](minecraft-q3.md) | anci31d | 🔍 forensics | 🟡 medium | 534 | Установщик пакета раскрывает конфигурацию cron |
| [Сработка](srabotka.md) | citr0n | 🔍 forensics | 🟡 medium | 494 | Состояние TCP-клиента и XOR двух блоков |
| [Нулевой меридиан](nulevoy-meridian.md) | citr0n | 🧩 ppc | 🟢 easy | 365 | Аффинные матрицы над GF(251) и поиск по двум вахтам |
| [Receipt](receipt.md) | anci31d | 🖼️ stego | 🟢 easy | 350 | Сообщение в исправленных байтах QR |
| [Uralmash](uralmash.md) | anci31d | 🖼️ stego | 🟡 medium | 572 | Alpha LSB → ZIP → битовые блоки → AES-GCM |
| [Кодовый замок](codoviy_zamok.md) | zx689abn74y | ⚙️ reverse | 🟢 easy | 380 | CRC-фильтр → связи пар → meet-in-the-middle по двум суммам → SHA-256-квитанция |

Небольшие исходные вложения включены в `files/`. Образы дисков, сетевые дампы и ленту `sexta.dat` берите из исходных заданий.

[← Ко всем CTF](../README.md)
