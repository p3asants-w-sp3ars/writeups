# 🏆 Кубок CTF 2026

| | |
|---|---|
| **Даты** | 31.10.2026 12:00 → 01.11.2026 12:00 (MSK) |
| **Формат флага** | `ctfcup{...}` |
| **Результат** | 25 решённых тасков · 8499 очков |
| **Райтапов** | 17 |

## 📝 Райтапы

| Таск | Автор | Категория | Сложность | Очки | Суть решения |
|---|---|---|---|---:|---|
| [Hidden Network](hidden-network.md) | citr0n | 🌐 web | 🔴 hard | 772 | SSRF через userinfo в URL (`http://mme-monitor@host/`) → сервисный тикет внутреннего агента |
| [Peridromofilia](peridromofilia.md) | citr0n | 🌐 web | 🟡 medium | 567 | Mass assignment в MongoEngine-апдейте: `profile___cls` подменяет класс профиля на `ServiceCard` |
| [compuuuter](compuuuter.md) | citr0n | 🌐 web | 🟡 medium | 100 | TOCTOU между guard и evaluate + hash-flooding расширяет окно гонки до опкода 1337 |
| [Iso](iso.md) | citr0n | 🔐 crypto | 🔴 hard | 736 | Скрытое `p` по цепочке 2-изогений: кратное `p` → ECM → j-инвариант решёткой |
| [Weird RSA](weird-rsa.md) | citr0n | 🔐 crypto | 🟢 easy | 100 | RSA над `GF(257)[x]`: многочлены факторизуются за полиномиальное время |
| [filter](filter.md) | anci31d | 🧩 pwn | 🟢 easy | 100 | Self-modifying shellcode обходит статический фильтр запрещённых инструкций |
| [Noise in space](noise_in_space.md) | anci31d | ⚙️ reverse | 🟡 medium | 327 | Исправление двух нулевых параметров DSP-виртуальной машины и восстановление аудиофразы |
| [mmm](mmm.md) | citr0n | ⚙️ reverse | 🟢 easy | 100 | Вход — собственный вектор зашитой матрицы 40×40 |
| [Burmalda](burmalda.md) | anci31d | ⚙️ reverse | 🟡 medium | 100 | Извлечение констант Godot и воспроизведение линейного декодера флага |
| [Russian Post: Trust Level](mobile-russian-post.md) | citr0n | 📱 mobile | 🟡 medium | 337 | APK на gomobile: decoy-функции, ручной реверс `VerifySealedParcel` в `libgojni.so` |
| [Mobile Treasure Hunters](mobile_treasure_hunters.md) | anci31d | 📱 mobile | 🟡 medium | 327 | Восстановление SQLite/WAL и ключевой цепочки Android-сообщений с проверкой AES-GCM |
| [MeowSim: Schrodinger Edition](meowsim.md) | anci31d | 📱 mobile | 🟡 medium | 100 | Декомпиляция APK и восстановление XOR-флага через SHA-256-поток |
| [Puzzle](puzzle.md) | anci31d | 🔍 forensics | 🟡 medium | 380 | Восстановление фрагментов DATX из дампа памяти, сборка PNG и декодирование QR |
| [Художественный фильм](khudozhestvenniy-film.md) | citr0n | 🔍 forensics | 🔴 hard | 256 | Дамп EVM-форка: metamorphic-прокси через `CREATE`/`selfdestruct` перезаписывает слот роли |
| [My Own FS](my_own_fs.md) | anci31d | 🔍 forensics | 🟢 easy | 100 | Восстановление удалённого PNG по цепочке inode в образе файловой системы |
| [Ровный робот](rovniy-robot.md) | citr0n | 🧩 misc | 🔴 hard | 642 | On-chain нарды: гладкое `P-1` в VRF → Pohlig–Hellman → предсказание костей |
| [Snake](snake.md) | anci31d | 🧩 misc | 🟡 medium | 100 | Гамильтонов цикл проходит все 61 клетки шестиугольного поля |

## ✅ Все решённые таски

| Таск | Очки | Решено | Райтап |
|---|---:|---|:---:|
| GhostVector | 793 | 01.11 01:02 | — |
| Hidden Network | 772 | 31.10 23:20 | [📄](hidden-network.md) |
| Iso | 736 | 01.11 10:43 | [📄](iso.md) |
| PokéBox | 723 | 31.10 14:58 | — |
| Ровный робот | 642 | 01.11 00:16 | [📄](rovniy-robot.md) |
| Peridromofilia | 567 | 31.10 13:17 | [📄](peridromofilia.md) |
| 21 century man | 494 | 01.11 00:37 | — |
| ker quest | 400 | 31.10 18:04 | — |
| Электронный журнал | 394 | 31.10 14:37 | — |
| Puzzle | 380 | 31.10 19:46 | [📄](puzzle.md) |
| Russian Post: Trust Level | 337 | 31.10 13:04 | [📄](mobile-russian-post.md) |
| Noise in space | 327 | 31.10 20:30 | [📄](noise_in_space.md) |
| Mobile Treasure Hunters | 327 | 31.10 20:05 | [📄](mobile_treasure_hunters.md) |
| Художественный фильм | 256 | 31.10 13:00 | [📄](khudozhestvenniy-film.md) |
| Chik Chirik | 229 | 31.10 18:28 | — |
| Traverse | 207 | 31.10 13:20 | — |
| Святой Кодекс | 115 | 31.10 14:36 | — |
| filter | 100 | 31.10 14:33 | [📄](filter.md) |
| MeowSim: Schrodinger Edition | 100 | 31.10 14:07 | [📄](meowsim.md) |
| Burmalda | 100 | 31.10 14:01 | [📄](burmalda.md) |
| Snake | 100 | 31.10 13:12 | [📄](snake.md) |
| My Own FS | 100 | 31.10 12:39 | [📄](my_own_fs.md) |
| compuuuter | 100 | 31.10 12:30 | [📄](compuuuter.md) |
| MMM | 100 | 31.10 12:25 | [📄](mmm.md) |
| Weird RSA | 100 | 31.10 12:17 | [📄](weird-rsa.md) |

## ❌ Не решено

CyberCup 2077 · Святой Кодекс (Revenge) · Image Viewer · Connectome · Tartaros · Docus

---

[← Ко всем CTF](../README.md)
