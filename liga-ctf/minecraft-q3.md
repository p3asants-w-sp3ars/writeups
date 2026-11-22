---
title: "я просто хотел майнкрафт / Q3"
ctf: "Студенческая лига CTF — Раунд 1"
author: "anci31d"
date: 2026-11-21
category: forensics
points: 534
flag_format: "flag{...}"
---

# я просто хотел майнкрафт / Q3

## Условие

Определите основной активный планировщик, обеспечивающий повторный запуск вредоносных скриптов. В качестве ответа предоставьте абсолютный путь к его конфигурационному файлу в формате `flag{/absolute/path/to/file}`.

Исходные вложения задания: `traffic.pcap`, `victim_out.qcow2`. Крупные дампы в репозиторий не включены; команды выполняются в каталоге с этими файлами.

## Summary

Установщик вредоносного пакета копирует конфигурацию cron, которая повторно запускает скрипты.

## Solution

Из PCAP извлечён переданный по HTTP пакет `mc-backup-tool_1.3.7-ubuntu22_amd64.deb`. Его `postinst` устанавливает cron-файл командой:

```text
cp /usr/share/mc-backup-tool/cronfile /etc/cron.d/mc-backup-sync
```

Файл задаёт запуск `sync.sh` в 06:00 и 18:00 и `heartbeat.sh` каждые шесть часов в 30 минут. В пакете есть также systemd timer, однако `postinst` не включает и не запускает его; cron настроен явно.

Нужны tshark, ar и tar с поддержкой zstd. Извлекаем HTTP-объекты и читаем установщик, не запуская его:

```bash
mkdir -p httpobj tmpdeb
tshark -r traffic.pcap --export-objects http,httpobj
ar x httpobj/mc-backup-tool_1.3.7-ubuntu22_amd64.deb --output tmpdeb >/dev/null
mkdir -p pkg
tar --zstd -xf tmpdeb/data.tar.zst -C pkg
tar --zstd -xOf tmpdeb/control.tar.zst ./postinst | grep 'cp /usr/share/mc-backup-tool/cronfile /etc/cron.d/mc-backup-sync'
```

Сохранённый вывод:

```text
cp /usr/share/mc-backup-tool/cronfile /etc/cron.d/mc-backup-sync
```

## Flag

```text
flag{/etc/cron.d/mc-backup-sync}
```

[← К райтапам соревнования](README.md)
