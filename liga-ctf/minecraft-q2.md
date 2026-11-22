---
title: "я просто хотел майнкрафт / Q2"
ctf: "Студенческая лига CTF — Раунд 1"
author: "anci31d"
date: 2026-11-21
category: forensics
points: 521
flag_format: "flag{...}"
---

# я просто хотел майнкрафт / Q2

## Условие

Определить файл, скрывающий артефакты атаки от обычных инструментов обозрения файловой системы.

Исходные вложения задания: `traffic.pcap`, `victim_out.qcow2`. Крупные дампы в репозиторий не включены; команды выполняются в каталоге с этими файлами.

## Summary

Библиотека из `/etc/ld.so.preload` перехватывает обращения к файлам и скрывает следы вредоносного пакета.

## Solution

Нужны QEMU (`qemu-img`), Sleuth Kit (`fls`, `icat`) и GNU Binutils (`nm`).

Пакет `mc-backup-tool`, извлечённый из HTTP-трафика, устанавливает библиотеку
`/usr/lib/mc-backup-tool/stealth/libmcbackup.so` и добавляет её путь в
`/etc/ld.so.preload`. Она перехватывает `stat` и `lstat` и скрывает каталоги
`/var/cache/mc-backup-tool` и `/var/log/mc-backup-tool`. Это виновник сокрытия.

В образе третий GPT-раздел содержит LVM: `pe_start = 2048` секторов,
логический том начинается с extent 0. Поэтому смещение ext4 в образе —
`3674112 + 2048 = 3676160` секторов. Образ частично повреждён, для чтения
доступных секторов использован режим salvage:

```sh
qemu-img convert --salvage -O raw victim_out.qcow2 victim_salvage.raw
fls -o 3676160 -r -p victim_salvage.raw | grep 'usr/lib/mc-backup-tool/stealth/libmcbackup.so'
icat -o 3676160 victim_salvage.raw 47112 > recovered-libmcbackup.so
nm -D recovered-libmcbackup.so | grep -E ' (stat|lstat)$'
```

`fls` показывает inode `47112`, а символы ELF включают `stat` и `lstat`.

Сохранённый вывод:

```text
r/r 47112: usr/lib/mc-backup-tool/stealth/libmcbackup.so
0000000000001202 T lstat
000000000000118e T stat
```

## Flag

```text
flag{/usr/lib/mc-backup-tool/stealth/libmcbackup.so}
```

[← К райтапам соревнования](README.md)
