---
title: "я просто хотел майнкрафт / Q1"
ctf: "Студенческая лига CTF — Раунд 1"
author: "anci31d"
date: 2026-11-21
category: forensics
difficulty: medium
points: 481
flag_format: "flag{...}"
---

# я просто хотел майнкрафт / Q1

## Условие

Идентифицируйте хост атакующего, в качестве ответа предоставьте домен, относящийся к нему IP-адрес и порт, использованные для эксфильтрации в формате `flag{full.domain.tld(ip.addr):port}`.

Исходные вложения задания: `traffic.pcap`, `victim_out.qcow2`. Крупные дампы в репозиторий не включены; команды выполняются в каталоге с этими файлами.

## Summary

HTTP-запросы в PCAP раскрывают домен, IP-адрес и порт сервера эксфильтрации.

## Solution

Нужен Wireshark CLI (capinfos и tshark). Просматриваем HTTP-запросы:

```sh
capinfos traffic.pcap
tshark -r traffic.pcap -Y 'http.request' -T fields \
  -e ip.src -e ip.dst -e tcp.dstport -e http.host -e http.request.method -e http.request.uri
```

В обычном обновлении системы видны обращения к Ubuntu mirrors. Подозрительная сессия начинается с POST-запросов к `backup.mchost.io:8443` на внутренний адрес `192.168.1.245`:

```text
10.3.3.27 -> 192.168.1.245:8443  POST backup.mchost.io /handshake
10.3.3.27 -> 192.168.1.245:8443  POST backup.mchost.io /upload
10.3.3.27 -> 192.168.1.245:8443  POST backup.mchost.io /heartbeat
```

Большой запрос `/upload` содержит сжатый архив, что подтверждает эксфильтрацию.

## Flag

```text
flag{backup.mchost.io(192.168.1.245):8443}
```

[← К райтапам соревнования](README.md)
