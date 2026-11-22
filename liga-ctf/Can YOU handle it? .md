# Writeup — «Can YOU handle it?» (481 балл)

## 1. Задание

- **Название:** Can YOU handle it? (481 балл)
- **Описание:** «Подозрительный процесс работал непродолжительное время, однако успел обработать флаг.»
- **Файлы:** `disk.vhdx`, `suspicious_full.dmp`
- **Формат флага:** `flag{...}`

## 2. Первичный анализ

```
$ ls
disk.vhdx
suspicious_full.dmp

$ file disk.vhdx suspicious_full.dmp
disk.vhdx:           Microsoft Disk Image eXtended, by Microsoft Windows 10.0.26200.0, sequence 0xa
suspicious_full.dmp: Mini DuMP crash report, 15 streams, Fri Feb 27 22:05:11 2026, 0x20006 type
```

**`disk.vhdx`** — динамический VHDX объёмом 256 МиБ (268 435 456 байт). Внутри — MBR-разметка, один раздел NTFS, начинающийся с сектора 128 (смещение 65 536 байт). Метка тома: **`CTF_DELETED_HANDLE`**. Кластер NTFS — 4096 байт.

**`suspicious_full.dmp`** — пользовательский полный дамп памяти (MDMP), 15 потоков, PID 3664, Windows build 26200, время создания — `2026-02-27 22:05:11 UTC`. Флаги дампа `0x20006` соответствуют `MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpIgnoreInaccessibleMemory`.

**Инструменты:** `7z`, `libvhdi` через `ctypes` (утилиты `vhdimount`/`qemu-nbd` в системе отсутствовали), SleuthKit (`fls`, `istat`, `icat`), `strings`, Python, `dnfile`/`dncil` для разбора .NET-сборки. Все действия выполнялись с копиями в `/tmp/opencode`, исходные файлы не изменялись.

## 3. Ход расследования

### 3.1. Анализ `disk.vhdx`

VHDX был сконвертирован в сырой образ `/tmp/opencode/disk.raw` через `libvhdi`:

```python
import ctypes

lib = ctypes.CDLL("libvhdi.so.1")
f, err = ctypes.c_void_p(), ctypes.c_void_p()
lib.libvhdi_file_initialize(ctypes.byref(f), ctypes.byref(err))
lib.libvhdi_file_open(f, b"disk.vhdx", 1, ctypes.byref(err))

size = ctypes.c_uint64()
lib.libvhdi_file_get_media_size(f, ctypes.byref(size), ctypes.byref(err))

with open("/tmp/opencode/disk.raw", "wb") as out:
    off = 0
    while off < size.value:
        n = min(1 << 20, size.value - off)
        buf = ctypes.create_string_buffer(n)
        got = lib.libvhdi_file_read_buffer_at_offset(f, buf, n, off, ctypes.byref(err))
        out.write(buf.raw[:got])
        off += got

lib.libvhdi_file_close(f, ctypes.byref(err))
lib.libvhdi_file_free(ctypes.byref(f), ctypes.byref(err))
```

Разметка и файлы:

```
$ fls -r -p -o 128 /tmp/opencode/disk.raw
d/d 43-144-1: ProgramData/Microsoft/Windows/WER/ReportQueue/{7b2c8c2e-6c56-4c73-9f5f-2f5b7d1b0d91}
d/d 44-144-1: ProgramData/Microsoft/Windows/WER/ReportQueue/{7b2c8c2e-6c56-4c73-9f5f-2f5b7d1b0d91}/cache
-/r * 45-128-3: $Extend/$Deleted/000100000000002D225258D5
-/r * 47-128-1: $Extend/$Deleted/006400000000002F2497EC1D
-/r * 48-128-1: $Extend/$Deleted/0011000000000030685001B9
-/r * 49-128-1: $Extend/$Deleted/001200000000003136F1BE28
-/r * 50-128-1: $Extend/$Deleted/0004000000000032383F520D
-/r * 51-128-1: $Extend/$Deleted/00560000000000335B070942
-/r * 52-128-1: $Extend/$Deleted/001800000000003476A7D519
```

В `$Extend\$Deleted` найдены удалённые файлы. Шесть из них (inode 47–52) содержат обычные decoy-флаги:

```
flag{decoy-99-1587a236}
flag{decoy-116-f079c264}
flag{decoy-134-d8942e8e}
flag{decoy-138-dd1011b5}
flag{decoy-224-76a013f1}
flag{decoy-248-2fa9f95a}
```

Главная находка — **inode 45**: удалённый файл размером 16 384 байта, нерезидентный `$DATA`, четыре кластера `1417–1420`, сырое смещение `65 536 + 1417 * 4096 = 0x599000`. Содержимое выглядит высокоэнтропийным, без сигнатур. Это и есть удалённый `telemetry.bin`.

```
$ istat -o 128 /tmp/opencode/disk.raw 45
Not Allocated File
Name: 000100000000002D225258D5
Parent MFT Entry: 29  ($Extend\$Deleted)
Allocated Size: 16384   Actual Size: 16384
Type: $DATA (128-3) Non-Resident size: 16384
1417 1418 1419 1420
```

Извлечение:

```
$ icat -o 128 /tmp/opencode/disk.raw 45 > /tmp/opencode/inode45.bin
$ ls -l /tmp/opencode/inode45.bin
-rw-rw-r-- 1 deaddream deaddream 16384 ...
```

### 3.2. Анализ `suspicious_full.dmp`

В дампе найдены командная строка процесса и его аргументы:

```
"C:\Users\rcsi\out\author\20260227_140506\bin\SuspiciousBrief.exe"
  --flag-path "R:\ProgramData\\Microsoft\\Windows\\WER\ReportQueue\{7b2c8c2e-6c56-4c73-9f5f-2f5b7d1b0d91}\cache\telemetry.bin"
  --hold-seconds 90
  --decoy-heap-flags 400
  --xor-key 252
  --flag-offset 7434
  --flag-length 37
```

Ключевые параметры:

- `--xor-key 252` = `0xFC`
- `--flag-offset 7434`
- `--flag-length 37`
- путь к удалённому `telemetry.bin`

Дополнительно в дампе обнаружено:

- **400 decoy-флагов** в UTF-16: `flag{decoy-0-...}` … `flag{decoy-399-...}`;
- закреплённая (pinned) строка конфигурации:

```
cfg:xor=252;off=7434;len=37;path=R:\ProgramData\Microsoft\Windows\WER\ReportQueue\{7b2c8c2e-6c56-4c73-9f5f-2f5b7d1b0d91}\cache\telemetry.bin
```

- .NET-метаданные сборки `SuspiciousBrief.dll` и имена методов: `ParseArgs`, `GetNormalizedPathString`, `MakeDecoyFlag`, `Main`; P/Invoke: `CreateFileW`, `CreateFileMappingW`, `MapViewOfFile`, `DeleteFileW`.

Сборка `SuspiciousBrief.dll` была извлечена из дампа (VA `0x1F401E32000`, смещение в дампе `0x1AF0E4B`) и разобрана по IL. Логика `Main`:

1. Открывает `telemetry.bin` через `CreateFileW` с `GENERIC_READ` и `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
2. Создаёт read-only mapping (`CreateFileMappingW` + `MapViewOfFile`).
3. Удаляет файл через `DeleteFileW`, пока handle/mapping ещё открыты. Файл переезжает в `$Extend\$Deleted`, но его данные остаются доступны через отображение.
4. Создаёт 400 decoy-флагов в куче и закрепляет строку `cfg:xor=...`.
5. Читает **один байт** по смещению `flagOffset` через `Marshal.ReadByte` и удерживает процесс/мэппинг `hold-seconds` (90 секунд).
6. Флаг **не расшифровывается** — программа вообще не выполняет XOR. Она лишь хранит отображение удалённого файла и «подсказку» с ключом/смещением/длиной.

Именно поэтому флаг остаётся XOR-зашифрованным в 16-КБ отображении. В дампе это отображение лежит по смещению `0x3A80E4B` (VA `0x1F403F00000`) и побайтово совпадает с содержимым inode 45 с диска.

## 4. Решение

### Шаг 1. Простой XOR всего дампа с ключом `0xFC`

Дамп целиком пропускается через XOR с `0xFC`, после чего ищется `flag{...}`:

```python
import re

data = open("suspicious_full.dmp", "rb").read()
xored = bytes(b ^ 0xFC for b in data)

for m in re.finditer(rb"flag\{[^}]{1,100}\}", xored):
    print(m.group().decode())
```

Вывод:

```
flag{w3_h4ndl3_i7_by_n07_h4ndling_i7}
```

Найден ровно один флаг. Это и есть ответ.

### Шаг 2. Проверка через 16-КБ файл из дампа

Дополнительно из дампа извлекается 16-КБ отображение по смещению `0x3A80E4B`, и XOR применяется к области `7434..7471`:

```python
blob = open("suspicious_full.dmp", "rb").read()[0x3A80E4B:0x3A80E4B + 0x4000]
flag = bytes(b ^ 0xFC for b in blob[7434:7434 + 37]).decode()
print(flag)
```

Вывод:

```
flag{w3_h4ndl3_i7_by_n07_h4ndling_i7}
```

### Шаг 3. Проверка по удалённому файлу на диске

Тот же результат получается из inode 45, извлечённого с `disk.vhdx`:

```python
blob = open("/tmp/opencode/inode45.bin", "rb").read()
flag = bytes(b ^ 0xFC for b in blob[7434:7434 + 37]).decode()
print(flag)
```

Вывод:

```
flag{w3_h4ndl3_i7_by_n07_h4ndling_i7}
```

Все три пути (весь дамп, 16-КБ отображение, удалённый файл на диске) дают один и тот же флаг.

## 5. Флаг

```
flag{w3_h4ndl3_i7_by_n07_h4ndling_i7}
```

## 6. Выводы

**Что за подозрительный процесс.**  
`SuspiciousBrief.exe` — .NET 8 single-file self-contained приложение (singlefilehost), запущенное из `C:\Users\rcsi\out\author\20260227_140506\bin`. Оно работало с файлом `R:\ProgramData\Microsoft\Windows\WER\ReportQueue\{7b2c8c2e-...}\cache\telemetry.bin`.

**Как он «обрабатывал» флаг.**  
Процесс:

- открыл `telemetry.bin` с правом `FILE_SHARE_DELETE`;
- создал read-only file mapping и `MapViewOfFile`;
- удалил файл, пока отображение было активно (файл попал в `$Extend\$Deleted`, но данные остались в памяти);
- создал 400 ложных флагов в куче;
- закрепил в памяти строку `cfg:xor=252;off=7434;len=37;path=...`;
- прочитал всего один байт по смещению `7434` и удерживал процесс 90 секунд;
- **не выполнял XOR и не материализовал настоящий флаг**.

Флаг остался XOR-зашифрованным (`0xFC`) в отображённом файле. Задача аналитика — найти отображение/удалённый файл и применить XOR самостоятельно. Название «Can YOU handle it?» и сам флаг `w3_h4ndl3_i7_by_n07_h4ndling_i7` («we handle it by not handling it») — прямая отсылка к этой уловке: программа «обрабатывает» флаг тем, что не обрабатывает его, а лишь держит handle на удалённый файл.

**Рекомендации по защите:**

- логировать командные строки процессов (Event ID 4688, Sysmon Event ID 1) и искать подозрительные аргументы вида `--xor-key`, `--flag-offset`, `--flag-path`;
- детектировать связку `CreateFileW` с `FILE_SHARE_DELETE` → `CreateFileMappingW`/`MapViewOfFile` → `DeleteFileW`, особенно для чувствительных файлов;
- включить аудит работы с файлами/handle (Sysmon FileDelete, Object Access Auditing) и хранить полные дампы памяти короткоживущих процессов;
- при инциденте сохранять `$MFT`, `$UsnJrnl`, `$LogFile` и unallocated space — удалённый, но отображённый файл может быть восстановлен как из памяти, так и с диска;
- не хранить секреты в предсказуемых путях вроде `ProgramData\...\WER\...\cache`; использовать ACL/EFS/DPAPI и ротацию секретов;
- применять YARA-правила для поиска XOR-обфусцированных маркеров (`flag{`, `CTF{`) и строки `cfg:xor=` в дампах памяти.

**Итог:** флаг — `flag{w3_h4ndl3_i7_by_n07_h4ndling_i7}`.
