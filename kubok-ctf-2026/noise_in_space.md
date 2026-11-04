---
title: "Noise in space"
ctf: "Кубок CTF 2026"
author: "anci31d"
date: 2026-11-01
category: reverse
difficulty: medium
points: 327
flag_format: "ctfcup{...}"
---

# Noise in space

## Summary

В архиве даны I/Q-запись `capture.iq`, DSP-виртуальная машина `dsp_vm` и её программа `kernel.kdsp`. Два нулевых параметра в kernel ломают настройку приёмника: первый должен быть `25000`, второй затирает вычисленное значение `3600`. После двух исправлений VM записывает разборчивый WAV с фразой `Tune the noise`.

## Solution

`kernel.kdsp` состоит из четырёхбайтовых инструкций. В дизассемблированной VM видно, что инструкция по `0x60` загружает параметр в `R3`, который использует следующая операция демодуляции. По смещению `0x88` находится обнуление `R8`; следующая операция использует `R8` для коррекции аудио.

```text
offset  bytes          effect
0x60    00 00 30 01    R3 = 0
0x64    00 30 42 21    demodulate(R2, R3) -> R4
0x88    00 00 80 01    R8 = 0
0x8c    00 80 94 22    transform(R4, R8) -> R9
```

Сначала находим несущую. `capture.iq` — чередующиеся `float32` I/Q-отсчёты с частотой 240 кГц. Спектр даёт максимум около 25 кГц:

```python
x = np.fromfile("capture.iq", dtype="<f4")
iq = x[::2] + 1j * x[1::2]
frequency, power = scipy.signal.welch(iq, fs=240000, nperseg=16384,
                                      return_onesided=False)
print(frequency[np.argmax(power)])  # 25004.8828125
```

Разрешение спектра около 14.65 Гц, поэтому параметр демодулятора — `25000`. Второй параметр вычисляется перед обнулением:

```python
frequency = ((0x1357 ^ 0x2468) + (9 << 4)) ^ 0x39df
assert frequency == 3600
```

Нужные правки kernel:

```python
from pathlib import Path

kernel = bytearray(Path("kernel.kdsp").read_bytes())
assert kernel[0x60:0x64] == bytes.fromhex("00 00 30 01")
assert kernel[0x88:0x8c] == bytes.fromhex("00 00 80 01")

kernel[0x60:0x62] = (25000).to_bytes(2, "little")
# R8 = R8 + 0: сохраняем вычисленные 3600 вместо загрузки нуля.
kernel[0x88:0x8c] = bytes.fromhex("00 00 88 03")
Path("kernel_solved.kdsp").write_bytes(kernel)
```

`25000 = 0x61a8`, поэтому первые два байта инструкции становятся `a8 61`. Вторую инструкцию заменяем на сложение регистра с нулём: вычисленное ранее значение `R8` не меняется.

Далее запускаем поставленную VM на исходной записи и исправленном kernel:

```bash
./dsp_vm capture.iq kernel_solved.kdsp solved.wav
sha256sum solved.wav
```

Полученный WAV — mono PCM 48 kHz; его SHA-256:

```text
69f0eb7fc6e7ef67f5c60fa18ce1093c158aa37a252815f086ef43132a86d08b  solved.wav
```

В записи слышно: `Receiver service message, the calibration phrase follows. Tune the noise.` Поэтому пробелы заменяем подчёркиваниями в формате флага.

## Flag

```text
ctfcup{tune_the_noise}
```
