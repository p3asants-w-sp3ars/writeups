#!/usr/bin/env python3
import argparse
import hashlib
import struct
import subprocess
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


P = 251


def read_tape(path):
    data = path.read_bytes()
    if data[:13] != b"SEXTA3\0\0\x03\0\xfb\0\x08" or data[17] != 1:
        raise ValueError("Unexpected Sexta header")

    depth, night_count, morning_count, seal = data[13:17]
    count, reference = struct.unpack_from("<HH", data, 18)
    offset = 22
    tables = []
    for size in (night_count, morning_count):
        tables.append([data[i:i + 28] for i in range(offset, offset + 28 * size, 28)])
        offset += 28 * size

    observations = []
    for _ in range(count):
        observations.append((data[offset:offset + 8], data[offset + 8],
                             data[offset + 9:offset + 17]))
        offset += 17

    nonce = data[offset:offset + 12]
    tag = data[offset + 12:offset + 28]
    size, = struct.unpack_from("<H", data, offset + 28)
    ciphertext = data[offset + 30:]
    if len(ciphertext) != size:
        raise ValueError("Unexpected capsule length")

    return depth, seal, reference, tables, observations, (nonce, ciphertext + tag)


def connector_matrix(observations):
    matrix = []
    for channel in range(8):
        equations = [list(start) + [1, end[channel]]
                     for start, mask, end in observations if mask >> channel & 1]
        for col in range(9):
            pivot = next((i for i in range(col, len(equations)) if equations[i][col]), None)
            if pivot is None:
                raise ValueError(f"Channel {channel} has too few independent readings")
            equations[col], equations[pivot] = equations[pivot], equations[col]
            factor = pow(equations[col][col], -1, P)
            row = [value * factor % P for value in equations[col]]
            equations[col] = row
            for i, other in enumerate(equations):
                if i != col:
                    equations[i] = [(x - other[col] * y) % P for x, y in zip(other, row)]
        if any(row[-1] for row in equations[9:]):
            raise ValueError(f"Readings disagree for channel {channel}")
        matrix.append([row[-1] for row in equations[:9]])
    return matrix


def matching_journals(depth, seal, tables, start, matrix):
    inputs = [depth, *(len(table) for table in tables), seal]
    inputs.extend(value for table in tables for limb in table for value in limb)
    inputs.extend(start)
    inputs.extend(value for row in matrix for value in row)
    source = Path(__file__).with_suffix(".cpp")
    with tempfile.TemporaryDirectory() as directory:
        solver = Path(directory) / "search"
        subprocess.run(["c++", "-O3", "-std=c++17", str(source), "-o", str(solver)], check=True)
        result = subprocess.check_output([str(solver)], input=" ".join(map(str, inputs)), text=True)
    for line in result.splitlines():
        order, *values = map(int, line.split())
        yield order, values[:depth], values[depth:2 * depth], values[2 * depth:]


def replay(start, watches):
    state = list(start)
    trace = []
    for table, journal in watches:
        for index in journal:
            a, b, c, d = [table[index][i:i + 7] for i in range(0, 28, 7)]
            for i in range(7):
                state[i + 1] = (state[i + 1] + a[i] * state[i] + b[i]) % P
            for i in range(6, -1, -1):
                state[i] = (state[i] + c[i] * state[i + 1] + d[i]) % P
            trace.append(bytes(state))
    return trace


def solve(path):
    depth, seal, reference, tables, observations, (nonce, capsule) = read_tape(path)
    start = observations[reference][0]
    matrix = connector_matrix(observations)
    for order, first, second, wiring in matching_journals(depth, seal, tables, start, matrix):
        watches = [(tables[order], first), (tables[1 - order], second)]
        trace = replay(start, watches)
        if sum(trace[depth - 1]) % P != seal:
            continue
        for sample, mask, reading in observations:
            end = replay(sample, watches)[-1]
            if any(reading[j] != end[wiring[j]] for j in range(8) if mask >> j & 1):
                break
        else:
            material = (b"SEXTA/handover/3\0" + start + trace[-1]
                        + bytes([order, *first, *second]) + b"".join(trace))
            key = hashlib.sha256(material).digest()
            try:
                flag = AESGCM(key).decrypt(nonce, capsule, b"SEXTA/meridian/3")
            except InvalidTag:
                continue
            print(f"order={order} first={first} second={second}")
            print(f"wiring={wiring} seal={seal} observations={len(observations)}")
            print(flag.decode("ascii"))
            return
    raise ValueError("No journal passed the replay and capsule checks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("tape", type=Path)
    solve(parser.parse_args().tape)
