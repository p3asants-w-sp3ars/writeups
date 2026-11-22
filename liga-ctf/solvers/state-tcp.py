#!/usr/bin/env python3
import argparse
import base64
import json
import re
import subprocess
import zlib
from collections import defaultdict
from pathlib import Path


MASK32 = (1 << 32) - 1
WIRE = {
    1: ([2, 0, 1], 3, 5, [73, 35, 167]),
    2: ([1, 2, 0], 11, 7, [211, 86, 29]),
    3: ([0, 2, 1], 6, 3, [142, 61, 196]),
}


def read_labels(path):
    hits, misses = path.read_text().split("Сработки:", 1)[1].split("Пропуски:", 1)
    return tuple(set(re.findall(r"^(\d+)\s+(d\d+)$", text, re.M))
                 for text in (hits, misses))


def read_http(buffer):
    start = min(buffer)
    data = bytes(buffer[i] for i in range(start, max(buffer) + 1))
    while data:
        head, data = data.split(b"\r\n\r\n", 1)
        line, *headers = head.decode("ascii").split("\r\n")
        headers = dict(header.split(":", 1) for header in headers)
        headers = {key.lower(): value.strip() for key, value in headers.items()}
        size = int(headers.get("content-length", "0"))
        if size > len(data):
            raise ValueError("Truncated HTTP body")
        body, data = data[:size], data[size:]
        yield line, headers, body


def read_exchanges(pcap, ports):
    command = ["tshark", "-n", "-r", str(pcap), "-Y", "tcp.len > 0", "-T", "fields"]
    for field in ("tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.payload"):
        command.extend(("-e", field))

    streams = defaultdict(dict)
    for line in subprocess.check_output(command, text=True).splitlines():
        stream, src, dst, seq, payload = line.split("\t")
        if src in ports and dst == "80":
            port, direction = src, "request"
        elif dst in ports and src == "80":
            port, direction = dst, "response"
        else:
            continue

        buffer = streams[port, stream, direction]
        for position, byte in enumerate(bytes.fromhex(payload), int(seq)):
            if buffer.setdefault(position, byte) != byte:
                raise ValueError("Conflicting TCP retransmission")

    for port, stream, direction in streams:
        if direction == "request":
            requests = read_http(streams[port, stream, "request"])
            responses = read_http(streams[port, stream, "response"])
            yield port, zip(requests, responses, strict=True)


def rotate_left(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & MASK32


def unpack(wire, mode, seed, seq):
    if len(wire) != 48:
        raise ValueError("Unexpected record length")
    order, bias, step, salt = WIRE[mode]
    state = (seed ^ ((seq + 1) * 0x9E3779B9)) & MASK32
    raw = bytearray(48)
    for slot, block in enumerate(order):
        shift = (seq + bias + step * slot + ((seed >> (3 * (slot + 1))) & 15)) & 15
        for i in range(16):
            state = (state * 1664525 + 1013904223) & MASK32
            raw[16 * block + ((i + shift) & 15)] = (
                wire[16 * slot + i] ^ (state >> 24) ^ salt[slot]
            )
    return raw


def restore_records(exchanges):
    mode = seed = seq = 0
    pending = {}
    seen = set()
    cache = {}
    records = {}
    for (request, q_headers, body), (response, a_headers, result) in exchanges:
        path = request.split()[1]
        status = int(response.split()[1])
        event = q_headers.get("x-request-id")

        if path in ("/open", "/reset") and status == 201:
            session = json.loads(result)
            mode, seed, seq = session["mode"], int(session["nonce"], 16), 0
            pending.clear()
            seen.clear()
            cache.clear()
            continue

        if path == "/gate/v3":
            wire = base64.b64decode(body, validate=True)
            if event not in cache:
                cache[event] = wire
                records[event] = unpack(wire, mode, seed, seq)
            elif cache[event] != wire:
                raise ValueError(f"Wire body changed on retry of {event}")

        if path == "/switch":
            if status == 409:
                pending.pop(event, None)
            else:
                pending[event] = json.loads(body)
        change = pending.pop(a_headers.get("x-commit"), None)
        if change is not None:
            mode = change["mode"]
            seed = rotate_left(seed ^ int(change["salt"], 16), 11)
        if (path == "/gate/v3" and status == 204
                and a_headers.get("x-receipt") == event and event not in seen):
            mixed = seed ^ zlib.crc32(wire) ^ int(a_headers["x-ratchet"], 16)
            seed = (rotate_left(mixed, 7) + 0x6D2B79F5) & MASK32
            seq += 1
            seen.add(event)

    return records


def xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def find_signature(records, hits, misses):
    candidates = []
    for i, j in ((0, 16), (0, 32), (16, 32)):
        values = {key: xor(raw[i:i + 16], raw[j:j + 16])
                  for key, raw in records.items()}
        positives = {values[key] for key in hits}
        if len(positives) == 1 and positives.isdisjoint(values[key] for key in misses):
            candidates.append(positives.pop())
    signature, = candidates
    return signature


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("note", type=Path)
    args = parser.parse_args()
    hits, misses = read_labels(args.note)
    labels = hits | misses
    records = {}
    for port, exchanges in read_exchanges(args.pcap, {port for port, _ in labels}):
        for event, record in restore_records(exchanges).items():
            records[port, event] = record
    if set(records) != labels or hits & misses:
        raise ValueError("Record IDs do not match the note")

    signature = find_signature(records, hits, misses)
    print(f"{len(hits)} сработок, {len(misses)} пропусков: {signature.hex()}")
    decoded = xor(signature, b"TSPU" * 4)
    print((decoded[3:] + decoded[:3]).decode("ascii"))


if __name__ == "__main__":
    main()
