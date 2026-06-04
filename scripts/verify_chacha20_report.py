from __future__ import annotations

import html
from pathlib import Path


MASK = 0xFFFFFFFF


def rotl32(x: int, n: int) -> int:
    return ((x << n) & MASK) | (x >> (32 - n))


def quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 16)

    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 12)

    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 8)

    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 RFC 8439 nonce must be 12 bytes")

    def le32(chunk: bytes) -> int:
        return int.from_bytes(chunk, "little")

    state = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
    ]
    state += [le32(key[i : i + 4]) for i in range(0, 32, 4)]
    state += [counter & MASK]
    state += [le32(nonce[i : i + 4]) for i in range(0, 12, 4)]

    working_state = state[:]
    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    return b"".join(
        ((working_state[i] + state[i]) & MASK).to_bytes(4, "little")
        for i in range(16)
    )


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    ciphertext = bytearray()
    offset = 0

    while offset < len(plaintext):
        keystream = chacha20_block(key, counter, nonce)
        block = plaintext[offset : offset + 64]
        ciphertext.extend(p ^ k for p, k in zip(block, keystream))
        offset += len(block)
        counter = (counter + 1) & MASK

    return bytes(ciphertext)


def split_markdown_row(line: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for ch in line.strip():
        if escaped:
            if ch == "|":
                current.append("|")
            else:
                current.append("\\")
                current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "|":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    if escaped:
        current.append("\\")

    parts.append("".join(current).strip())

    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]

    return parts


def find_report() -> Path:
    reports = list(Path(".").glob("ChaCha20_*.md"))
    if len(reports) != 1:
        raise RuntimeError(f"Expected exactly one ChaCha20 report, found: {reports}")
    return reports[0]


def parse_report_rows(report: Path) -> list[tuple[int, list[str]]]:
    rows: list[tuple[int, list[str]]] = []
    text = report.read_text(encoding="utf-8")

    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("|"):
            continue

        columns = split_markdown_row(line)
        if len(columns) == 5 and columns[0].startswith("2b7e"):
            rows.append((line_no, columns))

    return rows


def main() -> int:
    report = find_report()
    rows = parse_report_rows(report)
    failures: list[tuple[int, str, int, str, str, int]] = []

    for line_no, (key_hex, nonce_hex, counter_text, plaintext_text, ciphertext_hex) in rows:
        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        counter = int(counter_text)

        if plaintext_text == "-" and ciphertext_hex == "-":
            plaintext = b""
            expected = b""
        else:
            plaintext = html.unescape(plaintext_text).encode("utf-8")
            expected = bytes.fromhex(ciphertext_hex)

        actual = chacha20_encrypt(key, counter, nonce, plaintext)
        if actual != expected:
            failures.append(
                (
                    line_no,
                    plaintext_text,
                    counter,
                    expected.hex(),
                    actual.hex(),
                    len(plaintext),
                )
            )

    print(f"file={report}")
    print(f"parsed_rows={len(rows)}")
    print(f"checked_rows={len(rows)}")
    print(f"failures={len(failures)}")

    for line_no, plaintext, counter, expected, actual, length in failures:
        print(f"line={line_no} counter={counter} len={length} plaintext={plaintext!r}")
        print(f"  expected={expected}")
        print(f"  actual  ={actual}")

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe")
    nonce = bytes.fromhex("000000000000004a00000000")
    print("keystream_c0_64=" + chacha20_block(key, 0, nonce).hex())
    print("keystream_c1_64=" + chacha20_block(key, 1, nonce).hex())

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
