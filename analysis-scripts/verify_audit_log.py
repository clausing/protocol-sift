#!/usr/bin/env python3
"""Verify the hash chain in a forensic_audit.log written by audit_hook.py.

Usage: verify_audit_log.py [path/to/forensic_audit.log]
Defaults to ./analysis/forensic_audit.log

Exits 0 if every entry's hash and prev_hash chain correctly, in sequence
order, with no gaps. Exits 1 and reports the first broken line otherwise —
that line is where an entry was altered, deleted, or reordered.
"""
import hashlib
import json
import sys

GENESIS_HASH = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./analysis/forensic_audit.log"
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line for line in (raw.strip() for raw in f) if line]
    except FileNotFoundError:
        print(f"FAIL: {path} does not exist")
        sys.exit(1)

    if not lines:
        print(f"OK: {path} is empty (no entries to verify)")
        sys.exit(0)

    expected_prev = GENESIS_HASH
    expected_seq = 0
    for lineno, raw in enumerate(lines, start=1):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"FAIL: line {lineno}: invalid JSON ({exc})")
            sys.exit(1)

        if entry.get("prev_hash") != expected_prev:
            print(
                f"FAIL: line {lineno} (seq={entry.get('seq')}): prev_hash mismatch — "
                f"expected {expected_prev}, found {entry.get('prev_hash')}"
            )
            sys.exit(1)

        stored_hash = entry.get("hash")
        recomputed = sha256_hex(canonical({k: v for k, v in entry.items() if k != "hash"}))
        if stored_hash != recomputed:
            print(f"FAIL: line {lineno} (seq={entry.get('seq')}): hash mismatch — entry has been altered")
            sys.exit(1)

        if entry.get("seq") != expected_seq:
            print(
                f"FAIL: line {lineno}: seq mismatch — expected {expected_seq}, "
                f"found {entry.get('seq')} (missing or reordered entry)"
            )
            sys.exit(1)

        expected_prev = stored_hash
        expected_seq += 1

    print(f"OK: {len(lines)} entries verified, chain intact, seq 0..{expected_seq - 1}")
    sys.exit(0)


if __name__ == "__main__":
    main()
