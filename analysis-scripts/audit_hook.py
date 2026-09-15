#!/usr/bin/env python3
"""Append a hash-chained JSONL entry to ./analysis/forensic_audit.log for one
Claude Code hook event (PreToolUse/PostToolUse/SessionStart/SessionEnd).

Invoked as: audit_hook.py <pre|post|session_open|session_close>
with the hook's JSON payload on stdin.

Must never block the tool call or the session: any internal failure is
swallowed (and noted on stderr) rather than raised, and the process always
exits 0.
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64
LOG_RELPATH = os.path.join("analysis", "forensic_audit.log")
MAX_INLINE_CHARS = 2000  # cap embedded fields (e.g. tool_response) so one noisy event can't blow up the log


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def summarize_bytes(value):
    """Record a large field's hash+length instead of storing it verbatim."""
    if value is None:
        return {"present": False}
    raw = value if isinstance(value, (bytes, bytearray)) else str(value).encode("utf-8")
    return {"present": True, "chars": len(raw), "sha256": sha256_hex(raw)}


def truncate(value, limit=MAX_INLINE_CHARS):
    s = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    if len(s) <= limit:
        return s
    raw = s.encode("utf-8")
    return s[:limit] + f"...<truncated, {len(s)} chars total, sha256={sha256_hex(raw)}>"


def get_claude_version():
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=5)
        return (out.stdout.strip() or out.stderr.strip()) or None
    except Exception:
        return None


def read_last_entry(log_path):
    if not os.path.exists(log_path):
        return None
    last = None
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return None
    try:
        return json.loads(last)
    except json.JSONDecodeError:
        return None


def build_fields(phase, payload):
    if phase in ("pre", "post"):
        tool_name = payload.get("tool_name")
        fields = {"tool": tool_name}
        if phase == "pre":
            tool_input = payload.get("tool_input") or {}
            if tool_name == "Bash":
                fields["command"] = tool_input.get("command")
            elif tool_name == "Write":
                fields["file_path"] = tool_input.get("file_path")
                fields["content"] = summarize_bytes(tool_input.get("content"))
            else:
                fields["tool_input"] = tool_input
        else:
            fields["tool_response"] = truncate(payload.get("tool_response"))
        return fields
    if phase == "session_open":
        return {
            "source": payload.get("source"),
            "host": socket.gethostname(),
            "user": os.environ.get("USER") or os.environ.get("LOGNAME"),
            "claude_version": get_claude_version(),
        }
    if phase == "session_close":
        return {"reason": payload.get("reason")}
    return {"raw": truncate(payload)}


def append_entry(cwd, phase, payload):
    log_path = os.path.join(cwd, LOG_RELPATH)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    prev = read_last_entry(log_path)
    prev_hash = prev["hash"] if prev else GENESIS_HASH
    seq = (prev["seq"] + 1) if prev else 0

    entry = {
        "seq": seq,
        "ts": utc_now(),
        "session_id": payload.get("session_id"),
        "phase": phase,
        "prev_hash": prev_hash,
    }
    entry.update(build_fields(phase, payload))
    entry["hash"] = sha256_hex(canonical(entry))

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "unknown"

    try:
        raw_stdin = sys.stdin.read()
    except Exception:
        raw_stdin = ""
    try:
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
    except Exception:
        payload = {}

    cwd = payload.get("cwd") or os.getcwd()

    try:
        append_entry(cwd, phase, payload)
    except Exception as exc:
        sys.stderr.write(f"audit_hook: failed to log ({exc})\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
