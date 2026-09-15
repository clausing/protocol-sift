# Real Audit Log — Implementation Plan

Status: **Implemented.** Scope: Bash + Write, hash-chain only, `Stop` hook
dropped (see "Decisions (resolved)" below). Not yet exercised against a real
case directory — see Testing / verification plan.

This captures the gap analysis and proposed changes to turn
`./analysis/forensic_audit.log` from a model-authored end-of-session narrative
into an automatic, contemporaneous, tamper-evident record of every tool
invocation during a case.

---

## Background — what exists today

- The only hook configured anywhere in this repo is `Stop`
  (`global/settings.json:162-173`), which appends one line —
  `SESSION-CLOSED <timestamp> <pwd>` — via a plain `echo`.
- The actual "audit" content is entirely dependent on the model choosing to
  write one structured narrative block — timestamp, case dir, artifacts
  examined, tools run, findings — before delivering final findings
  (`global/CLAUDE.md:28-42`). There is no automatic, per-command, machine-written
  entry today.
- **Confirmed against the Claude Code hooks docs:** `Stop` fires at the end of
  *every* agent turn, not at true session/process exit. So today's
  `SESSION-CLOSED` line is written repeatedly throughout an investigation, not
  once at the real end — a pre-existing labeling bug, independent of this
  project. `SessionEnd` is a distinct, separate hook event meant for true
  session termination (matcher values: `clear`, `resume`, `logout`,
  `prompt_input_exit`, `other`); `SessionStart` is its counterpart
  (`startup`, `resume`, `clear`, `compact`, `fork`).
- `global/settings.json` installs to `~/.claude/settings.json` — one file,
  shared across every case directory on the box (`install.sh`). There is no
  per-case `settings.json`, so hooks must live in the global file.
- Raw tool *output* is already preserved separately, per the existing
  chain-of-custody convention: Bash invocations pipe through `tee` into
  `./exports/` (`README.md:412-419`), and `Write` calls (reports, derived
  CSV/JSON, scripts) go to `./analysis/`, `./exports/`, or `./reports/`
  (`global/CLAUDE.md:24`). Neither of those currently has any automatic
  provenance record — only the model's own narrative.

## Design goals

1. **Automatic** — every logged event is written by a hook, not by the model
   choosing to report it.
2. **Contemporaneous** — written at/near the time of the call, not batched at
   the end of the session.
3. **Complete enough to matter, without being noisy** — cover the two
   categories of evidentiary action (tool execution, artifact authorship)
   without logging every file glance.
4. **Tamper-evident** — an edited or deleted entry should be detectable.
5. **Attributable** — who/what/when/where for every entry, in UTC.
6. **Independent of the LLM's narrative** — the model's summary can still
   exist, but as a labeled companion, not the source of truth.

---

## Scope decision (leaning: Bash + Write)

Bash and Write are not redundant with each other:

- **Bash** covers every actual forensic tool invocation (`vol.py`,
  `log2timeline.py`, `ausearch`, `yara`, mounts, etc.) — including the
  `tee ... ./exports/...` redirects that already preserve raw tool output, since
  those are just part of the logged Bash command string.
- **Write** covers content the model authors directly — derived CSV/JSON in
  `./analysis/`, custom scripts, and final reports in `./reports/`. This
  currently has **zero** automatic record. Skipping it leaves the most
  court-relevant artifacts (the actual report) with no provenance beyond the
  model's own say-so.

Noise/cost estimate:
- Event count: Bash calls per session run dozens–low hundreds; Write calls are
  far fewer (single digits–~20). Adding Write is a small fraction more events.
- Log size: the `Write` tool's hook payload includes full file content. To
  avoid bloating the log, Write events should record `file_path` +
  `sha256(content)` + byte length, **not** the content itself — still
  tamper-evident (a later edit to that file is caught by hash mismatch)
  without duplicating file contents into the log.

**Not in scope:** `Read` events. Logging every file glance at evidence would be
high-volume and low forensic value relative to Bash+Write; can be revisited if
a case specifically needs full read provenance.

---

## Summary of changes

| Priority | Type | File | Change | Status |
|----------|------|------|--------|--------|
| Critical | **New** | `analysis-scripts/audit_hook.py` | Reads hook JSON from stdin, appends one JSONL line to `./analysis/forensic_audit.log` per event; hash-chained | Done |
| Critical | Update | `global/settings.json` | Add `PreToolUse`/`PostToolUse` hooks (matcher `Bash, Write`), `SessionStart`, `SessionEnd` | Done |
| Important | Update | `install.sh` | Install `audit_hook.py` + `verify_audit_log.py` into `~/.claude/analysis-scripts/` alongside `md2pdf.py` | Done |
| Important | Update | `global/CLAUDE.md` | Redirect model-authored narrative summary to `./reports/session_summary.md`, labeled as analyst commentary, not evidence | Done |
| Important | Update | `README.md` | Rewrite "Notes on Chain of Custody" to describe the two-tier system (hook log = ground truth, session summary = narrative) | Done |
| Important | New | `analysis-scripts/verify_audit_log.py` | Recompute hash chain, report first broken line | Done |
| Important | Update | `global/settings.json` | Remove existing `Stop` hook (superseded by `SessionEnd`, which is the correct true-session-close event) | Done |
| Fix | Update | `LINUX_IR_PLAN.md` | Mirror this plan's status (existing repo convention) | Done |
| Unverified | — | — | `PostToolUse` payload's exact `tool_response` fields for Bash (exit code/stdout/stderr) were not confirmed against a live payload — `audit_hook.py` handles this defensively (`truncate()` on whatever `tool_response` contains, capped at 2000 chars, hashed if larger) rather than assuming specific field names. **Not yet exercised against a real session** — see Testing / verification plan | Needs live verification |

---

## Decisions (resolved)

1. **Tamper-evidence strength: hash-chain only.** No `chattr +a` — no root
   requirement, no finalize/rotate procedure to document. Each JSONL line
   still carries `sha256(prev_hash + this_line)`, so any post-hoc edit or
   deletion is detectable via `verify_audit_log.py`; it just isn't blocked
   in real time.
2. **Existing `Stop` hook: dropped.** `SessionEnd` now provides the correct,
   single true-session-close event; the per-turn `Stop` marker was a
   mislabeled workaround for `SessionEnd` not being wired up, and is removed
   rather than kept/renamed.

---

## Actual log format (as emitted by `audit_hook.py`)

JSONL, one object per line, in `./analysis/forensic_audit.log`. Every entry
carries `seq`, `ts` (UTC), `session_id`, `phase`, `prev_hash`, and `hash` —
`hash` is `sha256(canonical_json(entry_without_hash_field))`, so it commits to
`prev_hash` and every other field in the same line:

```json
{"seq": 42, "ts": "2026-09-15T14:03:21Z", "session_id": "...", "phase": "pre", "prev_hash": "...", "tool": "Bash", "command": "python3 /opt/volatility3-2.20.0/vol.py -f mem.lime linux.pslist", "hash": "..."}
{"seq": 43, "ts": "2026-09-15T14:03:24Z", "session_id": "...", "phase": "post", "prev_hash": "...", "tool": "Bash", "tool_response": "<truncate()'d — see Unverified row above>", "hash": "..."}
{"seq": 44, "ts": "2026-09-15T14:05:02Z", "session_id": "...", "phase": "pre", "prev_hash": "...", "tool": "Write", "file_path": "./reports/findings.md", "content": {"present": true, "chars": 8422, "sha256": "..."}, "hash": "..."}
```

Session bookends:

```json
{"seq": 0, "ts": "...", "session_id": "...", "phase": "session_open", "prev_hash": "0000...0000", "source": "startup", "host": "...", "user": "...", "claude_version": "...", "hash": "..."}
{"seq": 99, "ts": "...", "session_id": "...", "phase": "session_close", "prev_hash": "...", "reason": "prompt_input_exit", "hash": "..."}
```

`post` entries are not explicitly linked to their `pre` entry by id (no
`ref_seq`) — they're correlated positionally in the log (the next `post` for
a given `tool` after a `pre`). Verify with:
`python3 ~/.claude/analysis-scripts/verify_audit_log.py [path]`.

---

## Testing / verification plan (once implemented)

- Dry-run in a scratch (non-case) directory: confirm `PreToolUse`/`PostToolUse`
  fire for Bash and Write, confirm valid JSONL, confirm the hash chain
  validates via `verify_audit_log.py`.
- Confirm a full session produces exactly one `session_open` and one
  `session_close` entry, not one per turn.
- Confirm a denied/blocked Bash attempt still produces a `pre` entry (attempt
  is on record even if execution didn't happen).
- Confirm the logger never blocks a real tool call on its own failure (hook
  script must be defensive — always exit 0 for logging purposes).
