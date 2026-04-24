# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## DFIR Orchestrator — SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |

---

## Operator Preferences

- **NEVER ask questions during a task.** Run every workflow fully autonomously start-to-finish. No check-ins, no confirmations, no "shall I proceed?". Deliver final findings only. If blocked, pick the most reasonable path and note it in the output.

---

## Forensic Constraints

- **No hallucinations** — Never guess, assume, or fabricate forensic artifacts, file contents, or system states.
- **Deterministic execution** — Use court-vetted CLI tools to generate facts; ground all conclusions in raw tool output.
- **Evidence integrity** — Never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — Write all scripts, CSVs, JSON, and reports to `./analysis/`, `./exports/`, or `./reports/`. Never write to `/` or evidence directories.
- **Timestamps** — Always output in UTC.
- **Verification** — Verify tool success after every run. On failure: read stderr → hypothesize → correct → retry.

---

## Installed Tool Paths

| Tool | Invocation | Notes |
|------|-----------|-------|
| **Volatility 3** | `python3 /opt/volatility3-2.20.0/vol.py` | Do NOT use `/usr/local/bin/vol.py` — that is Vol2 |
| **Memory Baseliner** | `python3 /opt/memory-baseliner/baseline.py` | |
| **EZ Tools (root)** | `dotnet /opt/zimmermantools/<Tool>.dll` | Runtime only; no SDK |
| **EZ Tools (subdir)** | `dotnet /opt/zimmermantools/<Subdir>/<Tool>.dll` | e.g. `EvtxeCmd/EvtxECmd.dll` |
| **YARA** | `/usr/local/bin/yara` (v4.1.0) | |
| **Sleuth Kit** | `fls`, `icat`, `ils`, `blkls`, `mactime`, `tsk_recover` | System PATH |
| **EWF tools** | `ewfmount`, `ewfinfo`, `ewfverify` | System PATH |
| **Plaso** | `log2timeline.py`, `psort.py`, `pinfo.py` | GIFT PPA v20240308 |
| **bulk_extractor** | `bulk_extractor` (v2.0.3) | Defaults to 4 threads |
| **photorec** | `sudo photorec` | File carving by signature |
| **dotnet runtime** | `/usr/bin/dotnet` (v6.0.36) | Runtime only — `dotnet --version` will error |
| **blkid** | `sudo blkid -o value -s TYPE --offset $((N*512)) /mnt/ewf/ewf1` | Identify filesystem type at a partition offset before mounting |
| **kpartx** | `sudo kpartx -av /dev/loopX` | Map LVM partitions from loop device — required before `vgchange` |
| **vgchange** | `sudo vgchange -ay` / `sudo vgchange -an <vg>` | Activate / deactivate LVM volume groups |
| **lvs / lvdisplay** | `sudo lvs` | List LVM logical volumes and their device paths |
| **btrfs** | `sudo btrfs subvolume list /mnt/linux_mount` | List Btrfs subvolumes before selecting mount target |
| **journalctl** | `journalctl --directory <path> --utc` | Use `--directory` to read offline journal from mounted evidence |
| **ausearch** | `ausearch -i -f <audit.log>` | Use `-f` for offline audit log; without it reads the live system |
| **aureport** | `aureport --summary -if <audit.log>` | Use `-if` for offline audit log |
| **last / lastb** | `last -F -f <wtmp>` / `lastb -F -f <btmp>` | Login and failed-login history from binary logs |
| **rkhunter** | `sudo rkhunter --check --rootdir /mnt/linux_mount` | Use `--rootdir` for offline mounted image |
| **chkrootkit** | `sudo chkrootkit -r /mnt/linux_mount` | Use `-r` for offline mounted image |
| **btf2json** | `btf2json --btf <vmlinux> --map System.map > output.json` | Preferred ISF generator for kernels ≥5.2 (uses embedded BTF — no debug package needed); repo: github.com/vobst/btf2json |
| **dwarf2json** | `dwarf2json linux --elf <vmlinux>` | Fallback ISF generator for kernels <5.2; requires kernel debug package (linux-image-*-dbg) |

> **Linux memory symbols:** Volatility 3 Linux plugins require a per-kernel ISF
> file — unlike Windows, symbols cannot be auto-downloaded. Priority:
> (1) pre-built from https://github.com/Abyss-W4tcher/volatility3-symbols;
> (2) `btf2json` from embedded BTF (kernels ≥5.2, no debug package needed);
> (3) `dwarf2json` from the kernel debug package (older kernels).

**Not available on this instance:** MemProcFS, VSCMount (Windows-only).

### Shell Aliases (`.bash_aliases`)

```bash
vss_carver            # sudo python /opt/vss_carver/vss_carver.py
vss_catalog_manipulator
lr                    # getfattr -Rn ntfs.streams.list  (list NTFS ADS)
workbook-update       # update FOR508 workbook
```

---

## Tool Routing

> Consult the relevant skill file before executing a forensic utility.

| Domain | Skill File |
|--------|-----------|
| Case scope & metadata | `@./CLAUDE.md` (project working directory) |
| Timeline generation (Plaso) | `@~/.claude/skills/plaso-timeline/SKILL.md` |
| File system & carving (Sleuth Kit) | `@~/.claude/skills/sleuthkit/SKILL.md` |
| Memory forensics (Volatility 3 / Memory Baseliner) | `@~/.claude/skills/memory-analysis/SKILL.md` |
| Windows artifacts (EZ Tools / Event Logs / Registry) | `@~/.claude/skills/windows-artifacts/SKILL.md` |
| Threat hunting & IOC sweeps (YARA / Velociraptor) | `@~/.claude/skills/yara-hunting/SKILL.md` |
| Linux artifacts (logs / persistence / execution) | `@~/.claude/skills/linux-artifacts/SKILL.md` |

EZ Tools prefer native .NET over WINE. GUI tools (TimelineExplorer, RegistryExplorer) require WINE or the Windows analysis VM.
