# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Course:** SANS FOR508 — Advanced Incident Response, Threat Hunting & Digital Forensics
**Scenario:** Stark Research Labs (SRL) — Lab 1.1 APT Incident Response Challenge

---

## Case Overview

| Field | Value |
|-------|-------|
| **Client** | Stark Research Labs (SRL) |
| **Domain** | SHIELDBASE (Windows Server 2022, 2022 DFL) |
| **Threat Actor** | CRIMSON OSPREY (state-level APT) |
| **Incident Declared** | 2023-01-24 |
| **Your Role** | External IR consultant |
| **Initial Responders** | Roger Sydow (IT Admin), Clint Barton (IT Security Analyst) |

---

## Evidence Files

| File | System | Notes |
|------|--------|-------|
| `/cases/srl/base-dc-cdrive.E01` | dc01 — Domain Controller | C: drive (~12.5 GB) |
| `/cases/srl/base-rd01-cdrive.E01` | rd01 — Remote Desktop Server | C: drive (~16.6 GB) — **primary compromise host** |
| `/cases/memory/rd01-memory.img` | rd01 | RAM capture (5 GB, primary analysis image) |
| `/cases/srl/base-rd_memory.img` | rd01 | RAM capture (3 GB, baseline-era image) |
| `/cases/srl/base-dc_memory.img` | dc01 | RAM capture (5 GB) |

**Read-only — do NOT modify evidence files.**
Output all analysis to `./analysis/`, `./exports/`, or `./reports/` (relative to `/cases/srl/`).

---

## Common Commands

### Mount E01 images (read-only)

```bash
# Mount rd01 C: drive
sudo mkdir -p /mnt/ewf_rd01 /mnt/rd01
sudo ewfmount /cases/srl/base-rd01-cdrive.E01 /mnt/ewf_rd01
sudo mount -o ro,loop,noatime /mnt/ewf_rd01/ewf1 /mnt/rd01

# Mount dc01 C: drive
sudo mkdir -p /mnt/ewf_dc01 /mnt/dc01
sudo ewfmount /cases/srl/base-dc-cdrive.E01 /mnt/ewf_dc01
sudo mount -o ro,loop,noatime /mnt/ewf_dc01/ewf1 /mnt/dc01

# Unmount when done
sudo umount /mnt/rd01 && sudo umount /mnt/ewf_rd01
sudo umount /mnt/dc01 && sudo umount /mnt/ewf_dc01
```

### Volatility 3 (memory — rd01)

```bash
VOL="python3 /opt/volatility3-2.20.0/vol.py"
IMG="/cases/memory/rd01-memory.img"

# Human-readable process tree
$VOL -f $IMG -r pretty windows.pstree | cut -d '|' -f 1-11

# All processes incl. exited
$VOL -f $IMG windows.psscan | grep -v "N/A"

# Command lines
$VOL -f $IMG windows.cmdline | tee ./exports/cmdline.txt

# Process SIDs
$VOL -f $IMG windows.getsids | tee ./exports/getsids.txt

# Network connections
$VOL -f $IMG -r csv windows.netstat | tee ./exports/netstat.csv

# DLL list for a specific PID
$VOL -f $IMG -r csv windows.dlllist --pid 1912 | tee ./exports/dlllist-stun.csv
```

### Memory Baseliner (process / service / driver diff)

```bash
python3 /opt/memory-baseliner/baseline.py \
  -proc -i /cases/memory/rd01-memory.img \
  --loadbaseline \
  --jsonbaseline /cases/memory/baseline/Win11x64_proc_baseline.json \
  -o ./exports/proc_baseline_diff.csv
```

### EZ Tools (dotnet, Windows artifacts from mounted image)

```bash
# MFTECmd — parse MFT
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f /mnt/rd01/\$MFT \
  --csv ./exports/ --csvf rd01-mft.csv

# EvtxECmd — parse event logs
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d /mnt/rd01/Windows/System32/winevt/Logs/ \
  --csv ./exports/ --csvf rd01-evtx.csv \
  --maps /opt/zimmermantools/EvtxeCmd/Maps/

# RECmd — registry hives
dotnet /opt/zimmermantools/RECmd/RECmd.dll \
  -d /mnt/rd01/Windows/System32/config/ \
  --csv ./exports/ --csvf rd01-registry.csv

# AmcacheParser
dotnet /opt/zimmermantools/AmcacheParser.dll \
  -f /mnt/rd01/Windows/AppCompat/Programs/Amcache.hve \
  --csv ./exports/ --csvf rd01-amcache.csv
```

### Sleuth Kit (filesystem, no mount required)

```bash
# List files — rd01 image
fls -r -o 2048 /mnt/ewf_rd01/ewf1 | grep -i "stun"

# Extract a file by inode
icat -o 2048 /mnt/ewf_rd01/ewf1 <INODE> > ./exports/stun_extracted.exe

# Verify image
ewfverify /cases/srl/base-rd01-cdrive.E01
```

---

## Network Topology

| Network | Subnet | Key Hosts |
|---------|--------|-----------|
| **Management** | 172.16.8.0/24 | log01, assess01/02, sft01, trust01, adusa01 (ELF01 syslog) |
| **Services** | 172.16.4.0/24 | dc01, file01, exchange01 (Exchange 2019), proxy01 (Squid), dev01, sql01 |
| **Business Line** | 172.16.7.0/24 | wksta01–wksta10 (Windows 11) |
| **R&D** | 172.16.6.0/24 | rd01–rd10 (Windows 11); lateral movement target: **172.16.6.12** |
| **DMZ** | 172.16.19.0/24 | dns01, ftp01, smtp01 |
| **VPN Client** | 172.16.30.0/24 | Remote workers |

**External attacker IP:** 172.15.1.20

---

## Domain Accounts

| Account | Role |
|---------|------|
| `rsydow-a` | Domain Admin — Roger Sydow (IT Admin) |
| `cbarton-a` | Domain Admin — Clint Barton (IT Security Analyst) |
| `srl.admin` | Emergency Domain Admin (break-glass) |
| `srladmin` | Local Admin — all workstations |

---

## Known IOCs

### Confirmed Malware

| Indicator | Type | Detail |
|-----------|------|--------|
| `STUN.exe` | Malware binary | `C:\Windows\System32\STUN.exe`, PID 1912, parent svchost.exe PID 1244 |
| `msedge.exe` | Masquerading | 7 instances from STUN.exe + explorer.exe; Trojan:Win32/PowerRunner.A |
| `pssdnsvc.exe` | Suspicious service | `C:\Windows\` — name/path mismatch for PsShutdown |
| `atmfd.dll` | Missing driver | In Autoruns but absent from filesystem |

### Attacker Activity

| Indicator | Detail |
|-----------|--------|
| Lateral movement | `net use H: \\172.16.6.12\c$\Users` — net.exe PID 9128 |
| Execution | STUN.exe as scheduled task → svchost.exe → taskhostw.exe |
| Evasion | msedge.exe masquerading; Defender detected + terminated repeatedly |

---

## Incident Timeline (UTC)

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2023-01-24 | Incident declared; F-Response agents deployed |
| 2023-01-25 14:52:04 | Lateral movement — `net use H: \\172.16.6.12\c$\Users` |
| 2023-01-25 14:56:42–15:04:43 | msedge.exe PIDs spawned |
| 2023-01-25 15:00:56 | msedge.exe PID 2524 active at memory capture time |
| 2023-01-29 12:23:16 | Kansa post-intrusion collection (Autorunsc timestamp) |

---

## Notes

- **Kansa Autorunsc CSVs** (`rd01/dc01/file01/hunt01`) are on the Windows forensic workstation at `G:\SRL_Evidence\kansa\kansa-post-intrusion\Output_20230129122316\Autorunsc\` — not on this SIFT instance.
- **MemProcFS** is not installed on this SIFT instance.
- **VSCMount** is Windows-only — do not use on SIFT.
- Timestamps: always report in UTC.
- Vol3 binary: `/opt/volatility3-2.20.0/vol.py` — NOT `/usr/local/bin/vol.py` (that is Vol2).
