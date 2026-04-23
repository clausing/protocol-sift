# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Investigation Type:** Linux Host Incident Response

---

## Case Overview

| Field | Value |
|-------|-------|
| **Client** | <!-- Client name --> |
| **Host(s)** | <!-- hostname(s) + role: web server / jump host / build server / etc. --> |
| **OS / Distro** | <!-- Ubuntu 22.04 / Debian 11 / RHEL 8 / etc. --> |
| **Kernel** | <!-- output of uname -r — required for Volatility 3 Linux symbol generation --> |
| **Init System** | <!-- systemd / SysV --> |
| **Filesystem** | <!-- ext4 / xfs / btrfs / LVM+ext4 / LVM+xfs --> |
| **Auditd Configured** | <!-- Yes (with execve rules) / Yes (minimal) / No / Unknown --> |
| **Domain Joined** | <!-- No / AD via SSSD (domain.corp) / AD via winbind / LDAP only --> |
| **Timezone** | <!-- e.g. America/New_York — affects syslog/auth.log timestamps; journald/auditd can be read in UTC regardless --> |
| **Threat Actor** | <!-- Name or designation if known --> |
| **Incident Declared** | <!-- YYYY-MM-DD UTC --> |
| **Your Role** | External IR consultant |

---

## Evidence Files

| File | System | Notes |
|------|--------|-------|
| `/cases/<case>/disk.E01` | <!-- hostname --> | Full disk (<!-- ~X GB -->) |
| `/cases/<case>/memory.lime` | <!-- hostname --> | LiME memory image (<!-- X GB -->) |

**Read-only — do NOT modify evidence files.**
Output all analysis to `./analysis/`, `./exports/`, or `./reports/` relative to this directory.

---

## Common Commands

### Mount image (read-only)

```bash
sudo mkdir -p /mnt/ewf /mnt/linux_mount
sudo ewfmount /cases/<case>/disk.E01 /mnt/ewf

# Inspect partition table and identify filesystem/volume type
sudo mmls /mnt/ewf/ewf1
OFFSET=$(sudo mmls /mnt/ewf/ewf1 | awk '/Linux/{print $3; exit}')
sudo blkid -o value -s TYPE --offset $((OFFSET * 512)) /mnt/ewf/ewf1
# → ext4, xfs, btrfs, or LVM2_member
```

**ext4 (simple partition):**
```bash
sudo mount -o ro,loop,nosuid,noexec,nodev,norecovery,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
```

**XFS (simple partition — no TSK filesystem tools available):**
```bash
sudo mount -o ro,loop,nosuid,noexec,nodev,norecovery,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
# Use mounted path + find/Plaso for timeline; skip fls/icat/mactime
```

**Btrfs (check subvolumes after initial mount):**
```bash
sudo mount -o ro,loop,nosuid,noexec,nodev,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
sudo btrfs subvolume list /mnt/linux_mount   # usually shows @ as root subvol
sudo umount /mnt/linux_mount
sudo mount -o ro,loop,nosuid,noexec,nodev,subvol=@,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
```

**LVM (when blkid returns LVM2_member):**
```bash
LOOP=$(sudo losetup -f --show /mnt/ewf/ewf1)
sudo kpartx -av "$LOOP"            # creates /dev/mapper/loopXpY devices
sudo pvscan && sudo vgscan
sudo vgchange -ay                  # activate volume group(s)
sudo lvs                           # list logical volumes + VG names
sudo mount -o ro,nosuid,noexec,nodev,norecovery /dev/vgname/lvname /mnt/linux_mount  # ext4, XFS
# sudo mount -o ro,nosuid,noexec,nodev /dev/vgname/lvname /mnt/linux_mount            # Btrfs only

# Cleanup
sudo umount /mnt/linux_mount
sudo vgchange -an vgname
sudo kpartx -dv "$LOOP"
sudo losetup -d "$LOOP"
sudo umount /mnt/ewf
```

```bash
# Verify and identify distro (all filesystem types)
ls /mnt/linux_mount/
cat /mnt/linux_mount/etc/os-release
cat /mnt/linux_mount/etc/machine-id
df -Th /mnt/linux_mount

# System timezone — syslog/auth.log timestamps reflect this; journald/auditd readable in UTC regardless
cat /mnt/linux_mount/etc/timezone 2>/dev/null        # Debian/Ubuntu; may not exist on RHEL
ls -la /mnt/linux_mount/etc/localtime                # symlink target shows TZ on modern distros
# If /etc/localtime is a binary zoneinfo copy (not a symlink):
# strings /mnt/linux_mount/etc/localtime | tail -2
```

### Volatility 3 (Linux memory)

```bash
VOL="python3 /opt/volatility3-2.20.0/vol.py"
IMG="/cases/<case>/memory.lime"

# Verify symbol table loaded correctly (run this first)
$VOL -f $IMG linux.info

# Process enumeration
$VOL -f $IMG linux.pslist | tee ./exports/pslist.txt
$VOL -f $IMG linux.psaux  | tee ./exports/psaux.txt

# Rootkit checks (run on every Linux case)
$VOL -f $IMG linux.check_syscall | tee ./exports/check_syscall.txt
$VOL -f $IMG linux.check_modules | tee ./exports/check_modules.txt
$VOL -f $IMG linux.check_creds   | tee ./exports/check_creds.txt
$VOL -f $IMG linux.tty_check     | tee ./exports/tty_check.txt
$VOL -f $IMG linux.netfilter     | tee ./exports/netfilter.txt

# Bash history from memory (survives even if .bash_history was cleared)
$VOL -f $IMG linux.bash | tee ./exports/memory_bash_history.txt

# Network connections
$VOL -f $IMG linux.netstat | tee ./exports/memory_netstat.txt
```

> **Symbol table:** Volatility 3 Linux requires a per-kernel ISF file.
> Priority: (1) pre-built from https://github.com/Abyss-W4tcher/volatility3-symbols;
> (2) `btf2json` from the kernel's embedded BTF data (kernels ≥ 5.2, no debug package needed);
> (3) `dwarf2json` from the kernel debug package (fallback for older kernels).
> See `LINUX_IR_PLAN.md` § Linux Symbol Requirements for commands.

### Linux artifact extraction

```bash
# See @~/.claude/skills/linux-artifacts/SKILL.md for full extraction commands

# Quick: extract key artifacts
sudo mkdir -p ./exports/{etc,logs,journal,audit,shell_history,cron,systemd,ssh_keys,staging}

sudo cp -rp /mnt/linux_mount/etc/passwd /mnt/linux_mount/etc/shadow \
            /mnt/linux_mount/etc/group  /mnt/linux_mount/etc/sudoers \
            /mnt/linux_mount/etc/ssh/   ./exports/etc/ 2>/dev/null

sudo cp -rp /mnt/linux_mount/var/log ./exports/logs/

MACHINE_ID=$(cat /mnt/linux_mount/etc/machine-id)
sudo find /mnt/linux_mount/var/log/journal -name "*.journal" \
  -exec cp --parents {} ./exports/journal/ \; 2>/dev/null
```

### Log analysis

```bash
# Auth log (Debian/Ubuntu: auth.log; RHEL: secure)
grep "Accepted\|Failed\|sudo:" \
  /mnt/linux_mount/var/log/auth.log 2>/dev/null | \
  tee ./exports/auth_events.txt

# Systemd journal (offline — critical: use --directory, not live system)
MACHINE_ID=$(cat /mnt/linux_mount/etc/machine-id)
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  --since "<!-- YYYY-MM-DD -->" --utc --no-pager | \
  tee ./exports/journal_full.txt

# Login history
last  -F -f /mnt/linux_mount/var/log/wtmp | tee ./exports/wtmp_logins.txt
lastb -F -f /mnt/linux_mount/var/log/btmp | tee ./exports/btmp_failed.txt 2>/dev/null
```

### Plaso timeline

```bash
# Full Linux image ingest
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_linux.plaso \
  --parsers linux \
  --hashers md5 \
  --timezone UTC \
  /mnt/linux_mount/

# Export timeline
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_timeline.csv \
  ./analysis/<CASE_ID>_linux.plaso
```

---

## Network Topology

| Network | Subnet | Key Hosts |
|---------|--------|-----------|
| <!-- name --> | <!-- CIDR --> | <!-- hostname / role --> |

**External attacker IP(s):** <!-- if known -->

---

## Key Accounts

| Account | UID / Domain | Type | Role / Notes |
|---------|--------------|------|-------------|
| root | 0 | Local | System root |
| <!-- account --> | <!-- uid or DOMAIN\user --> | Local / AD | <!-- role --> |

> If the host is domain-joined, AD accounts appear in auth.log/secure and wtmp but
> **not** in `/etc/passwd` (unless cached). Check `/etc/sssd/sssd.conf` for the domain
> and `/var/log/sssd/` for auth events.

---

## Known IOCs

### Confirmed Artifacts

| Indicator | Type | Detail |
|-----------|------|--------|
| `<!-- sha256 -->` | ELF hash | <!-- binary at /tmp/... --> |
| `<!-- ip:port -->` | C2 endpoint | <!-- observed in netstat / auth.log --> |
| `<!-- /path/to/file -->` | Persistence | <!-- cron / systemd / authorized_keys --> |

### Attacker Activity

| Indicator | Detail |
|-----------|--------|
| <!-- technique --> | <!-- detail --> |

---

## Incident Timeline (UTC)

| Timestamp (UTC) | Event |
|-----------------|-------|
| <!-- YYYY-MM-DD HH:MM:SS --> | <!-- event description --> |

---

## Notes

- Kernel version: `<!-- uname -r -->` — required for Volatility 3 symbol file
- Distro family determines log paths: Debian/Ubuntu → `auth.log`; RHEL → `/var/log/secure`
- Auditd: <!-- configured with execve rules / minimal / not running --> — impacts
  availability of command execution evidence
- **Always check `/etc/ld.so.preload` immediately** — a non-empty file is a critical indicator
- Timestamps: always report in UTC
- Vol3 binary: `/opt/volatility3-2.20.0/vol.py`
- Do NOT write to `/mnt/`, `/cases/`, or evidence directories
