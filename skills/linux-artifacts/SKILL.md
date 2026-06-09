# Skill: Linux Artifacts (Logs / Persistence / Execution / Rootkits)

## Overview
Use this skill for Linux host-based artifact analysis on the SIFT workstation.
Covers authentication logs, systemd journal, auditd, shell history, persistence
mechanisms, rootkit indicators, and artifact extraction from Linux disk images.

> **Evidence mount assumption:** Commands below use `/mnt/linux_mount` as the
> read-only mount point for the target Linux filesystem. For ext4/XFS/Btrfs/LVM
> mount procedures, see the **Mount Procedures** section below. For `ewfmount`
> and `mmls`, see `@~/.claude/skills/sleuthkit/SKILL.md`.

---

## Filesystem Type Detection

Before extracting artifacts, identify the filesystem type — it determines whether TSK
tools are available and whether LVM activation or Btrfs subvolume handling is needed.

```bash
# After ewfmount — identify filesystem / volume type at the partition level
sudo mmls /mnt/ewf/ewf1

# Probe a specific partition offset for its filesystem type
OFFSET=$(sudo mmls /mnt/ewf/ewf1 | awk '/Linux/{print $3; exit}')
sudo blkid -o value -s TYPE --offset $((OFFSET * 512)) /mnt/ewf/ewf1
# Returns: ext4, xfs, btrfs, LVM2_member, etc.

# After mounting — confirm from the mounted path
df -Th /mnt/linux_mount
```

**Decision table:**

| Result | Action |
|--------|--------|
| `ext4` / `ext3` | Standard mount (`-o ro,loop,offset=...`); TSK tools available |
| `xfs` | Standard mount; **no TSK filesystem tools** — use mounted path + find/Plaso |
| `btrfs` | Mount, list subvolumes, remount with `-o ro,subvol=@`; **no TSK tools** |
| `LVM2_member` | LVM activation required — see **Mount Procedures** section below |

For XFS and Btrfs, all artifact extraction commands in this skill file work as-is
because they target `/mnt/linux_mount/` paths. Only TSK-based filesystem navigation
(`fls`, `icat`, `mactime` via bodyfile) is unavailable.

---

## Mount Procedures (Linux)

> After `ewfmount` surfaces the raw image. `ewfmount` + `mmls` commands are in
> `@~/.claude/skills/sleuthkit/SKILL.md`.

```bash
sudo mkdir -p /mnt/ewf /mnt/linux_mount
sudo ewfmount /cases/<case>/disk.E01 /mnt/ewf/
OFFSET=$(sudo mmls /mnt/ewf/ewf1 | awk '/Linux/{print $3; exit}')
sudo blkid -o value -s TYPE --offset $((OFFSET * 512)) /mnt/ewf/ewf1
```

**ext4 or XFS (simple partition):**
```bash
sudo mount -o ro,loop,nosuid,noexec,nodev,norecovery,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
```

**Btrfs (check subvolumes after initial mount):**
```bash
sudo mount -o ro,loop,nosuid,noexec,nodev,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
sudo btrfs subvolume list /mnt/linux_mount   # usually shows @ as root subvol
sudo umount /mnt/linux_mount
sudo mount -o ro,loop,nosuid,noexec,nodev,subvol=@,offset=$((OFFSET * 512)) /mnt/ewf/ewf1 /mnt/linux_mount
```

**LVM (when `blkid` returns `LVM2_member`):**
```bash
LOOP=$(sudo losetup -f --show /mnt/ewf/ewf1)
sudo kpartx -av "$LOOP"            # creates /dev/mapper/loopXpY devices
sudo pvscan && sudo vgscan
sudo vgchange -ay                  # activate volume group(s)
sudo lvs                           # list logical volumes + VG names
sudo mount -o ro,nosuid,noexec,nodev,norecovery /dev/vgname/lvname /mnt/linux_mount  # ext4, XFS
# sudo mount -o ro,nosuid,noexec,nodev /dev/vgname/lvname /mnt/linux_mount           # Btrfs only

# Cleanup
sudo umount /mnt/linux_mount
sudo vgchange -an vgname
sudo kpartx -dv "$LOOP"
sudo losetup -d "$LOOP"
sudo umount /mnt/ewf
```

---

## UAC Triage Collections

UAC (Unix Artifact Collector — github.com/tclahr/uac) is a live-response triage tool
that produces a tar.gz archive of forensic artifacts without a disk image. When you
have a UAC collection instead of (or alongside) an E01, adapt the workflow as follows.

```bash
# Extract the archive
mkdir -p /cases/<case>/uac
tar -xzf /cases/<case>/uac-<hostname>-<os>-<datetime>.tar.gz -C /cases/<case>/uac/

# Locate the UAC root (top-level extracted directory)
UAC=$(ls -d /cases/<case>/uac/uac-*/ 2>/dev/null | head -1)
ls "$UAC"   # confirm structure before proceeding
```

**Common UAC directory layout (verify with `ls $UAC` — varies by profile):**

| Path | Contents |
|------|----------|
| `$UAC/live_response/process/` | `ps`, `lsof`, `/proc` snapshots — processes at collection time |
| `$UAC/live_response/network/` | `netstat`, `ss`, `ip`, `arp` — network state at collection time |
| `$UAC/live_response/system/` | `uname`, `lsmod`, `sysctl`, `dmesg` |
| `$UAC/live_response/packages/` | `dpkg -l`, `rpm -qa` |
| `$UAC/live_response/hardware/` | `lshw`, `dmidecode` |
| `$UAC/bodyfile/bodyfile.txt` | Pre-generated bodyfile — stage it and run the filesystem timeline pass |
| `$UAC/etc/`, `$UAC/var/`, `$UAC/home/` | Collected files mirroring original paths |

```bash
# Volatile data available in UAC but absent from disk images
cat "$UAC/live_response/process/ps.txt"       2>/dev/null
cat "$UAC/live_response/process/lsof.txt"     2>/dev/null
cat "$UAC/live_response/network/netstat.txt"  2>/dev/null
cat "$UAC/live_response/network/ss.txt"       2>/dev/null
cat "$UAC/live_response/system/lsmod.txt"     2>/dev/null

# /dev/shm and /run contents — captured live by UAC, absent from disk images
ls "$UAC/dev/shm/" 2>/dev/null
ls "$UAC/run/"     2>/dev/null

# Filesystem timeline — if UAC collected a bodyfile, stage it and generate mactime
if [ -f "$UAC/bodyfile/bodyfile.txt" ]; then
  cp "$UAC/bodyfile/bodyfile.txt" ./analysis/bodyfile.txt
  mactime -y -b ./analysis/bodyfile.txt > ./analysis/mactime_y.csv
  echo "Bodyfile staged → ./analysis/bodyfile.txt; mactime → ./analysis/mactime_y.csv"
  # Proceed with the full timeline pass: § Timeline Integration below
fi
```

**Adapting disk-image commands to UAC:** replace `/mnt/linux_mount` with `$UAC`.
Most `grep`, `find`, `cat`, and `awk` commands in this skill work unchanged with
that substitution. Tool-based analysis that requires a mounted block device
(`journalctl --directory`, `last -f`, `ausearch -f`) still works if the relevant
files were collected:

```bash
# Journal — if UAC collected var/log/journal
MACHINE_ID=$(cat "$UAC/etc/machine-id" 2>/dev/null)
journalctl --directory "$UAC/var/log/journal/${MACHINE_ID}/" --utc --no-pager 2>/dev/null

# wtmp / btmp login history
last  -F -f "$UAC/var/log/wtmp"  2>/dev/null
lastb -F -f "$UAC/var/log/btmp"  2>/dev/null

# Auth log (Debian/Ubuntu)
grep "Accepted\|Failed\|sudo:" "$UAC/var/log/auth.log" 2>/dev/null
```

**What UAC provides vs disk image:**

| Capability | Disk image (E01) | UAC triage |
|------------|-----------------|------------|
| Volatile data (processes, network, /dev/shm) | No — lost at shutdown | **Yes** — captured live |
| Unallocated space / file carving | Yes | No |
| Full filesystem (all files) | Yes | Profile-dependent |
| TSK bodyfile / mactime | Generate from image | **Pre-generated** |
| Memory | Separate .lime capture | No |

---

## Distro Quick Reference

| Artifact | Debian / Ubuntu | RHEL / CentOS / Fedora |
|----------|----------------|----------------------|
| Auth log | `/var/log/auth.log` | `/var/log/secure` |
| System log | `/var/log/syslog` | `/var/log/messages` |
| Kernel log | `/var/log/kern.log` | included in `messages` |
| Cron log | `/var/log/cron.log` | `/var/log/cron` |
| Package log | `/var/log/dpkg.log` | `/var/log/yum.log` / `/var/log/dnf.log` |
| User crontabs | `/var/spool/cron/crontabs/<user>` | `/var/spool/cron/<user>` |
| Package query | `dpkg -l` / `dpkg -V` | `rpm -qa` / `rpm -Va` |

---

## Tool Reference

| Tool | Purpose | Notes |
|------|---------|-------|
| `journalctl` | Read systemd journal (incl. offline) | Use `--file` or `--directory` for mounted evidence |
| `ausearch` | Search auditd logs | Use `-f` for offline log file |
| `aureport` | Summarize auditd logs | Use `-if` for offline log file |
| `last` | Login history from wtmp | Use `-F -f <path>` for full timestamps + offline file |
| `lastb` | Failed login history from btmp | Use `-F -f <path>` for full timestamps + offline file |
| `rkhunter` | Rootkit detection scan | Use `--rootdir` for mounted image |
| `chkrootkit` | Rootkit detection scan | Use `-r` for mounted image |
| `find` | File system searches | Core tool for recent files, SUID, staging |
| `stat` | File metadata (MAC times, inode) | — |

---

## User Account Analysis

```bash
# All accounts — look for UID 0 duplicates and unexpected shell accounts
cat /mnt/linux_mount/etc/passwd

# Accounts with UID 0 (should be root only)
awk -F: '$3 == 0 {print $1}' /mnt/linux_mount/etc/passwd

# Accounts with a valid login shell (non-service accounts)
awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {print $1, $3, $7}' \
  /mnt/linux_mount/etc/passwd

# File modification time on passwd/shadow (reveals when accounts were added)
stat /mnt/linux_mount/etc/passwd /mnt/linux_mount/etc/shadow

# Group memberships — check sudo / wheel / adm / docker membership
cat /mnt/linux_mount/etc/group
grep -E "^(sudo|wheel|adm|docker):" /mnt/linux_mount/etc/group

# Sudoers — ALL / NOPASSWD grants are high priority
cat /mnt/linux_mount/etc/sudoers 2>/dev/null
grep -rE "(ALL|NOPASSWD)" \
  /mnt/linux_mount/etc/sudoers \
  /mnt/linux_mount/etc/sudoers.d/ 2>/dev/null

# Writable or non-root-owned scripts/binaries listed explicitly in sudoers rules
# Non-root owner can chmod/replace the file; world/group-writable = any user can modify
grep -rh "^[^#]" \
  /mnt/linux_mount/etc/sudoers \
  /mnt/linux_mount/etc/sudoers.d/ 2>/dev/null | \
  grep -oE '/[^ ,\t:!]+' | sort -u | \
  while IFS= read -r p; do
    mp="/mnt/linux_mount${p}"
    [ -f "$mp" ] || continue
    result=$(find "$mp" -maxdepth 0 \
      \( ! -user root -o -perm -o+w -o \( -perm -g+w ! -group root \) \) 2>/dev/null)
    [ -n "$result" ] && echo "SUSPECT SUDOERS TARGET: $p"
  done | tee ./exports/writable_sudoers_paths.txt

# SSH authorized_keys — backdoor key implantation
find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "authorized_keys" 2>/dev/null | \
  while IFS= read -r f; do
    echo "=== $f ==="
    cat "$f"
  done | tee ./exports/authorized_keys_all.txt

# SSH host key fingerprints (verify against expected baseline)
for key in /mnt/linux_mount/etc/ssh/ssh_host_*_key.pub; do
  ssh-keygen -lf "$key" 2>/dev/null
done
```

### Domain Join / SSSD (Active Directory integration)

Corporate Linux hosts are often AD-joined. Domain accounts do **not** appear in
`/etc/passwd` unless locally cached — look in logs and wtmp instead.

Three integration methods:

| Method | Config | PAM module | Users appear as |
|--------|--------|------------|----------------|
| SSSD (on-prem AD) | `/etc/sssd/sssd.conf` | `pam_sss.so` | `user@domain.corp` |
| winbind (Samba) | `/etc/samba/smb.conf` | `pam_winbind.so` | `DOMAIN\user` |
| Azure AD — Microsoft `aadsshlogin` | `/etc/aadpasswd` (NSS cache) | `aad_ssh.so` | `user@tenant.onmicrosoft.com` |
| Azure AD — Canonical `aad-auth` (Ubuntu) | `/etc/aad.conf` | `pam_aad.so` | `user@tenant.onmicrosoft.com` |

```bash
# --- Determine join method ---
cat /mnt/linux_mount/etc/sssd/sssd.conf 2>/dev/null
ls  /mnt/linux_mount/etc/sssd/conf.d/ 2>/dev/null
cat /mnt/linux_mount/etc/realmd.conf 2>/dev/null
cat /mnt/linux_mount/etc/krb5.conf 2>/dev/null
grep -E "workgroup|realm|security" \
  /mnt/linux_mount/etc/samba/smb.conf 2>/dev/null

# Azure AD — Microsoft aadsshlogin: /etc/aadpasswd is NSS cache of AAD users
cat /mnt/linux_mount/etc/aadpasswd 2>/dev/null
# Azure AD — Canonical aad-auth (Ubuntu): tenant config + offline cache
cat /mnt/linux_mount/etc/aad.conf 2>/dev/null
ls  /mnt/linux_mount/var/lib/aad/cache/ 2>/dev/null

# --- PAM wiring (confirms auth is routed through domain) ---
# pam_sss=SSSD  aad_ssh=MS aadsshlogin  pam_aad=Canonical aad-auth  pam_winbind=winbind
grep -rl "pam_sss\|aad_ssh\|pam_aad\|pam_winbind" /mnt/linux_mount/etc/pam.d/ 2>/dev/null

# --- SSSD domain auth logs ---
sudo mkdir -p ./exports/sssd/
sudo cp -rp /mnt/linux_mount/var/log/sssd/ ./exports/sssd/ 2>/dev/null
grep -iE "(auth|fail|success|pam)" \
  /mnt/linux_mount/var/log/sssd/sssd_*.log 2>/dev/null | head -50

# --- Domain accounts in login records ---
# wtmp: domain users appear as user@domain.corp or DOMAIN\user
last -F -f /mnt/linux_mount/var/log/wtmp | grep -v "^reboot\|^wtmp" | head -30

# auth.log / secure: SSSD and Azure AD auth events
grep -iE "sssd|pam_sss|aad_ssh|pam_aad|krb5|Accepted.*@" \
  /mnt/linux_mount/var/log/auth.log \
  /mnt/linux_mount/var/log/secure 2>/dev/null | head -30

# --- Cached credentials ---
ls /mnt/linux_mount/var/lib/sss/db/ 2>/dev/null         # SSSD credential cache
ls /mnt/linux_mount/var/lib/aad/cache/ 2>/dev/null       # Canonical aad-auth cache
```

---

## Authentication Log Analysis

```bash
# Consolidate all auth logs (current + rotated; .gz-aware)
{
  for f in $(ls /mnt/linux_mount/var/log/auth.log* \
                /mnt/linux_mount/var/log/secure*    2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/auth_all.log
echo "Consolidated: $(wc -l < ./exports/auth_all.log) auth records"

# All successful SSH logins (source IP + user + timestamp)
grep "Accepted" ./exports/auth_all.log | tee ./exports/ssh_logins_success.txt

# Top source IPs for successful SSH logins (anomaly pivot)
awk '{print $11}' ./exports/ssh_logins_success.txt | \
  sort | uniq -c | sort -rn | head -20

# Failed SSH logins (brute force / credential stuffing)
grep "Failed password" ./exports/auth_all.log | tee ./exports/ssh_logins_failed.txt

# Invalid user attempts (probing non-existent accounts)
grep "Invalid user" ./exports/auth_all.log

# Sudo usage with full command
grep "sudo:.*COMMAND" ./exports/auth_all.log | tee ./exports/sudo_usage.txt

# su to root
grep "session opened for user root" ./exports/auth_all.log

# New user / group creation
grep -E "(useradd|groupadd|usermod|passwd:)" ./exports/auth_all.log

# Login history from wtmp (all logins / logouts with duration)
last -F -f /mnt/linux_mount/var/log/wtmp | tee ./exports/wtmp_logins.txt

# Failed login history from btmp
lastb -F -f /mnt/linux_mount/var/log/btmp 2>/dev/null | \
  tee ./exports/btmp_failed.txt

# Last login per account
lastlog --root /mnt/linux_mount 2>/dev/null | tee ./exports/lastlog.txt
```

---

## Systemd Journal (journalctl)

Reading an offline journal requires `--file` or `--directory` — the most common
operational mistake is forgetting this and reading the live system's journal instead.

```bash
# Find the machine-id (required to locate journal directory)
cat /mnt/linux_mount/etc/machine-id

# List journal files on the evidence
find /mnt/linux_mount/var/log/journal -name "*.journal" 2>/dev/null

# Read offline journal — all events in a time window (UTC)
MACHINE_ID=$(cat /mnt/linux_mount/etc/machine-id)
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  --since "2023-01-24 00:00:00" --until "2023-01-26 23:59:59" \
  --utc --no-pager | tee ./exports/journal_window.txt

# Filter by service unit
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  -u sshd --utc --no-pager

# Filter by executable path
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  _EXE=/usr/sbin/sshd --utc --no-pager

# Sudo commands only
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  _COMM=sudo --utc --no-pager

# Kernel messages (module loading, panics, oops)
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  -k --utc --no-pager | tee ./exports/journal_kernel.txt

# All errors and above
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  -p err --utc --no-pager

# Events from a specific PID
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  _PID=<pid> --utc --no-pager

# Export to JSON for scripted analysis
journalctl \
  --directory /mnt/linux_mount/var/log/journal/${MACHINE_ID}/ \
  --since "2023-01-24" --utc -o json \
  > ./exports/journal_export.json
```

**High-value journal filters for IR:**
| Filter | Purpose |
|--------|---------|
| `-u sshd` | SSH logins, key auth, failures |
| `-u cron` | Scheduled task execution |
| `_COMM=sudo` | All sudo invocations |
| `-k` | Kernel: module loads, panics, hardware |
| `-p err` | All error-level and above events |
| `_SYSTEMD_UNIT=<name>.service` | Specific service events |

---

## System Logs

```bash
# Syslog / messages — consolidate all rotated logs
{
  for f in $(ls /mnt/linux_mount/var/log/syslog* \
                /mnt/linux_mount/var/log/messages* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/syslog_all.txt
echo "Consolidated: $(wc -l < ./exports/syslog_all.txt) syslog records"

# Kernel log — module loading visible here (rootkit installation indicator)
{
  for f in $(ls /mnt/linux_mount/var/log/kern.log* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/kern_all.log
grep -iE "(module|insmod|rmmod|modprobe)" ./exports/kern_all.log

# Cron execution log
{
  for f in $(ls /mnt/linux_mount/var/log/cron.log* \
                /mnt/linux_mount/var/log/cron \
                /mnt/linux_mount/var/log/cron.* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/cron_all.log

# Package manager log — what was installed / removed and when
# Debian/Ubuntu:
{
  for f in $(ls /mnt/linux_mount/var/log/dpkg.log* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/dpkg_all.log
grep " install \| remove " ./exports/dpkg_all.log | tee ./exports/dpkg_changes.txt

# RHEL (yum):
{
  for f in $(ls /mnt/linux_mount/var/log/yum.log* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/yum_all.log
cat ./exports/yum_all.log | tee ./exports/yum_log.txt

# RHEL (dnf):
{
  for f in $(ls /mnt/linux_mount/var/log/dnf.log* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/dnf_all.log
grep "Installed\|Removed" ./exports/dnf_all.log | tee ./exports/dnf_changes.txt
```

---

## Auditd Analysis

Auditd provides syscall-level auditing. It must have been running and configured with
execve rules to capture command execution. Verify before relying on it.

```bash
# Confirm auditd was configured and check its rules
cat /mnt/linux_mount/etc/audit/auditd.conf 2>/dev/null
cat /mnt/linux_mount/etc/audit/rules.d/*.rules 2>/dev/null

# Confirm execve auditing was enabled (required to capture command execution)
grep "execve" /mnt/linux_mount/etc/audit/rules.d/*.rules 2>/dev/null

# List all audit logs present (current + rotated)
ls /mnt/linux_mount/var/log/audit/audit.log* 2>/dev/null | sort -V

# Consolidate all rotated logs into one file (oldest first; handles optional .gz)
{
  for f in $(ls /mnt/linux_mount/var/log/audit/audit.log* 2>/dev/null | sort -Vr); do
    case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
  done
} > ./exports/audit_all.log
echo "Consolidated: $(wc -l < ./exports/audit_all.log) audit records"

# All execution events
ausearch -i -sc execve \
  -f ./exports/audit_all.log 2>/dev/null | \
  tee ./exports/audit_execve.txt

# Specific user's activity by UID
ausearch -i -ua <uid> \
  -f ./exports/audit_all.log 2>/dev/null

# Failed authentications
ausearch -i -m USER_AUTH -sv no \
  -f ./exports/audit_all.log 2>/dev/null

# Outbound network connections (connect syscall)
ausearch -i -sc connect \
  -f ./exports/audit_all.log 2>/dev/null | \
  tee ./exports/audit_network.txt

# Sudo / privilege escalation commands
ausearch -i -m USER_CMD \
  -f ./exports/audit_all.log 2>/dev/null

# Summary reports
aureport --summary     -if ./exports/audit_all.log 2>/dev/null
aureport -au --summary -if ./exports/audit_all.log 2>/dev/null
aureport -x  --summary -if ./exports/audit_all.log 2>/dev/null
aureport --anomaly     -if ./exports/audit_all.log 2>/dev/null

# PROCTITLE is hex-encoded — decode it to readable command lines
ausearch -m EXECVE \
  -f ./exports/audit_all.log 2>/dev/null | \
  grep "proctitle=" | python3 -c "
import sys
for line in sys.stdin:
    for field in line.strip().split():
        if field.startswith('proctitle='):
            val = field.split('=', 1)[1]
            try:
                print(bytes.fromhex(val).decode('utf-8', errors='replace'))
            except ValueError:
                print(val)
"
```

**Key auditd record types:**
| Type | Description |
|------|-------------|
| `EXECVE` | Command execution with argv |
| `SYSCALL` | System call with process context |
| `PATH` | File access path |
| `SOCKADDR` | Network connection destination |
| `USER_AUTH` | Authentication event |
| `USER_LOGIN` | Login event |
| `USER_CMD` | sudo command |
| `PROCTITLE` | Full command line (hex-encoded) |
| `USER_START` | Session opened |
| `USER_END` | Session closed |
| `ANOM_ABEND` | Abnormal process termination |

---

## Shell History

```bash
# Helper: read + export a set of history files
_dump_hist() {
  local name="$1"; shift
  find /mnt/linux_mount/home /mnt/linux_mount/root "$@" 2>/dev/null | \
    while IFS= read -r f; do echo "=== $f ==="; cat "$f"; done \
    | tee "./exports/${name}_history_all.txt"
}

_dump_hist bash  -name ".bash_history"
_dump_hist zsh   -name ".zsh_history" -o -name ".zhistory"
_dump_hist fish  -path "*/fish/fish_history"   # YAML: cmd + epoch timestamp per entry
_dump_hist tcsh  -name ".history"              # tcsh / csh
_dump_hist ksh   -name ".sh_history"           # ksh

# Red flags across all shell histories
cat ./exports/*_history_all.txt 2>/dev/null | \
  grep -iE \
    "(wget|curl|chmod \+x|base64|/dev/shm|/tmp/\.|nc |ncat |bash -i|python.*-c|perl.*-e|mkfifo|ssh-keygen.*-p)" \
  | tee ./exports/shell_history_suspicious.txt
# ssh-keygen -p in history: attacker was most likely probing private keys to identify
# which lack a passphrase — unprotected keys can be used directly for lateral movement
# without cracking. Passphrase removal is a secondary possibility but requires knowing
# the current passphrase; probing costs nothing and reveals the same information.

# HISTFILE tampering — attacker may disable history recording
grep -rE "(HISTSIZE=0|HISTFILESIZE=0|HISTFILE=/dev/null)" \
  /mnt/linux_mount/home/*/.bashrc \
  /mnt/linux_mount/home/*/.bash_profile \
  /mnt/linux_mount/root/.bashrc \
  /mnt/linux_mount/root/.bash_profile 2>/dev/null

# Bash history with timestamps — only present if HISTTIMEFORMAT was set
# Lines starting with #<epoch> are timestamps for the next command
grep -A1 "^#[0-9]\{10\}" ./exports/bash_history_all.txt | \
  awk '/^#/{t=strftime("%Y-%m-%d %H:%M:%S UTC", substr($0,2))} !/^#/{print t, $0}'
```

---

## Persistence Mechanisms

### Cron

```bash
# System-wide crontab
cat /mnt/linux_mount/etc/crontab

# Cron drop-in directories
cat /mnt/linux_mount/etc/cron.d/* 2>/dev/null
ls -la /mnt/linux_mount/etc/cron.{hourly,daily,weekly,monthly}/ 2>/dev/null

# Per-user crontabs
for f in /mnt/linux_mount/var/spool/cron/crontabs/* \
          /mnt/linux_mount/var/spool/cron/*; do
  [[ -f "$f" ]] && echo "=== $(basename "$f") ===" && cat "$f"
done

# Red flags: cron running from staging areas or using encoders/downloaders
grep -rE "(/tmp/|/dev/shm|base64|wget|curl|python|perl|bash -i)" \
  /mnt/linux_mount/etc/crontab \
  /mnt/linux_mount/etc/cron.d/ \
  /mnt/linux_mount/var/spool/cron/ 2>/dev/null
```

### Systemd Services and Timers

```bash
# System-wide service units — two locations:
#   /etc/systemd/system/     admin/attacker-created (highest priority)
#   /usr/lib/systemd/system/ package-installed (check for backdoored packages)
ls -la /mnt/linux_mount/etc/systemd/system/*.service \
        /mnt/linux_mount/usr/lib/systemd/system/*.service 2>/dev/null | \
  tee ./exports/systemd_services.txt

# Timer units (scheduled task equivalent) — same two locations
ls -la /mnt/linux_mount/etc/systemd/system/*.timer \
        /mnt/linux_mount/usr/lib/systemd/system/*.timer 2>/dev/null

# System-wide user units (applied to all users; /etc requires root to create)
ls -la /mnt/linux_mount/etc/systemd/user/ 2>/dev/null
ls -la /mnt/linux_mount/usr/lib/systemd/user/ 2>/dev/null

# Per-user units (any user can create — also check .timer and .socket)
find /mnt/linux_mount/home /mnt/linux_mount/root \
  \( -path "*/.config/systemd/user/*.service" \
     -o -path "*/.config/systemd/user/*.timer" \
     -o -path "*/.config/systemd/user/*.socket" \) 2>/dev/null

# Units enabled at boot (symlinked into wants directories)
ls -la /mnt/linux_mount/etc/systemd/system/multi-user.target.wants/ 2>/dev/null

# Inspect a unit file
cat /mnt/linux_mount/etc/systemd/system/<unit>.service

# Red flags: scan all persistent unit locations
grep -rE "ExecStart=.*(\/tmp\/|\/dev\/shm\/|base64|bash -i|python|perl|curl|wget)" \
  /mnt/linux_mount/etc/systemd/system/ \
  /mnt/linux_mount/etc/systemd/user/ \
  /mnt/linux_mount/usr/lib/systemd/system/ \
  /mnt/linux_mount/usr/lib/systemd/user/ \
  2>/dev/null | tee ./exports/systemd_suspicious.txt

# Red flags in per-user units
find /mnt/linux_mount/home /mnt/linux_mount/root \
  -path "*/.config/systemd/user/*" \
  \( -name "*.service" -o -name "*.timer" \) 2>/dev/null | \
  xargs grep -lE "ExecStart=.*(\/tmp\/|\/dev\/shm\/|base64|bash -i|python|perl|curl|wget)" \
  2>/dev/null >> ./exports/systemd_suspicious.txt
```

### SysV Init Scripts and rc.local

systemd runs SysV init scripts via `systemd-sysv-generator` (wraps `/etc/init.d/` scripts
as units). `/etc/rc.local` is executed by `rc-local.service` if it exists and is executable
— a well-known persistence location on Ubuntu/Debian and RHEL.

```bash
# SysV init scripts (executed by systemd compatibility layer)
ls -la /mnt/linux_mount/etc/init.d/ 2>/dev/null | tee ./exports/initd_scripts.txt

# Runlevel symlinks (S* = start, K* = kill — check rc2.d/rc3.d/rc5.d for multi-user boot)
ls -la /mnt/linux_mount/etc/rc2.d/ \
        /mnt/linux_mount/etc/rc3.d/ \
        /mnt/linux_mount/etc/rc5.d/ 2>/dev/null

# rc.local — runs as root at end of boot if executable (check even on systemd hosts)
ls -la /mnt/linux_mount/etc/rc.local 2>/dev/null
cat /mnt/linux_mount/etc/rc.local 2>/dev/null

# RHEL/CentOS: rc.d directory
ls -la /mnt/linux_mount/etc/rc.d/ 2>/dev/null
cat /mnt/linux_mount/etc/rc.d/rc.local 2>/dev/null

# Red flags in init scripts and rc.local
grep -rE "(wget|curl|base64|bash -i|nc |ncat |/tmp/|/dev/shm)" \
  /mnt/linux_mount/etc/init.d/ \
  /mnt/linux_mount/etc/rc.local \
  /mnt/linux_mount/etc/rc.d/rc.local 2>/dev/null
```

### LD_PRELOAD / ld.so.preload

**Critical: if `/etc/ld.so.preload` exists and is non-empty, every process on the
system loaded that library. Treat as confirmed rootkit until proven otherwise.**

```bash
# Check ld.so.preload (CRITICAL — check this first)
if [[ -s /mnt/linux_mount/etc/ld.so.preload ]]; then
    echo "[CRITICAL] /etc/ld.so.preload is non-empty:"
    cat /mnt/linux_mount/etc/ld.so.preload
else
    echo "[OK] /etc/ld.so.preload absent or empty"
fi

# Dynamic linker library search path configuration
cat /mnt/linux_mount/etc/ld.so.conf
cat /mnt/linux_mount/etc/ld.so.conf.d/*.conf 2>/dev/null

# Shared libraries newer than /etc/passwd (recently added)
find /mnt/linux_mount/usr/lib \
     /mnt/linux_mount/usr/local/lib \
     /mnt/linux_mount/lib \
     /mnt/linux_mount/lib64 \
  -name "*.so*" -newer /mnt/linux_mount/etc/passwd 2>/dev/null | \
  tee ./exports/new_shared_libs.txt
```

### Kernel Module Loading

```bash
# Modules loaded at boot
cat /mnt/linux_mount/etc/modules 2>/dev/null
cat /mnt/linux_mount/etc/modules-load.d/*.conf 2>/dev/null

# Module options and aliases — install directives run arbitrary commands
cat /mnt/linux_mount/etc/modprobe.d/*.conf 2>/dev/null

# Flag install directives (runs a command whenever the module is loaded)
grep -r "^install" /mnt/linux_mount/etc/modprobe.d/ 2>/dev/null

# All .ko files on disk (for YARA scanning / hash verification)
find /mnt/linux_mount/lib/modules -name "*.ko" 2>/dev/null | \
  sort > ./analysis/kernel_modules_on_disk.txt
```

### Shell RC Files

Executed on every interactive shell start — a common and often-overlooked
persistence location.

```bash
# System-wide shell configuration
cat /mnt/linux_mount/etc/profile
cat /mnt/linux_mount/etc/profile.d/*.sh 2>/dev/null
cat /mnt/linux_mount/etc/bash.bashrc 2>/dev/null        # Debian/Ubuntu
cat /mnt/linux_mount/etc/bashrc 2>/dev/null             # RHEL/CentOS

# zsh global configs (/etc/zshenv runs for ALL zsh invocations — highest persistence risk)
cat /mnt/linux_mount/etc/zshenv 2>/dev/null
cat /mnt/linux_mount/etc/zprofile 2>/dev/null
cat /mnt/linux_mount/etc/zshrc 2>/dev/null

# fish global configs
cat /mnt/linux_mount/etc/fish/config.fish 2>/dev/null
cat /mnt/linux_mount/etc/fish/conf.d/*.fish 2>/dev/null

# Per-user RC files
for user_home in /mnt/linux_mount/home/* /mnt/linux_mount/root; do
    for rc in .bashrc .bash_profile .profile .zshenv .zprofile .zshrc .zlogin; do
        f="${user_home}/${rc}"
        [[ -f "$f" ]] && echo "=== $f ===" && cat "$f"
    done
    # fish per-user config lives in a subdirectory
    f="${user_home}/.config/fish/config.fish"
    [[ -f "$f" ]] && echo "=== $f ===" && cat "$f"
done | tee ./exports/shell_rc_all.txt

# Red flags
grep -iE "(curl|wget|base64|/dev/tcp|nc |ncat |python.*-c)" \
  ./exports/shell_rc_all.txt
```

### SSH Authorized Keys

If `ssh-keygen -p` appears in shell history, the attacker was likely probing private
keys to find unprotected ones (no passphrase prompt = usable immediately for lateral
movement). Cross-reference any unprotected private keys found here against that history.

```bash
# All authorized_keys — fingerprint each key for pivot
find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "authorized_keys" 2>/dev/null | \
  while IFS= read -r keyfile; do
    echo "=== $keyfile ==="
    cat "$keyfile"
    echo "--- fingerprints ---"
    while IFS= read -r keyline; do
        echo "$keyline" | ssh-keygen -l -f /dev/stdin 2>/dev/null
    done < "$keyfile"
    echo
  done | tee ./exports/authorized_keys_fingerprinted.txt
```

### SSH Client Config

`~/.ssh/config` (and system-wide `/etc/ssh/ssh_config`) can contain `ProxyCommand`
directives that execute arbitrary commands whenever the user SSHs to a matching host —
a subtle persistence and credential-harvesting vector.

```bash
# System-wide SSH client config and drop-in dir
cat /mnt/linux_mount/etc/ssh/ssh_config 2>/dev/null
ls  /mnt/linux_mount/etc/ssh/ssh_config.d/ 2>/dev/null
cat /mnt/linux_mount/etc/ssh/ssh_config.d/*.conf 2>/dev/null

# Per-user SSH client configs
find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "config" -path "*/.ssh/*" 2>/dev/null | \
  while IFS= read -r f; do
    echo "=== $f ==="; cat "$f"
  done | tee ./exports/ssh_client_configs.txt

# Flag high-risk directives
grep -i "ProxyCommand\|ControlMaster\|IdentityFile" ./exports/ssh_client_configs.txt
```

### SUID / SGID Binaries

```bash
# All SUID binaries (execute as file owner — typically root)
find /mnt/linux_mount -xdev -perm -4000 -type f 2>/dev/null | \
  sort > ./exports/suid_binaries.txt

# All SGID binaries
find /mnt/linux_mount -xdev -perm -2000 -type f 2>/dev/null | \
  sort > ./exports/sgid_binaries.txt

# Flag SUID binaries outside standard system directories (suspicious additions)
grep -v "^\(/mnt/linux_mount\)\?\(/usr\)\?\(/s\?bin\|/lib\)" \
  ./exports/suid_binaries.txt

# POSIX file capabilities — grant specific privileges without full SUID root
# Attackers use cap_setuid, cap_net_raw, cap_net_bind_service, cap_sys_ptrace, etc.
# to achieve privilege escalation without the visibility of a SUID binary
getcap -r /mnt/linux_mount 2>/dev/null | tee ./exports/file_capabilities.txt
# Flag high-risk capabilities
grep -E "cap_(setuid|setgid|sys_admin|sys_ptrace|net_raw|dac_override)" \
  ./exports/file_capabilities.txt

# Suspect SUID/SGID — non-root-owned, world-writable, or non-root-group-writable
# Owner can chmod/replace; writable = any matching user can overwrite
find /mnt/linux_mount -xdev \( -perm -4000 -o -perm -2000 \) -type f \
  \( ! -user root -o -perm -o+w -o \( -perm -g+w ! -group root \) \) 2>/dev/null | \
  tee ./exports/writable_suid_sgid.txt
```

### Other Persistence Locations

```bash
# AT jobs (run-once scheduled commands)
ls /mnt/linux_mount/var/spool/at/ 2>/dev/null
ls /mnt/linux_mount/var/spool/atjobs/ 2>/dev/null

# MOTD scripts (execute as root on every interactive login)
ls -la /mnt/linux_mount/etc/update-motd.d/ 2>/dev/null
cat /mnt/linux_mount/etc/update-motd.d/* 2>/dev/null

# Udev rules with RUN directives (triggered by hardware events)
grep -r "^RUN" /mnt/linux_mount/etc/udev/rules.d/ 2>/dev/null

# XDG autostart (graphical sessions)
ls /mnt/linux_mount/etc/xdg/autostart/ 2>/dev/null
find /mnt/linux_mount/home -path "*/.config/autostart/*.desktop" 2>/dev/null

# PAM module backdoors (hooks all authentication)
ls /mnt/linux_mount/etc/pam.d/
# Non-standard PAM modules are unusual — flag any outside /lib/security/
grep -rh "pam_" /mnt/linux_mount/etc/pam.d/ | \
  grep -v "^#" | awk '{print $3}' | sort -u

# APT hooks (Debian/Ubuntu) — execute arbitrary commands during package operations
# Directives: DPkg::Pre-Install-Pkgs, DPkg::Post-Invoke, APT::Update::Pre-Invoke, etc.
# Check both the main config and the drop-in directory.
grep -rh "DPkg::\|APT::Update::\|APT::Get::" \
  /mnt/linux_mount/etc/apt/apt.conf \
  /mnt/linux_mount/etc/apt/apt.conf.d/ 2>/dev/null | \
  tee ./exports/apt_hooks.txt

# Flag hook commands that reference non-standard paths — hidden dirs (.backup, .cache),
# staging areas (/tmp, /var/tmp, /dev/shm), or paths outside /usr/bin /bin /sbin.
grep -Ei '(Pre|Post)-Invoke|Pre-Install-Pkgs' ./exports/apt_hooks.txt | \
  grep -Ev '"[[:space:]]*/?(usr/|usr/local/|s?bin/|lib/)' | \
  grep -E '"' | \
  tee ./exports/apt_hooks_suspicious.txt

# TRIAGE: ANY non-empty output above is a confirmed finding.
# Attackers routinely name backdoors after legitimate services (sshd, cron, systemd,
# NetworkManager) to defeat casual review. The binary NAME is irrelevant — the PATH
# is the indicator. A real sshd lives in /usr/sbin/sshd, never /root/.backup/sshd.
# Treat every entry as malicious until proven otherwise by hash or package provenance.

# Timestamps on the conf files that contain hook directives — mtime/ctime shows
# when the hook was planted; crtime shows "-" if filesystem lacks birth-time support.
grep -rl "Pre-Invoke\|Post-Invoke\|Pre-Install-Pkgs\|Post-Install-Pkgs" \
  /mnt/linux_mount/etc/apt/apt.conf \
  /mnt/linux_mount/etc/apt/apt.conf.d/ 2>/dev/null | \
while IFS= read -r f; do
  echo "=== $f ==="
  stat -c "  atime:  %x
  mtime:  %y
  ctime:  %z
  crtime: %w" "$f" 2>/dev/null
done | tee ./exports/apt_hook_conf_timestamps.txt

# For each flagged binary: confirm ELF type, all timestamps, and hash for threat intel
while IFS= read -r line; do
  binary=$(echo "$line" | grep -oP '"\K[^"]+' | awk '{print $1}')
  [ -z "$binary" ] && continue
  target="/mnt/linux_mount${binary}"
  echo "=== $binary ==="
  file "$target" 2>/dev/null || echo "(not found on disk)"
  stat -c "  atime:  %x
  mtime:  %y
  ctime:  %z
  crtime: %w
  size:   %s bytes" "$target" 2>/dev/null
  sha256sum "$target" 2>/dev/null | awk '{print "  sha256:", $1}'
done < ./exports/apt_hooks_suspicious.txt | tee ./exports/apt_hooks_binaries.txt

# DNF/Yum plugins (RHEL/CentOS/Fedora) — Python modules loaded by the package manager
# List plugin config files — each .conf enables a named plugin module
ls /mnt/linux_mount/etc/dnf/plugins/ 2>/dev/null
ls /mnt/linux_mount/etc/yum/pluginconf.d/ 2>/dev/null

# Find all plugin Python files across standard locations
find /mnt/linux_mount/usr/lib/python*/site-packages/dnf-plugins/ \
     /mnt/linux_mount/usr/lib/python*/dist-packages/dnf-plugins/ \
     /mnt/linux_mount/usr/lib/yum-plugins/ \
  -type f -name "*.py" 2>/dev/null | tee ./exports/package_manager_plugins.txt

# Flag plugins containing execution or network primitives — a legitimate plugin
# has no reason to call subprocess/socket/eval or reference staging paths
grep -Hl \
  -e "subprocess" -e "os\.system" -e "os\.popen" -e "os\.exec" \
  -e "socket\." -e "urllib" -e "requests\." -e "http\." \
  -e "base64" -e "eval(" -e "exec(" \
  -e "/tmp/" -e "/var/tmp/" -e "/dev/shm/" \
  $(cat ./exports/package_manager_plugins.txt) 2>/dev/null | \
  tee ./exports/package_manager_plugins_suspicious.txt

# Show matching lines plus all timestamps for each content-flagged plugin.
# (Loop reads package_manager_plugins_suspicious.txt — only files that matched
# the grep -Hl above, so stat runs only on confirmed content hits.)
# ctime reveals permission/ownership changes even if mtime was backdated;
# crtime (birth) shows "-" on filesystems without birth-time support — use
# debugfs -R "stat <inode>" /dev/<device> on ext4 to retrieve it from the inode.
while IFS= read -r plugin; do
  echo "=== $plugin ==="
  stat -c "  atime:  %x
  mtime:  %y
  ctime:  %z
  crtime: %w" "$plugin" 2>/dev/null
  grep -n \
    -e "subprocess" -e "os\.system" -e "os\.popen" -e "os\.exec" \
    -e "socket\." -e "urllib" -e "requests\." \
    -e "base64" -e "eval(" -e "exec(" \
    -e "/tmp/" -e "/var/tmp/" -e "/dev/shm/" \
    "$plugin" 2>/dev/null
done < ./exports/package_manager_plugins_suspicious.txt | \
  tee ./exports/package_manager_plugins_findings.txt

# D-Bus service files — a D-Bus .service file can specify an Exec= that runs as the
# activating user; an attacker can drop one to execute code when any D-Bus call hits it
find /mnt/linux_mount -path '*/dbus-1/*' -type f -name '*.service' 2>/dev/null | \
  tee ./exports/dbus_services.txt
# Flag entries referencing staging areas or network tools
grep -EH \
  "(curl |wget |nc -|ncat |socat |/tmp/|/var/tmp/|/dev/shm/|/dev/tcp/|base64)" \
  $(cat ./exports/dbus_services.txt) 2>/dev/null | \
  tee ./exports/dbus_services_suspicious.txt

# NetworkManager dispatcher scripts — executed as root by NetworkManager when
# interface state changes (up/down/vpn-up/etc.); any executable file here runs as root
find /mnt/linux_mount -path '*/NetworkManager/dispatcher.d/*' \
  -type f -executable 2>/dev/null | \
  tee ./exports/nm_dispatcher_scripts.txt
# Inspect content of each script for red flags
xargs grep -EH \
  "(curl |wget |nc -|ncat |socat |/tmp/|/var/tmp/|/dev/shm/|/dev/tcp/|base64)" \
  < ./exports/nm_dispatcher_scripts.txt 2>/dev/null | \
  tee ./exports/nm_dispatcher_suspicious.txt

# Python .pth files — Python executes import statements and os.system() calls found
# in .pth files on startup; a malicious .pth in site-packages runs on every python invocation
find /mnt/linux_mount/usr/lib/python* \
     /mnt/linux_mount/usr/local/lib/python* \
     /mnt/linux_mount/home/*/.local/lib/python* \
  -type f -name '*.pth' 2>/dev/null | \
  while IFS= read -r f; do
    hit=$(grep -EH 'import |os\.system|exec\(' "$f" 2>/dev/null)
    [[ -n "$hit" ]] && echo "$hit"
  done | tee ./exports/python_pth_suspicious.txt

# Git hooks — scripts in .git/hooks/ execute automatically on git operations
# (pre-commit, post-merge, post-checkout, etc.); an attacker can implant code that
# fires whenever a developer runs git commands in a compromised repo
# .git/config can also set core.hooksPath to redirect to an attacker-controlled directory
find /mnt/linux_mount -type f \
  \( -path '*/.git/config' -o -path '*/.git/hooks/*' \) \
  ! -name '*.sample' 2>/dev/null | \
  tee ./exports/git_hooks.txt
# Show hook content for manual review
while IFS= read -r f; do
  echo "=== $f ==="
  cat "$f" 2>/dev/null
done < ./exports/git_hooks.txt | tee ./exports/git_hooks_content.txt
```

---

## Execution Evidence (Without Auditd)

When auditd was not running, these are the best fallback sources.

```bash
# Executables modified more recently than /etc/passwd (attacker-dropped tools)
find /mnt/linux_mount -type f -executable \
  -newer /mnt/linux_mount/etc/passwd \
  ! -path "*/proc/*" ! -path "*/sys/*" 2>/dev/null | \
  sort | tee ./exports/new_executables.txt

# World-writable executables (can be trojanised by any user)
find /mnt/linux_mount -type f -executable -perm -o+w 2>/dev/null | \
  tee ./exports/world_writable_executables.txt

# Package installations and removals with timestamps
# Debian/Ubuntu:
grep " install \| remove " /mnt/linux_mount/var/log/dpkg.log 2>/dev/null | \
  tee ./exports/dpkg_installs.txt

# RHEL/CentOS:
grep "Installed\|Erased" /mnt/linux_mount/var/log/yum.log 2>/dev/null
grep "Installed\|Removed" /mnt/linux_mount/var/log/dnf.log 2>/dev/null
```

---

## Temporary / Staging Areas

Attackers routinely stage tools in world-writable directories.
Enumerate and YARA-scan these before anything else.

> **tmpfs locations are NOT in disk images:** `/dev/shm`, `/run`, and (on some distros)
> `/tmp` are tmpfs (RAM-backed) mounts — the mount point exists on disk but the contents
> are lost at shutdown and absent from disk images. Capture them from a **live running
> system** before acquisition using Velociraptor or direct collection.

### From disk image (`/tmp` and `/var/tmp` only)

`/var/tmp` is always persistent. `/tmp` may be persistent or tmpfs — check
`/mnt/linux_mount/etc/fstab` for a `tmpfs /tmp` entry.

```bash
# All files in persistent staging areas (including hidden dotfiles)
find /mnt/linux_mount/tmp \
     /mnt/linux_mount/var/tmp \
  -type f 2>/dev/null | tee ./exports/staging_files.txt

# Hidden ELF binaries in staging/home dirs — attackers name dropper tools with a
# leading dot to hide them from plain ls; check file magic to confirm ELF regardless of name
find /mnt/linux_mount/tmp \
     /mnt/linux_mount/var/tmp \
     /mnt/linux_mount/home \
  -type f -name '.*' 2>/dev/null | \
  while IFS= read -r f; do
    file "$f" 2>/dev/null | grep -q 'ELF' && echo "$f"
  done | tee ./exports/hidden_elf_files.txt

# Hash all staging files for VirusTotal pivot
find /mnt/linux_mount/tmp \
     /mnt/linux_mount/var/tmp \
  -type f 2>/dev/null | \
  xargs sha256sum 2>/dev/null | tee ./exports/staging_hashes.txt

# Copy staging files for offline analysis / YARA scanning
mkdir -p ./exports/staging/
find /mnt/linux_mount/tmp \
     /mnt/linux_mount/var/tmp \
  -type f 2>/dev/null | \
  xargs -I{} cp --parents {} ./exports/staging/ 2>/dev/null
```

### From live system (tmpfs — requires Velociraptor or direct access)

```bash
# Velociraptor: collect files from ephemeral tmpfs locations
# Linux.Search.FileFinder with Glob: /dev/shm/**, /run/**, /tmp/**

# Direct collection (if shell access to live system)
find /dev/shm /run /tmp -type f 2>/dev/null | \
  xargs sha256sum 2>/dev/null | tee ./exports/live_staging_hashes.txt
find /dev/shm /run /tmp -type f 2>/dev/null | \
  xargs -I{} cp --parents {} ./exports/live_staging/ 2>/dev/null
```

---

## Web Server Artifacts

```bash
# Apache: POST requests to script files (webshell execution pattern)
grep "POST" /mnt/linux_mount/var/log/apache2/access.log 2>/dev/null | \
  grep -iE "\.(php|asp|jsp|py|sh|cgi|pl)" | \
  tee ./exports/web_post_requests.txt

# Nginx access log
grep "POST" /mnt/linux_mount/var/log/nginx/access.log 2>/dev/null | \
  grep -iE "\.(php|sh|cgi)"

# Error logs — webshell execution errors appear here
tail -200 /mnt/linux_mount/var/log/apache2/error.log 2>/dev/null
tail -200 /mnt/linux_mount/var/log/nginx/error.log   2>/dev/null

# Recently modified PHP files (webshell drop)
find /mnt/linux_mount/var/www \
     /mnt/linux_mount/srv/www \
     /mnt/linux_mount/usr/share/nginx \
  -name "*.php" -newer /mnt/linux_mount/etc/passwd 2>/dev/null | \
  tee ./exports/new_php_files.txt

# PHP files with eval+base64 or system() — webshell signatures
find /mnt/linux_mount/var/www -name "*.php" 2>/dev/null | \
  xargs grep -l \
    "eval.*base64_decode\|system(\|exec(\|shell_exec(\|passthru(\|popen(" \
    2>/dev/null | tee ./exports/webshell_candidates.txt

# Non-PHP scripts in web root (shouldn't normally be there)
find /mnt/linux_mount/var/www \
  \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.cgi" \) \
  2>/dev/null
```

---

## Rootkit Detection

```bash
# Check ld.so.preload first — most common rootkit injection mechanism
if [[ -s /mnt/linux_mount/etc/ld.so.preload ]]; then
    echo "[CRITICAL] /etc/ld.so.preload is non-empty:"
    cat /mnt/linux_mount/etc/ld.so.preload
fi

# rkhunter scan against mounted image
sudo rkhunter \
  --check \
  --rootdir /mnt/linux_mount \
  --no-summary \
  --skip-keypress 2>/dev/null | tee ./exports/rkhunter_output.txt

# chkrootkit scan
sudo chkrootkit -r /mnt/linux_mount 2>/dev/null | \
  tee ./exports/chkrootkit_output.txt

# Package manager integrity check — detects replaced system binaries
# Debian/Ubuntu: dpkg -V flags files that differ from package records
dpkg --root=/mnt/linux_mount -V 2>/dev/null | \
  grep "^.M" | tee ./exports/modified_system_files.txt

# RHEL/CentOS: rpm -Va flags altered files
rpm --root=/mnt/linux_mount -Va 2>/dev/null | \
  tee ./exports/rpm_verify.txt

# Kernel module list from disk (use with Volatility linux.check_modules for diff)
find /mnt/linux_mount/lib/modules -name "*.ko" 2>/dev/null | \
  xargs -I{} basename {} .ko | sort > ./analysis/modules_on_disk.txt

# eBPF/BPFdoor — BPFdoor attaches an eBPF program to a raw network socket so it
# receives every packet; the backdoor is triggered by a magic packet rather than
# an open port, making it invisible to netstat/ss. Live-system check only:
#   grep packet_recvmsg /proc/*/stack 2>/dev/null
# From a UAC collection, look for raw sockets and deleted-but-running executables:
grep -i raw   "$UAC/live_response/network/ss.txt"    2>/dev/null
grep -i packet "$UAC/live_response/process/lsof.txt" 2>/dev/null
grep '(deleted)' "$UAC/live_response/process/lsof.txt" 2>/dev/null

# Hidden processes via /proc vs ps discrepancy — live-system or UAC only
# (/proc is a virtual filesystem; absent from disk images)
# From a UAC collection: compare the collected /proc PID listing to the ps snapshot
comm -23 \
  <(ls "$UAC/proc/" 2>/dev/null | grep -E '^[0-9]+$' | sort) \
  <(awk 'NR>1{print $2}' "$UAC/live_response/process/ps.txt" 2>/dev/null | sort) \
  2>/dev/null | tee ./exports/hidden_pids.txt

# Hidden process via /proc bind mount — attacker bind-mounts something over /proc/<pid>
# to hide the process; visible in the live mount table captured by UAC
# (/proc/mounts is virtual — not present in disk images; use UAC mount output)
grep -E '/proc/[0-9]+' "$UAC/live_response/system/mount.txt" 2>/dev/null | \
  tee ./exports/proc_bind_mounts.txt
```

Note: both `rkhunter` and `chkrootkit` can produce false positives against offline
mounted images. Triage their findings manually.

---

## Targeted Artifact Extraction (from Mounted Image)

Run these after mounting the evidence image to copy artifacts into `./exports/`
for offline analysis.

```bash
# /etc — accounts, SSH config, PAM, persistence config
sudo mkdir -p ./exports/etc/
sudo cp -rp /mnt/linux_mount/etc/passwd \
            /mnt/linux_mount/etc/shadow \
            /mnt/linux_mount/etc/group \
            /mnt/linux_mount/etc/sudoers \
            /mnt/linux_mount/etc/ssh/ \
            ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/sudoers.d  ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/ld.so.preload ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/ld.so.conf.d ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/crontab    ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/cron.d     ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/systemd    ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/profile.d  ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/profile    ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/bash.bashrc ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/bashrc      ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/zshenv      ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/zprofile    ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/zshrc       ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/fish        ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/sssd        ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/krb5.conf   ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/realmd.conf ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/aad.conf    ./exports/etc/ 2>/dev/null   # Canonical aad-auth
sudo cp -p  /mnt/linux_mount/etc/aadpasswd   ./exports/etc/ 2>/dev/null   # MS aadsshlogin NSS cache
sudo cp -rp /mnt/linux_mount/var/log/sssd    ./exports/sssd/ 2>/dev/null

# Logs (full /var/log)
sudo mkdir -p ./exports/logs/
sudo cp -rp /mnt/linux_mount/var/log ./exports/logs/

# Systemd journal (binary format — read offline with journalctl --directory)
sudo mkdir -p ./exports/journal/
sudo find /mnt/linux_mount/var/log/journal -name "*.journal" \
  -exec cp --parents {} ./exports/journal/ \; 2>/dev/null

# Audit log
sudo mkdir -p ./exports/audit/
sudo cp -p /mnt/linux_mount/var/log/audit/audit.log* ./exports/audit/ 2>/dev/null

# Shell histories (all users)
sudo mkdir -p ./exports/shell_history/
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  \( -name ".bash_history" -o -name ".zsh_history" -o -name ".zhistory" \
     -o -path "*/fish/fish_history" -o -name ".history" -o -name ".sh_history" \) \
  -exec cp --parents {} ./exports/shell_history/ \; 2>/dev/null

# Cron jobs (all locations)
sudo mkdir -p ./exports/cron/
for d in crontab cron.d cron.daily cron.hourly cron.weekly cron.monthly; do
    [[ -e /mnt/linux_mount/etc/$d ]] && \
        sudo cp -rp /mnt/linux_mount/etc/$d ./exports/cron/
done
sudo cp -rp /mnt/linux_mount/var/spool/cron ./exports/cron/spool/ 2>/dev/null

# Systemd service units (system and per-user)
sudo mkdir -p ./exports/systemd/
sudo cp -rp /mnt/linux_mount/etc/systemd/system \
            ./exports/systemd/etc_system/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/systemd/user \
            ./exports/systemd/etc_user/ 2>/dev/null
# /usr/lib/systemd/ is large — copy only modified/suspicious units selectively
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  -path "*/.config/systemd" \
  -exec cp --parents -r {} ./exports/systemd/ \; 2>/dev/null

# SSH authorized_keys (all users)
sudo mkdir -p ./exports/ssh_keys/
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "authorized_keys" \
  -exec cp --parents {} ./exports/ssh_keys/ \; 2>/dev/null

# Staging areas (disk image only — /dev/shm and /run are tmpfs, not captured in images)
sudo mkdir -p ./exports/staging/
sudo find /mnt/linux_mount/tmp \
          /mnt/linux_mount/var/tmp \
  -type f 2>/dev/null \
  -exec cp --parents {} ./exports/staging/ \; 2>/dev/null

# Web root (webshell hunting)
sudo mkdir -p ./exports/webroot/
sudo cp -rp /mnt/linux_mount/var/www ./exports/webroot/ 2>/dev/null

# Installed package snapshot
dpkg --root=/mnt/linux_mount -l \
  > ./exports/installed_packages_dpkg.txt 2>/dev/null
rpm --root=/mnt/linux_mount -qa \
  > ./exports/installed_packages_rpm.txt 2>/dev/null
```

---

## Timeline Integration

Pattern-based SKILL checks find artifacts by **location and content**.
A filesystem timeline or Plaso supertimeline adds **time-based discovery** — find what was missed,
confirm timing, and reconstruct the attacker's session. These are complementary, not overlapping.

| Format | Source | Content |
|--------|--------|---------|
| **bodyfile** | `fls -r -m / <image>` (Sleuth Kit) | Pipe-delimited, epoch timestamps, all four MAC+b per inode |
| **mactime** | `mactime -b bodyfile.txt` | Comma-delimited, human-readable dates |
| **mactime -y** | `mactime -y -b bodyfile.txt` | Comma-delimited, ISO 8601 — easiest to filter |
| **l2tcsv** | `psort.py -o l2tcsv plaso.sqlite` | Plaso CSV — filesystem + log sources in one timeline |
| **dynamic** | `psort.py -o dynamic plaso.sqlite` | Plaso richer CSV, similar columns to l2tcsv |

> Bodyfile and mactime generation: see `@~/.claude/skills/sleuthkit/SKILL.md`.
> Plaso supertimeline generation: see `@~/.claude/skills/plaso-timeline/SKILL.md`.

### Format Identification

```bash
# Identify format from header / first data line
head -2 ./analysis/timeline.*

# bodyfile:   pipe-delimited; first field is MD5 hash (32 hex chars) or "0"
# mactime:    comma-delimited; date field looks like "Mon Jan 15 2024 02:13:47"
# mactime -y: header "Date,Size,Type,Mode,UID/GID,Inode,File Name"
# l2tcsv:     header "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag"
# dynamic:    similar header to l2tcsv; may include additional columns
```

### Time-Window Sweep — All Files Modified During the Attack Window

Set T1/T2 from auth log timestamps, audit records, or an initial confirmed finding.
**Use ctime** ($10 in bodyfile) — it reflects the actual write time even when mtime was backdated.

```bash
# --- bodyfile ---
# Convert from human-readable: date -d "2024-01-15 02:00:00 UTC" +%s
T1=1705276800
T2=1705363199
awk -F'|' -v t1=$T1 -v t2=$T2 \
  '$10 >= t1 && $10 <= t2 {printf "%s\t%s\n", $10, $2}' ./analysis/bodyfile.txt | \
  sort -n | tee ./exports/timeline_window.txt

# --- mactime -y (ISO timestamps) ---
D1="2024-01-15 00:00:00"
D2="2024-01-15 23:59:59"
awk -F, -v d1="$D1" -v d2="$D2" \
  'NR>1 && $1>=d1 && $1<=d2' ./analysis/mactime_y.csv | \
  tee ./exports/timeline_window.txt

# --- l2tcsv / dynamic (Plaso supertimeline) ---
# All sources (auth log, filestat, syslog, etc.) in one sorted view:
awk -F, 'NR>1 && $1>="2024-01-15T00:00:00" && $1<="2024-01-15T23:59:59"' \
  ./analysis/plaso_supertimeline.csv | tee ./exports/timeline_window.txt

# Filesystem events only (source == FILE, parser == filestat):
grep ",FILE," ./exports/timeline_window.txt | tee ./exports/timeline_window_fs.txt
```

### IOC Cross-Reference — Confirm SKILL Findings in the Timeline

Bodyfile and mactime paths are image-root-relative (`/root/.backup/sshd`).
Strip the `/mnt/linux_mount` prefix before searching. Plaso paths are also prefix-free.

```bash
# Build a deduplicated list of flagged paths from SKILL exports
{
  grep -oP '"\K/[^"]+' ./exports/apt_hooks_suspicious.txt 2>/dev/null
  cat ./exports/package_manager_plugins_suspicious.txt 2>/dev/null
  cat ./exports/new_executables.txt 2>/dev/null
  grep -oP '(?<=/mnt/linux_mount)[^\s"]+' \
    ./exports/apt_hooks_binaries.txt ./exports/suid_binaries.txt 2>/dev/null
} | sed 's|^/mnt/linux_mount||' | sort -u > /tmp/ioc_paths.txt

# Look up each path in the timeline (works for all formats)
while IFS= read -r path; do
  hits=$(grep -cF "$path" ./analysis/timeline.* 2>/dev/null || true)
  [ "$hits" -gt 0 ] && echo "=== $path ===" && grep -hF "$path" ./analysis/timeline.*
done < /tmp/ioc_paths.txt | tee ./exports/timeline_ioc_hits.txt
```

### Cluster Pivot — Find the Full Toolkit Drop

Attackers drop their entire toolkit in one session. Taking the ctime of a confirmed malicious
file and finding everything within ±60 seconds routinely surfaces implants that pattern checks
missed because they were in unusual locations or had innocuous names.

```bash
# --- bodyfile ---
# bodyfile fields: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
#                   $1   $2   $3   $4  $5  $6  $7   $8   $9   $10  $11
PIVOT_CTIME=$(awk -F'|' '/\/root\/.backup\/sshd/{print $10; exit}' ./analysis/bodyfile.txt)
echo "Pivot ctime: $PIVOT_CTIME  ($(date -d @$PIVOT_CTIME -u '+%Y-%m-%d %H:%M:%S UTC'))"

awk -F'|' -v t=$PIVOT_CTIME \
  '$10 >= t-60 && $10 <= t+60 {printf "%s\t%s\n", $10, $2}' \
  ./analysis/bodyfile.txt | sort -n | tee ./exports/timeline_cluster.txt

# --- l2tcsv / dynamic (Plaso) ---
# The supertimeline pivot reveals correlated log events (SSH logins, commands, etc.)
# in addition to filesystem writes — reconstruct the full attacker session.
PIVOT_MINUTE="2024-01-15T02:13"   # same-minute window is usually sufficient
grep "^${PIVOT_MINUTE}" ./analysis/plaso_supertimeline.csv | \
  tee ./exports/timeline_cluster.txt
```

### Backdating Detection — mtime vs ctime Discrepancy

`touch -t` forges mtime and atime but **cannot** change ctime — ctime always reflects the last
inode write. A file with a years-old mtime but a recent ctime has been backdated. Requires bodyfile.

```bash
# Files whose ctime falls in the attack window but mtime is >7 days older
# (ctime in window = written during the attack; old mtime = backdated to blend in)
T1=1705276800
T2=1705363199
awk -F'|' -v t1=$T1 -v t2=$T2 \
  '$10 >= t1 && $10 <= t2 && $9 < $10 - 604800 && $2 !~ /^\/(proc|sys|dev|run)/' \
  ./analysis/bodyfile.txt | \
  awk -F'|' '{printf "delta:%4dd  mtime: %s  ctime: %s  %s\n",
    int(($10-$9)/86400), $9, $10, $2}' | \
  sort -rn | tee ./exports/timeline_backdated.txt
```

---

## Key File Paths Reference

| Artifact | Debian / Ubuntu | RHEL / CentOS |
|----------|----------------|---------------|
| User accounts | `/etc/passwd` | same |
| Password hashes | `/etc/shadow` | same |
| Group memberships | `/etc/group` | same |
| Sudoers | `/etc/sudoers`, `/etc/sudoers.d/` | same |
| SSH server config | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` | same |
| SSH authorized keys | `~/.ssh/authorized_keys` | same |
| LD_PRELOAD rootkit | `/etc/ld.so.preload` | same |
| Library paths | `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` | same |
| Crontab | `/etc/crontab`, `/etc/cron.d/` | same |
| User crontabs | `/var/spool/cron/crontabs/<user>` | `/var/spool/cron/<user>` |
| Systemd units (admin) | `/etc/systemd/system/` | same |
| Systemd units (packages) | `/usr/lib/systemd/system/` | same |
| Systemd user units (all users) | `/etc/systemd/user/` | same |
| Systemd user units (packages) | `/usr/lib/systemd/user/` | same |
| Systemd per-user units | `~/.config/systemd/user/` | same |
| SysV init scripts | `/etc/init.d/` | same |
| SysV runlevel links | `/etc/rc2.d/`, `/etc/rc3.d/`, `/etc/rc5.d/` | `/etc/rc.d/` |
| Legacy boot script | `/etc/rc.local` | `/etc/rc.d/rc.local` |
| Auth log | `/var/log/auth.log` | `/var/log/secure` |
| System log | `/var/log/syslog` | `/var/log/messages` |
| Kernel log | `/var/log/kern.log` | (included in messages) |
| Audit log | `/var/log/audit/audit.log` | same |
| Systemd journal | `/var/log/journal/<machine-id>/` | same |
| Cron log | `/var/log/cron.log` | `/var/log/cron` |
| Package install log | `/var/log/dpkg.log` | `/var/log/yum.log` |
| Login history (wtmp) | `/var/log/wtmp` | same |
| Failed logins (btmp) | `/var/log/btmp` | same |
| Last login per user | `/var/log/lastlog` | same |
| Apache logs | `/var/log/apache2/` | `/var/log/httpd/` |
| Nginx logs | `/var/log/nginx/` | same |
| Attacker staging (disk) | `/tmp/`, `/var/tmp/` | same |
| Attacker staging (tmpfs — live only) | `/dev/shm/`, `/run/` | same |
| Web root | `/var/www/html/` | `/var/www/html/` or `/srv/www/` |
| Kernel modules | `/lib/modules/<kernel>/` | same |
| Machine ID | `/etc/machine-id` | same |

---

## Notes

- Check `/etc/ld.so.preload` first on every Linux case — a non-empty file means
  every process loaded attacker code and the system cannot be trusted at all
- `rkhunter` and `chkrootkit` produce false positives on offline images; triage
  findings manually before treating them as confirmed
- Shell history lacks timestamps by default unless `HISTTIMEFORMAT` was set —
  absence of timestamps is expected, not suspicious
- `journalctl --directory` is preferred over `--file` when multiple journal files
  exist in a directory; use `--file` for a single specific journal file
- `ausearch -f <file>` reads an offline audit log; without `-f` it queries the
  live system — always specify `-f` for offline evidence
- Package integrity checks (`dpkg -V`, `rpm -Va`) detect replaced system binaries
  by comparing file hashes against the package database records
- Correlate across sources: cron persistence + new executable in /tmp + outbound
  connection spike typically represent a single attacker action chain
- For super-timeline generation across all log sources see
  `@~/.claude/skills/plaso-timeline/SKILL.md` — use `--parsers linux`

---

## Output Paths

| Output | Path |
|--------|------|
| Extracted /etc | `./exports/etc/` |
| System logs | `./exports/logs/` |
| Systemd journal | `./exports/journal/` |
| Audit log | `./exports/audit/` |
| Shell histories | `./exports/shell_history/` |
| Cron jobs | `./exports/cron/` |
| Systemd units | `./exports/systemd/` |
| SSH authorized keys | `./exports/ssh_keys/` |
| Staging files | `./exports/staging/` |
| Web root | `./exports/webroot/` |
| Installed packages | `./exports/installed_packages_*.txt` |
| SUID binaries list | `./exports/suid_binaries.txt` |
| New executables | `./exports/new_executables.txt` |
| rkhunter output | `./exports/rkhunter_output.txt` |
| chkrootkit output | `./exports/chkrootkit_output.txt` |
| Modified system files | `./exports/modified_system_files.txt` |
| YARA hits | `./exports/yara_hits/` |
| Timeline window (attack window filter) | `./exports/timeline_window.txt` |
| Timeline window — filesystem only (Plaso) | `./exports/timeline_window_fs.txt` |
| Timeline IOC cross-reference | `./exports/timeline_ioc_hits.txt` |
| Timeline cluster pivot | `./exports/timeline_cluster.txt` |
| Backdated files (mtime/ctime discrepancy) | `./exports/timeline_backdated.txt` |
| Reports | `./reports/` |
