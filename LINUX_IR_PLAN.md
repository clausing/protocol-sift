# Linux IR Support — Implementation Plan

This document captures the gap analysis and proposed changes needed to extend
protocol-sift from Windows-only DFIR to dual Windows/Linux incident response.
It is intended as a contributor reference for the implementation PR.

---

## Background

The underlying toolchain (TSK, Plaso, Volatility 3, YARA, EWF tools) is largely
cross-platform. The gaps are entirely in the **skill files**, which are the core
value of protocol-sift. An analyst hitting a Linux incident today would get
correct tool permissions but zero workflow guidance.

---

## Summary of Changes

| Priority | Type | File | Change |
|----------|------|------|--------|
| Critical | **New** | `skills/linux-artifacts/SKILL.md` | Full Linux artifact analysis skill (new) |
| Critical | Update | `skills/memory-analysis/SKILL.md` | Add Linux Volatility 3 section |
| Important | Update | `global/CLAUDE.md` | Add Linux routing entry + tool paths |
| Important | Update | `skills/plaso-timeline/SKILL.md` | Expand `linux` parser documentation |
| Important | Update | `skills/sleuthkit/SKILL.md` | Add Linux artifact extraction block |
| Important | Update | `case-templates/CLAUDE.md` | Add Linux case template section |
| Minor | Update | `skills/yara-hunting/SKILL.md` | Add ELF module + Linux Velociraptor |
| Minor | Update | `global/settings.json` | Add Linux tool permissions |
| Minor | Update | `install.sh` | Install new linux-artifacts skill dir |

---

## Evidence Types

Linux IR evidence typically arrives as one or more of these:

| Type | Description | Notes |
|------|-------------|-------|
| Disk image (E01) | Full disk acquired offline | Mount read-only; enables carving + unallocated analysis |
| Memory image (.lime) | LiME RAM capture | Volatility 3 Linux plugins; requires per-kernel ISF |
| UAC triage archive (.tar.gz) | Live-response collection via [UAC](https://github.com/tclahr/uac) | Volatile data captured; no carving; bodyfile pre-generated |

**When you have a UAC triage collection instead of (or alongside) a disk image:**

```bash
mkdir -p /cases/<case>/uac
tar -xzf /cases/<case>/<host>-<date>-uac.tar.gz -C /cases/<case>/uac/
UAC=$(ls -d /cases/<case>/uac/uac-*/ | head -1)
ls "$UAC"   # confirm structure before proceeding
```

Replace `/mnt/linux_mount` with `$UAC` in artifact commands below. UAC captures
volatile data (running processes, network state, `/dev/shm`, `/run`) that are absent
from disk images because they live on tmpfs. What UAC does NOT provide: unallocated
space, deleted file carving, or VSS snapshots. See `linux-artifacts/SKILL.md`
§ UAC Triage Collections for the full command set.

---

## Critical — New File: `skills/linux-artifacts/SKILL.md`

This is the highest-priority deliverable. It is the Linux equivalent of
`windows-artifacts/SKILL.md` (currently 721 lines). Without it, an analyst
has no skill-file guidance for persistence, logs, or user activity on a Linux host.

### Required sections

#### 1. Overview
- Linux forensics philosophy: text-based logs vs binary hives; no single registry
  equivalent; artifact locations vary by distro
- Distro path differences table: Debian/Ubuntu vs RHEL/CentOS for key artifacts

| Artifact | Debian/Ubuntu path | RHEL/CentOS path |
|----------|--------------------|------------------|
| Auth log | `/var/log/auth.log` | `/var/log/secure` |
| System log | `/var/log/syslog` | `/var/log/messages` |
| Cron log | `/var/log/cron.log` | `/var/log/cron` |
| Package log | `/var/log/dpkg.log` | `/var/log/yum.log` or `/var/log/dnf.log` |
| Audit log | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |

#### 2. User Account Analysis
Key files to extract and examine:
- `/etc/passwd` — all accounts (check for UID 0 duplicates, non-login shells)
- `/etc/shadow` — password hashes (check recently changed entries)
- `/etc/group` — group memberships (check for unexpected sudo/wheel members)
- `/etc/sudoers` and `/etc/sudoers.d/` — privilege escalation paths
- `~/.ssh/authorized_keys` for all users — backdoor key implantation
- `~/.ssh/config` and `/etc/ssh/ssh_config` — `ProxyCommand` executes arbitrary commands on SSH connect

> **Domain-joined hosts:** Domain accounts (AD via SSSD/winbind, or Azure AD via
> `aadsshlogin`) do NOT appear in `/etc/passwd`. Look for them in wtmp, auth.log,
> and `/var/log/sssd/`. Check `/etc/sssd/sssd.conf`, `/etc/aad.conf`, and PAM for
> `pam_sss` / `aad_ssh.so`.

```bash
# Find all UID 0 accounts (should only be root)
awk -F: '$3 == 0 {print $1}' /mnt/linux_mount/etc/passwd

# Find all accounts with a login shell
awk -F: '$7 !~ /(nologin|false)/ {print $1, $7}' /mnt/linux_mount/etc/passwd

# Find all authorized_keys across all users
find /mnt/linux_mount/home /mnt/linux_mount/root -name "authorized_keys" 2>/dev/null

# Check sudoers for ALL / NOPASSWD grants
grep -rE "(ALL|NOPASSWD)" /mnt/linux_mount/etc/sudoers \
  /mnt/linux_mount/etc/sudoers.d/ 2>/dev/null

# Suspect scripts/binaries listed explicitly in sudoers rules
# Flags: non-root owner (can chmod/replace), world-writable, or non-root-group-writable
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
  done

# Domain join detection
cat /mnt/linux_mount/etc/sssd/sssd.conf 2>/dev/null   # SSSD (on-prem AD)
cat /mnt/linux_mount/etc/aad.conf 2>/dev/null          # Azure AD / Entra ID
cat /mnt/linux_mount/etc/krb5.conf 2>/dev/null
grep -rl "pam_sss\|aad_ssh\|pam_aad\|pam_winbind" /mnt/linux_mount/etc/pam.d/ 2>/dev/null
cat /mnt/linux_mount/etc/aadpasswd 2>/dev/null     # MS aadsshlogin: NSS cache of AAD users
cat /mnt/linux_mount/etc/aad.conf 2>/dev/null      # Canonical aad-auth: tenant config
```

#### 3. Authentication Log Analysis

```bash
# All successful SSH logins (with source IP)
grep "Accepted" /mnt/linux_mount/var/log/auth.log | \
  awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn

# All failed SSH logins
grep "Failed" /mnt/linux_mount/var/log/auth.log | \
  awk '{print $9,$11}' | sort | uniq -c | sort -rn

# Sudo usage
grep "sudo:" /mnt/linux_mount/var/log/auth.log | grep "COMMAND"

# su to root
grep "session opened for user root" /mnt/linux_mount/var/log/auth.log

# New user/group creation
grep -E "(useradd|groupadd|usermod)" /mnt/linux_mount/var/log/auth.log

# Failed logins (binary wtmp format) — from mounted evidence
last -F -f /mnt/linux_mount/var/log/wtmp | head -100

# Failed login attempts (btmp)
lastb -F -f /mnt/linux_mount/var/log/btmp | head -100
```

#### 4. Systemd Journal (journalctl)

Reading the offline binary journal from a mounted image is non-obvious — document it:

```bash
# Find machine-id first — required to locate journal directory
cat /mnt/linux_mount/etc/machine-id

# Read journal from mounted evidence (key non-obvious workflow)
journalctl \
  --file /mnt/linux_mount/var/log/journal/<machine-id>/*.journal \
  --since "2023-01-24 00:00:00" --until "2023-01-26 23:59:59" \
  --utc --no-pager

# Filter by service
journalctl \
  --file /mnt/linux_mount/var/log/journal/<machine-id>/*.journal \
  -u sshd --utc --no-pager

# Filter by executable
journalctl \
  --file /mnt/linux_mount/var/log/journal/<machine-id>/*.journal \
  _EXE=/usr/sbin/sshd --utc --no-pager

# All sudo events from journal
journalctl \
  --file /mnt/linux_mount/var/log/journal/<machine-id>/*.journal \
  _COMM=sudo --utc --no-pager

# Kernel messages (dmesg equivalent — includes module loading)
journalctl \
  --file /mnt/linux_mount/var/log/journal/<machine-id>/*.journal \
  -k --utc --no-pager

# Export to JSON for scripted analysis
journalctl \
  --file /mnt/linux_mount/var/log/journal/<machine-id>/*.journal \
  --since "2023-01-24" --utc -o json > ./exports/journal_export.json
```

#### 5. Auditd Analysis

Auditd is the Linux equivalent of Windows process creation auditing + object access
auditing combined. Only valuable if auditd was running on the target.

```bash
# Check if auditd was configured
cat /mnt/linux_mount/etc/audit/auditd.conf
cat /mnt/linux_mount/etc/audit/rules.d/*.rules

# All execution events (requires auditd execve rule)
ausearch -i -sc execve -f /mnt/linux_mount/var/log/audit/audit.log

# Specific user's activity by UID
ausearch -i -ua <uid> -f /mnt/linux_mount/var/log/audit/audit.log

# Failed authentication events
ausearch -i -m USER_AUTH -sv no -f /mnt/linux_mount/var/log/audit/audit.log

# Network connection events (outbound)
ausearch -i -sc connect -f /mnt/linux_mount/var/log/audit/audit.log

# Sudo commands
ausearch -i -m USER_CMD -f /mnt/linux_mount/var/log/audit/audit.log

# Summary reports
aureport --summary -if /mnt/linux_mount/var/log/audit/audit.log
aureport -au --summary -if /mnt/linux_mount/var/log/audit/audit.log   # auth
aureport -x --summary -if /mnt/linux_mount/var/log/audit/audit.log    # executables
aureport --anomaly -if /mnt/linux_mount/var/log/audit/audit.log

# PROCTITLE is hex-encoded — decode it
ausearch -m EXECVE -if /mnt/linux_mount/var/log/audit/audit.log | \
  grep proctitle= | \
  python3 -c "
import sys
for line in sys.stdin:
    for field in line.split():
        if field.startswith('proctitle='):
            val = field.split('=',1)[1]
            try:
                print(bytes.fromhex(val).decode('utf-8', errors='replace'))
            except ValueError:
                print(val)
"
```

Key auditd record types:
| Type | Description |
|------|-------------|
| `EXECVE` | Command execution — contains argv |
| `SYSCALL` | System call with process context |
| `PATH` | File access path |
| `SOCKADDR` | Network connection destination |
| `USER_AUTH` | Authentication event |
| `USER_LOGIN` | Login event |
| `USER_CMD` | sudo command |
| `PROCTITLE` | Process title (hex-encoded full command) |
| `USER_START` | Session opened |
| `USER_END` | Session closed |

#### 6. Shell History

```bash
# All shell histories — bash, zsh, fish, tcsh/csh, ksh
for spec in \
  "bash:-name .bash_history" \
  "zsh:-name .zsh_history -o -name .zhistory" \
  "fish:-path */fish/fish_history" \
  "tcsh:-name .history" \
  "ksh:-name .sh_history"
do
  shell="${spec%%:*}"; pat="${spec#*:}"
  find /mnt/linux_mount/home /mnt/linux_mount/root $pat 2>/dev/null | \
    while IFS= read -r f; do echo "=== $f ==="; cat "$f"; done \
    | tee "./exports/${shell}_history_all.txt"
done

# Red flags across all shell histories
cat ./exports/*_history_all.txt 2>/dev/null | \
  grep -iE "(wget|curl|chmod \+x|base64|/dev/shm|/tmp/\.|nc |ncat |/bin/sh|python.*-c|perl.*-e)" \
  | tee ./exports/shell_history_suspicious.txt

# HISTFILE tampering indicator: HISTSIZE=0 or HISTFILESIZE=0 in RC files
grep -rE "(HISTSIZE=0|HISTFILESIZE=0|HISTFILE=/dev/null)" \
  /mnt/linux_mount/home/*/.bashrc \
  /mnt/linux_mount/home/*/.bash_profile \
  /mnt/linux_mount/root/.bashrc 2>/dev/null
```

#### 7. Persistence Mechanisms

This is the most critical section — Linux equivalent of the Windows ASEP analysis.

**Cron**
```bash
# System crontab
cat /mnt/linux_mount/etc/crontab

# Cron drop-in directories (any file here runs as cron)
ls -la /mnt/linux_mount/etc/cron.d/
ls -la /mnt/linux_mount/etc/cron.hourly/
ls -la /mnt/linux_mount/etc/cron.daily/
ls -la /mnt/linux_mount/etc/cron.weekly/
ls -la /mnt/linux_mount/etc/cron.monthly/

# Per-user crontabs
ls -la /mnt/linux_mount/var/spool/cron/crontabs/
for f in /mnt/linux_mount/var/spool/cron/crontabs/*; do
  echo "=== $(basename $f) ==="; cat "$f"; done

# Red flags: cron running from /tmp, /dev/shm, base64 decode, wget
grep -rE "(/tmp/|/dev/shm|base64|wget|curl|python|perl|bash -i)" \
  /mnt/linux_mount/etc/cron* \
  /mnt/linux_mount/var/spool/cron/ 2>/dev/null
```

**Systemd services and timers**
```bash
# System-wide service units — /etc (admin/attacker) and /usr/lib (packages)
ls -la /mnt/linux_mount/etc/systemd/system/*.service \
        /mnt/linux_mount/usr/lib/systemd/system/*.service 2>/dev/null

# Timer units — same two locations
ls -la /mnt/linux_mount/etc/systemd/system/*.timer \
        /mnt/linux_mount/usr/lib/systemd/system/*.timer 2>/dev/null

# System-wide user units (applied to all users; require root to create)
ls -la /mnt/linux_mount/etc/systemd/user/ 2>/dev/null
ls -la /mnt/linux_mount/usr/lib/systemd/user/ 2>/dev/null

# Per-user units (any user; also check .timer and .socket)
find /mnt/linux_mount/home /mnt/linux_mount/root \
  \( -path "*/.config/systemd/user/*.service" \
     -o -path "*/.config/systemd/user/*.timer" \
     -o -path "*/.config/systemd/user/*.socket" \) 2>/dev/null

# Inspect a suspicious service
cat /mnt/linux_mount/etc/systemd/system/<service-name>.service

# Red flags: scan all persistent unit locations
grep -rE "ExecStart=.*(\/tmp\/|\/dev\/shm\/|\/home\/|base64|bash -i)" \
  /mnt/linux_mount/etc/systemd/system/ \
  /mnt/linux_mount/etc/systemd/user/ \
  /mnt/linux_mount/usr/lib/systemd/system/ \
  /mnt/linux_mount/usr/lib/systemd/user/ \
  2>/dev/null

# Red flags in per-user units
find /mnt/linux_mount/home /mnt/linux_mount/root \
  -path "*/.config/systemd/user/*" \
  \( -name "*.service" -o -name "*.timer" \) 2>/dev/null | \
  xargs grep -lE "ExecStart=.*(\/tmp\/|\/dev\/shm\/|base64|bash -i)" 2>/dev/null
```

**SysV init scripts and rc.local**
```bash
# SysV init scripts (wrapped by systemd-sysv-generator on systemd hosts)
ls -la /mnt/linux_mount/etc/init.d/ 2>/dev/null

# Runlevel symlinks
ls -la /mnt/linux_mount/etc/rc2.d/ \
        /mnt/linux_mount/etc/rc3.d/ \
        /mnt/linux_mount/etc/rc5.d/ 2>/dev/null

# rc.local — executed by rc-local.service at boot if executable (check even on systemd)
ls -la /mnt/linux_mount/etc/rc.local 2>/dev/null
cat /mnt/linux_mount/etc/rc.local 2>/dev/null
# RHEL/CentOS:
cat /mnt/linux_mount/etc/rc.d/rc.local 2>/dev/null

# Red flags
grep -rE "(wget|curl|base64|bash -i|nc |/tmp/|/dev/shm)" \
  /mnt/linux_mount/etc/init.d/ \
  /mnt/linux_mount/etc/rc.local \
  /mnt/linux_mount/etc/rc.d/rc.local 2>/dev/null
```

**LD_PRELOAD / ld.so.preload (rootkit injection vector)**
```bash
# If this file exists it is loaded into EVERY process — high priority
cat /mnt/linux_mount/etc/ld.so.preload

# Dynamic linker configuration (additional library paths)
cat /mnt/linux_mount/etc/ld.so.conf
ls /mnt/linux_mount/etc/ld.so.conf.d/

# List non-standard shared libraries in library paths
find /mnt/linux_mount/usr/lib /mnt/linux_mount/usr/local/lib /mnt/linux_mount/lib \
  -name "*.so*" -newer /mnt/linux_mount/etc/passwd 2>/dev/null
```

**Kernel module loading**
```bash
# Modules loaded at boot
cat /mnt/linux_mount/etc/modules

# Module configuration (can specify options and aliases — also load malicious modules)
ls /mnt/linux_mount/etc/modprobe.d/
cat /mnt/linux_mount/etc/modprobe.d/*.conf 2>/dev/null

# Red flags: install directives that run arbitrary commands
grep -r "^install" /mnt/linux_mount/etc/modprobe.d/ 2>/dev/null
```

**Shell RC files (executed on every shell start)**
```bash
# System-wide RC files
cat /mnt/linux_mount/etc/profile
ls /mnt/linux_mount/etc/profile.d/
cat /mnt/linux_mount/etc/bash.bashrc 2>/dev/null        # Debian/Ubuntu
cat /mnt/linux_mount/etc/bashrc 2>/dev/null             # RHEL/CentOS
cat /mnt/linux_mount/etc/zshenv 2>/dev/null             # all zsh invocations (highest risk)
cat /mnt/linux_mount/etc/zprofile 2>/dev/null
cat /mnt/linux_mount/etc/zshrc 2>/dev/null
cat /mnt/linux_mount/etc/fish/config.fish 2>/dev/null
cat /mnt/linux_mount/etc/fish/conf.d/*.fish 2>/dev/null

# Per-user RC files
for user_home in /mnt/linux_mount/home/* /mnt/linux_mount/root; do
  for rc in .bashrc .bash_profile .profile .zshenv .zprofile .zshrc .zlogin; do
    f="$user_home/$rc"
    [ -f "$f" ] && echo "=== $f ===" && cat "$f"
  done
  f="$user_home/.config/fish/config.fish"
  [ -f "$f" ] && echo "=== $f ===" && cat "$f"
done

# Red flags: curl/wget downloads, base64 decodes, reverse shells
grep -rE "(curl|wget|base64|/dev/tcp|nc |ncat |python.*-c)" \
  /mnt/linux_mount/home/*/.bashrc \
  /mnt/linux_mount/home/*/.bash_profile \
  /mnt/linux_mount/root/.bashrc 2>/dev/null
```

**SUID/SGID binaries (lateral movement / persistence)**
```bash
# All SUID binaries on the mounted image
find /mnt/linux_mount -perm -4000 -type f 2>/dev/null | sort > ./exports/suid_binaries.txt

# All SGID binaries
find /mnt/linux_mount -perm -2000 -type f 2>/dev/null | sort > ./exports/sgid_binaries.txt

# Compare against expected SUID binaries for the distro
# Known-good SUID list varies by distro; flag anything not in /usr/bin or /usr/sbin
grep -v "^\(/mnt/linux_mount\)\?\(/usr/bin\|/usr/sbin\|/bin\|/sbin\)" ./exports/suid_binaries.txt

# Suspect SUID/SGID — non-root-owned, world-writable, or non-root-group-writable
find /mnt/linux_mount -xdev \( -perm -4000 -o -perm -2000 \) -type f \
  \( ! -user root -o -perm -o+w -o \( -perm -g+w ! -group root \) \) 2>/dev/null | \
  tee ./exports/writable_suid_sgid.txt
```

**Other persistence locations**
```bash
# AT jobs
ls /mnt/linux_mount/var/spool/at/ 2>/dev/null

# MOTD scripts (execute as root at every login)
ls -la /mnt/linux_mount/etc/update-motd.d/ 2>/dev/null

# Udev rules with RUN directives (execute on hardware events)
grep -r "^RUN" /mnt/linux_mount/etc/udev/rules.d/ 2>/dev/null

# XDG autostart (graphical sessions)
ls /mnt/linux_mount/etc/xdg/autostart/ 2>/dev/null
find /mnt/linux_mount/home -path "*/.config/autostart/*.desktop" 2>/dev/null

# PAM modules (authentication hook — can backdoor all logins)
ls /mnt/linux_mount/etc/pam.d/
# Flag any non-standard .so references
grep -rE "pam_\w+\.so" /mnt/linux_mount/etc/pam.d/ | grep -v "common-"

# SSH client config — ProxyCommand persistence
find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "config" -path "*/.ssh/*" 2>/dev/null | \
  xargs grep -li "ProxyCommand\|ControlMaster" 2>/dev/null

# APT hooks (Debian/Ubuntu) — execute on every apt/dpkg operation
ls /mnt/linux_mount/etc/apt/apt.conf.d/ 2>/dev/null
grep -rh "DPkg::\|APT::Update::" /mnt/linux_mount/etc/apt/apt.conf.d/ 2>/dev/null

# DNF/Yum plugins (RHEL/CentOS/Fedora) — Python loaded by package manager
ls /mnt/linux_mount/etc/dnf/plugins/ 2>/dev/null
find /mnt/linux_mount/usr/lib/python*/site-packages/dnf-plugins/ \
     /mnt/linux_mount/usr/lib/yum-plugins/ \
  -type f -name "*.py" 2>/dev/null
```

#### 8. Execution Evidence (without auditd)

When auditd was not running, these are the best execution evidence sources:

```bash
# Recently modified executables (attacker-dropped tools)
find /mnt/linux_mount -type f -executable -newer /mnt/linux_mount/etc/passwd \
  ! -path "*/proc/*" 2>/dev/null | sort > ./exports/new_executables.txt

# World-writable executables (dangerous)
find /mnt/linux_mount -type f -executable -perm -o+w 2>/dev/null

# Files in persistent staging areas (attacker drop zones)
# NOTE: /dev/shm and /run are tmpfs — not in disk images; capture live with Velociraptor
find /mnt/linux_mount/tmp /mnt/linux_mount/var/tmp \
  -type f 2>/dev/null

# Package manager logs reveal what was installed/removed and when
# Debian/Ubuntu:
grep " install " /mnt/linux_mount/var/log/dpkg.log | tail -50
# RHEL/CentOS:
grep " Installed:" /mnt/linux_mount/var/log/yum.log 2>/dev/null || \
grep " Installed" /mnt/linux_mount/var/log/dnf.log 2>/dev/null
```

#### 9. Rootkit Detection

```bash
# rkhunter against mounted image (may need --rootdir adjustment)
sudo rkhunter --check --rootdir /mnt/linux_mount --no-summary 2>/dev/null \
  | tee ./exports/rkhunter_output.txt

# chkrootkit (some checks require live system — note in findings)
sudo chkrootkit -r /mnt/linux_mount 2>/dev/null | tee ./exports/chkrootkit_output.txt

# Check /etc/ld.so.preload (rootkit injection — if this exists, treat as critical)
cat /mnt/linux_mount/etc/ld.so.preload

# Find deleted-but-open files (attacker deleted binary still running)
# Requires live system: lsof | grep "(deleted)"

# Check for kernel module hiding: compare /proc/modules to modinfo
# Requires live system; for offline: check /mnt/linux_mount/lib/modules/$(uname-r)/
find /mnt/linux_mount/lib/modules -name "*.ko" 2>/dev/null | \
  xargs -I{} basename {} .ko | sort > ./analysis/all_modules_on_disk.txt
```

#### 10. Web Server Artifacts

```bash
# Apache access log — attacker web shell usage leaves POST requests
grep "POST" /mnt/linux_mount/var/log/apache2/access.log 2>/dev/null | \
  grep -iE "\.(php|asp|jsp|py|sh|cgi)" | tail -100

# Common webshell locations
find /mnt/linux_mount/var/www /mnt/linux_mount/srv/www \
  /mnt/linux_mount/usr/share/nginx \
  -name "*.php" -newer /mnt/linux_mount/etc/passwd 2>/dev/null

# PHP files with eval+base64 (webshell pattern)
find /mnt/linux_mount/var/www -name "*.php" 2>/dev/null | \
  xargs grep -l "eval.*base64_decode\|system(\|exec(\|shell_exec(" 2>/dev/null

# Nginx access log
grep "POST" /mnt/linux_mount/var/log/nginx/access.log 2>/dev/null | \
  grep -iE "\.(php|sh|cgi)"
```

#### 11. Targeted Artifact Extraction (from mounted image)

Linux equivalent of `sleuthkit/SKILL.md` Step 12. Run these after mounting the image:

```bash
# /etc — all configuration files (accounts, SSH, services, PAM)
sudo mkdir -p ./exports/etc/
sudo cp -r /mnt/linux_mount/etc ./exports/etc/

# Logs
sudo mkdir -p ./exports/logs/
sudo cp -rp /mnt/linux_mount/var/log ./exports/logs/

# Shell histories — all users, all shells
sudo mkdir -p ./exports/shell_history/
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  \( -name ".bash_history" -o -name ".zsh_history" -o -name ".zhistory" \
     -o -path "*/fish/fish_history" -o -name ".history" -o -name ".sh_history" \) \
  -exec cp --parents {} ./exports/shell_history/ \; 2>/dev/null

# Systemd units
sudo mkdir -p ./exports/systemd/
sudo cp -rp /mnt/linux_mount/etc/systemd/system ./exports/systemd/etc_system/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/systemd/user   ./exports/systemd/etc_user/ 2>/dev/null
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  -path "*/.config/systemd" \
  -exec cp --parents -r {} ./exports/systemd/ \; 2>/dev/null

# Cron jobs
sudo mkdir -p ./exports/cron/
for d in crontab cron.d cron.daily cron.hourly cron.weekly cron.monthly; do
  [ -e /mnt/linux_mount/etc/$d ] && \
    sudo cp -rp /mnt/linux_mount/etc/$d ./exports/cron/
done
sudo cp -rp /mnt/linux_mount/var/spool/cron ./exports/cron/spool/ 2>/dev/null

# SSH authorized_keys (all users)
sudo mkdir -p ./exports/ssh_keys/
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "authorized_keys" -exec cp --parents {} ./exports/ssh_keys/ \; 2>/dev/null

# Installed packages snapshot
dpkg --root=/mnt/linux_mount -l > ./exports/installed_packages_dpkg.txt 2>/dev/null || \
  cat /mnt/linux_mount/var/lib/dpkg/status > ./exports/installed_packages_dpkg.txt 2>/dev/null
rpm --root=/mnt/linux_mount -qa > ./exports/installed_packages_rpm.txt 2>/dev/null

# /tmp, /var/tmp — persistent staging (attacker drop zones)
# /dev/shm and /run are tmpfs — absent from disk images; collect live with Velociraptor
sudo mkdir -p ./exports/staging/
sudo find /mnt/linux_mount/tmp /mnt/linux_mount/var/tmp \
  -type f 2>/dev/null | \
  xargs -I{} cp --parents {} ./exports/staging/ 2>/dev/null

# Audit log
sudo mkdir -p ./exports/audit/
sudo cp -p /mnt/linux_mount/var/log/audit/audit.log ./exports/audit/ 2>/dev/null

# Systemd journal
sudo mkdir -p ./exports/journal/
sudo find /mnt/linux_mount/var/log/journal -name "*.journal" \
  -exec cp --parents {} ./exports/journal/ \; 2>/dev/null
```

#### 12. Key File Paths Reference Table

| Artifact | Path (Debian/Ubuntu) | Path (RHEL/CentOS) |
|----------|---------------------|---------------------|
| User accounts | `/etc/passwd` | same |
| Password hashes | `/etc/shadow` | same |
| Sudoers | `/etc/sudoers`, `/etc/sudoers.d/` | same |
| SSH authorized keys | `~/.ssh/authorized_keys` | same |
| SSH server config | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` | same |
| LD_PRELOAD | `/etc/ld.so.preload` | same |
| Crontab | `/etc/crontab`, `/etc/cron.d/` | same |
| User crontabs | `/var/spool/cron/crontabs/` | `/var/spool/cron/` |
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
| Kernel log | `/var/log/kern.log` | included in `/var/log/messages` |
| Audit log | `/var/log/audit/audit.log` | same |
| Systemd journal | `/var/log/journal/<machine-id>/` | same |
| Cron log | `/var/log/cron.log` | `/var/log/cron` |
| Package log | `/var/log/dpkg.log` | `/var/log/yum.log` |
| Login history (binary) | `/var/log/wtmp` | same |
| Failed logins (binary) | `/var/log/btmp` | same |
| Last login per user | `/var/log/lastlog` | same |
| Apache logs | `/var/log/apache2/` | `/var/log/httpd/` |
| Nginx logs | `/var/log/nginx/` | same |
| Temp staging (disk) | `/tmp/`, `/var/tmp/` | same |
| Temp staging (tmpfs — live only) | `/dev/shm/`, `/run/` | same |
| Web root | `/var/www/html/` | `/var/www/html/` or `/srv/www/` |

#### 13. Output Paths

Consistent with existing case structure:

| Output | Path |
|--------|------|
| Extracted /etc | `./exports/etc/` |
| Logs | `./exports/logs/` |
| Shell histories | `./exports/shell_history/` |
| Cron jobs | `./exports/cron/` |
| SSH keys | `./exports/ssh_keys/` |
| Systemd units | `./exports/systemd/` |
| Audit log | `./exports/audit/` |
| Journal | `./exports/journal/` |
| SUID binaries list | `./exports/suid_binaries.txt` |
| rkhunter output | `./exports/rkhunter_output.txt` |
| Package list | `./exports/installed_packages_*.txt` |
| Staging files | `./exports/staging/` |
| Analysis text | `./analysis/` |
| Reports | `./reports/` |

---

## Critical — Update: `skills/memory-analysis/SKILL.md`

Add a new major section after the existing Windows content: **Linux Memory Forensics**.

### New section content

#### Linux Symbol Requirements

This is the most important difference from Windows memory analysis. Windows symbols
are auto-downloaded from Microsoft's PDB server. Linux requires manual ISF generation
for each specific kernel version.

```bash
# Check if a pre-built ISF already exists for the target kernel
ls /opt/volatility3-*/volatility3/symbols/linux/
```

**Priority order for ISF generation:**

**Option 1 — Pre-built symbols (try first):**
```bash
# https://github.com/Abyss-W4tcher/volatility3-symbols
# Covers common Ubuntu / Debian / CentOS / RHEL kernels
```

**Option 2 — btf2json (preferred for kernels ≥ 5.2):**
BTF is embedded in the kernel binary — no debug package needed. Available when
`CONFIG_DEBUG_INFO_BTF=y` (default on Ubuntu 20.04+, Debian 11+, RHEL 8.3+).
Tool: https://github.com/vobst/btf2json
```bash
# Confirm BTF is present in the target kernel
grep CONFIG_DEBUG_INFO_BTF /mnt/linux_mount/boot/config-<kernel-version>

# Collect System.map from the target boot partition
cp /mnt/linux_mount/boot/System.map-<kernel-version> /tmp/

# vmlinuz is compressed — extract uncompressed kernel first
# (extract-vmlinux script is in linux-headers or kernel-source package)
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux \
  /mnt/linux_mount/boot/vmlinuz-<kernel-version> > /tmp/vmlinux

# Generate ISF (outputs to stdout)
btf2json --btf /tmp/vmlinux --map /tmp/System.map-<kernel-version> \
  > /opt/volatility3-*/volatility3/symbols/linux/<distro>-<kernel-version>.json
xz /opt/volatility3-*/volatility3/symbols/linux/<distro>-<kernel-version>.json
```

**Option 3 — dwarf2json (fallback for older kernels without BTF):**
Requires the debug kernel package for the exact kernel version.
```bash
# Debian/Ubuntu
sudo apt install linux-image-<exact-kernel-version>-dbg
# RHEL/CentOS
sudo yum install kernel-debuginfo-<exact-kernel-version>

dwarf2json linux \
  --elf /usr/lib/debug/boot/vmlinux-<exact-kernel-version> \
  > /opt/volatility3-*/volatility3/symbols/linux/<distro>-<kernel-version>.json
xz /opt/volatility3-*/volatility3/symbols/linux/<distro>-<kernel-version>.json
```

#### Linux Plugin Reference

```bash
alias vol="python3 /opt/volatility3-2.20.0/vol.py"

# Run linux.info first — confirms symbols loaded correctly
vol -f <image.img> linux.info
```

| Plugin | Purpose | Key analogue |
|--------|---------|--------------|
| `linux.pslist` | Process list via task_struct | `windows.pslist` |
| `linux.psscan` | Pool scan for hidden processes | `windows.psscan` |
| `linux.pstree` | Parent-child process tree | `windows.pstree` |
| `linux.psaux` | Process list with full argv | `windows.cmdline` |
| `linux.envars` | Environment variables per process | `windows.envars` |
| `linux.bash` | Bash history from memory | (no Windows equivalent) |
| `linux.lsmod` | Loaded kernel modules | `windows.modules` |
| `linux.check_modules` | **Detect hidden LKMs** | `windows.modscan` diff |
| `linux.check_syscall` | **Detect syscall table hooks** | (no Windows equivalent) |
| `linux.check_creds` | **Detect uid-0 sharing (privesc)** | (no Windows equivalent) |
| `linux.tty_check` | Detect TTY hook (keylogger) | (no Windows equivalent) |
| `linux.netfilter` | Netfilter hook enumeration | (no Windows equivalent) |
| `linux.netstat` | Network connections | `windows.netstat` |
| `linux.lsof` | Open file descriptors | `windows.handles` |
| `linux.elfs` | ELF files in process memory | `windows.dlllist` |
| `linux.malfind` | Injected code / anomalous memory | `windows.malfind` |
| `linux.procmaps` | Process memory maps (/proc/PID/maps) | `windows.vadinfo` |
| `linux.mountinfo` | Mount points per namespace | — |
| `linux.pid_namespace` | PID namespaces (containers) | — |
| `linux.kmsg` | Kernel message buffer | — |

```bash
# Standard opening set for Linux IR
vol -f <image.img> linux.pslist  > ./analysis/memory/pslist.txt
vol -f <image.img> linux.psscan  > ./analysis/memory/psscan.txt
vol -f <image.img> linux.psaux   > ./analysis/memory/psaux.txt
vol -f <image.img> linux.netstat > ./analysis/memory/netstat.txt

# Rootkit checks — run these on every Linux case
vol -f <image.img> linux.check_syscall  > ./analysis/memory/check_syscall.txt
vol -f <image.img> linux.check_modules  > ./analysis/memory/check_modules.txt
vol -f <image.img> linux.check_creds    > ./analysis/memory/check_creds.txt
vol -f <image.img> linux.tty_check      > ./analysis/memory/tty_check.txt
vol -f <image.img> linux.netfilter      > ./analysis/memory/netfilter.txt

# Bash history from memory (often survives even if .bash_history was cleared)
vol -f <image.img> linux.bash > ./analysis/memory/bash_history.txt

# Kernel module check: lsmod lists visible modules; check_modules finds hidden ones
vol -f <image.img> linux.lsmod         > ./analysis/memory/lsmod.txt
# Any module in check_modules output NOT in lsmod = hidden LKM rootkit

# Code injection (same concept as Windows malfind)
vol -f <image.img> linux.malfind --dump --output-dir ./exports/malfind/
```

#### Linux-Specific Six-Step Methodology

1. **Enumerate processes** — `linux.pslist` + `linux.psscan`; discrepancies = hidden process
2. **Review process arguments** — `linux.psaux`; look for reverse shells, encoded payloads
3. **Check network connections** — `linux.netstat`; extract unique external IPs
4. **Rootkit indicators** — `linux.check_syscall` (hooks), `linux.check_modules` (hidden LKMs), `linux.check_creds` (uid-0 sharing), `linux.tty_check` (keylogger), `linux.netfilter` (firewall manipulation)
5. **Bash history from memory** — `linux.bash`; often survives log clearing
6. **Injected code** — `linux.malfind`; dump and triage hits

#### Linux Process Anomaly Indicators

| Anomaly | What to Look For |
|---------|-----------------|
| PID 1 wrong | Should be `systemd` or `init`; anything else is suspicious |
| Kernel threads | Should appear in brackets `[kworker/0:0]` in name; user process in brackets = hiding |
| Orphaned process | PPID points to non-existent PID |
| Short-lived processes | Exited rapidly — atomic attacker commands |
| Shell spawned from web server | `bash` or `sh` child of `nginx`, `apache2`, `php-fpm` = webshell execution |
| Unexpected interpreter | `python`, `perl`, `ruby` as standalone long-running process |
| Process with deleted executable | `/proc/PID/exe` points to `(deleted)` path |
| Uid 0 sharing | `linux.check_creds` finds processes sharing root credentials = privesc |
| Modified syscall table | `linux.check_syscall` shows non-kernel addresses = syscall hook rootkit |
| Hidden kernel module | In `linux.check_modules` but absent from `linux.lsmod` = LKM rootkit |

---

## Important — Update: `global/CLAUDE.md`

### Changes needed

**1. Add Linux artifact routing entry to the Tool Routing table:**

```markdown
| Linux artifacts (logs / persistence / execution) | `@~/.claude/skills/linux-artifacts/SKILL.md` |
```

**2. Add Linux-specific tools to the Installed Tool Paths table:**

| Tool | Invocation | Notes |
|------|-----------|-------|
| **journalctl** | `journalctl --file <journal> --utc` | Read offline journal from mounted evidence |
| **ausearch** | `ausearch -i -f <audit.log>` | Search auditd records |
| **aureport** | `aureport --summary -if <audit.log>` | Summarize auditd log |
| **rkhunter** | `sudo rkhunter --check --rootdir /mnt/linux_mount` | Rootkit detection |
| **chkrootkit** | `sudo chkrootkit -r /mnt/linux_mount` | Rootkit detection |
| **last / lastb** | `last -F -f <wtmp>` / `lastb -F -f <btmp>` | Login history |
| **lsmod** | `lsmod` | Kernel module listing (live system) |
| **btf2json** | `btf2json --btf <vmlinux> --map System.map` | Generate Volatility Linux ISF (kernels ≥ 5.2, no debug pkg needed) |
| **dwarf2json** | `dwarf2json linux --elf <vmlinux>` | Generate Volatility Linux ISF (fallback for older kernels) |

**3. Add note about Linux symbol requirements** after the Vol3 tool path entry.

---

## Important — Update: `skills/plaso-timeline/SKILL.md`

### Changes needed

**1. Expand the `linux` parser preset entry** in the Common parser presets table with a note about what it covers.

**2. Add a "Linux Timeline Workflow" section** with worked examples:

```bash
# HOST_TZ: syslog/auth.log use local time — must match host's configured timezone
# (systemd_journal and mactime are epoch-based; always use UTC for those)
HOST_TZ=$(cat /mnt/linux_mount/etc/timezone 2>/dev/null || echo "UTC")

# Full Linux image ingest
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_linux.plaso \
  --parsers linux \
  --hashers md5 \
  --timezone "${HOST_TZ}" \
  /mnt/linux_mount/

# Targeted: just logs directory (fast — avoids parsing entire filesystem)
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_logs.plaso \
  --parsers linux \
  --timezone "${HOST_TZ}" \
  /mnt/linux_mount/var/log/

# Parse offline systemd journal (epoch-based — always UTC)
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_journal.plaso \
  --parsers systemd_journal \
  --timezone UTC \
  ./exports/journal/

# image_export.py: extract Linux artifact paths from image
image_export.py \
  --write ./exports/files/ \
  --filter /path/to/linux_filter.txt \
  /mnt/ewf/ewf1

# Example linux_filter.txt contents:
#   /etc/passwd
#   /etc/shadow
#   /etc/cron.d/
#   /var/log/
#   /home/*/.bash_history
#   /home/*/.zsh_history
#   /home/*/.zhistory
#   /home/*/.history
#   /home/*/.sh_history
#   /home/*/.local/share/fish/fish_history
#   /root/.bash_history
#   /root/.zsh_history
#   /root/.zhistory
#   /root/.history
#   /root/.sh_history
#   /root/.local/share/fish/fish_history
#   /etc/systemd/system/*.service
```

**3. Document what the `linux` parser preset covers:** syslog, auth.log, bash_history,
dpkg.log, apt_history, utmp/wtmp, cron logs, systemd_journal (separate parser),
and mactime bodyfiles from `fls`.

---

## Important — Update: `skills/sleuthkit/SKILL.md`

### Changes needed

**Add a "Linux Targeted Artifact Extraction" subsection** to Step 12 (currently only
has Windows paths). Key extractions:

```bash
# /etc — accounts, SSH config, PAM, persistence config
sudo find /mnt/linux_mount/etc -type f \
  \( -name "passwd" -o -name "shadow" -o -name "sudoers" \
     -o -name "crontab" -o -name "sshd_config" \
     -o -path "*/sshd_config.d/*" \
     -o -name "ld.so.preload" \) \
  -exec cp --parents {} ./exports/etc/ \; 2>/dev/null

# Auth logs
sudo cp -rp /mnt/linux_mount/var/log/auth.log ./exports/logs/ 2>/dev/null || \
sudo cp -rp /mnt/linux_mount/var/log/secure   ./exports/logs/ 2>/dev/null

# Systemd journal (binary format — copy first, then read with journalctl)
sudo find /mnt/linux_mount/var/log/journal -name "*.journal" \
  -exec cp --parents {} ./exports/journal/ \; 2>/dev/null

# Shell histories — all shells
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  \( -name ".bash_history" -o -name ".zsh_history" -o -name ".zhistory" \
     -o -path "*/fish/fish_history" -o -name ".history" -o -name ".sh_history" \) \
  -exec cp --parents {} ./exports/shell_history/ \; 2>/dev/null
```

**Add ext4 notes:**
- Root directory inode on ext4 is **inode 2** (not inode 5 as on NTFS)
- `norecovery` prevents journal replay on all journaled filesystems (NTFS, ext3/ext4, XFS);
  use `ro,nosuid,noexec,nodev,norecovery` for evidence mounts of these types; Btrfs needs only `ro,nosuid,noexec,nodev`
- Use `fls -f ext4` (or `ext3`) when forcing filesystem type; TSK does not support XFS

---

## Minor — Update: `skills/yara-hunting/SKILL.md`

### 1. Add ELF module section

Add after the existing PE module section:

```yara
import "elf"
import "math"

// Detect stripped ELF (no symbol table — common for malware)
rule Stripped_ELF {
    meta:
        description = "ELF binary with no symbol table (stripped)"
    condition:
        uint32(0) == 0x464C457F and
        not for any section in elf.sections : (section.name == ".symtab")
}

// Detect UPX-packed ELF
rule UPX_Packed_ELF {
    meta:
        description = "ELF binary packed with UPX"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upxbang = "UPX!" ascii
    condition:
        uint32(0) == 0x464C457F and any of them
}

// Detect suspicious shared library exporting common rootkit hooks
rule LD_PRELOAD_Rootkit {
    meta:
        description = "Shared library exporting multiple common system call hooks"
    strings:
        $h1 = "readdir"    ascii
        $h2 = "getdents"   ascii
        $h3 = "getdents64" ascii   // classic rootkit: hides files
        $h4 = "open64"     ascii
        $h5 = "fopen"      ascii
        $h6 = "write"      ascii
        $h7 = "read"       ascii
        $h8 = "connect"    ascii   // C2 connection hiding
    condition:
        elf.type == elf.ET_DYN and 3 of them
}

// High-entropy ELF (packed/encrypted payload)
rule High_Entropy_ELF {
    meta:
        description = "ELF binary with high overall entropy"
    condition:
        uint32(0) == 0x464C457F and
        math.entropy(0, filesize) > 7.2
}
```

**Useful ELF module fields:**
| Field | Description |
|-------|-------------|
| `elf.type` | `ET_EXEC` (executable), `ET_DYN` (shared lib), `ET_CORE` (core dump) |
| `elf.machine` | `EM_386`, `EM_X86_64`, `EM_ARM`, `EM_AARCH64` |
| `elf.number_of_sections` | Section count |
| `elf.sections[i].name` | Section name (`.text`, `.data`, `.bss`) |
| `elf.number_of_segments` | Program header count |
| `elf.symtab_entries` | Symbol table entries (0 = stripped) |
| `elf.dynsym_entries` | Dynamic symbol entries |

### 2. Update Linux scan targets

```bash
# Scan mounted Linux filesystem for suspicious ELF binaries
yara -r /path/to/linux_rules.yar /mnt/linux_mount/bin/ 2>/dev/null
yara -r /path/to/linux_rules.yar /mnt/linux_mount/usr/bin/ 2>/dev/null
yara -r /path/to/linux_rules.yar /mnt/linux_mount/usr/local/bin/ 2>/dev/null

# High-value Linux targets: staging areas, web roots, library paths
yara -r /path/to/linux_rules.yar /mnt/linux_mount/tmp/ 2>/dev/null
yara -r /path/to/linux_rules.yar /mnt/linux_mount/var/tmp/ 2>/dev/null
yara -r /path/to/linux_rules.yar /mnt/linux_mount/var/www/ 2>/dev/null
yara -r /path/to/linux_rules.yar /mnt/linux_mount/usr/lib/ 2>/dev/null
yara -r /path/to/linux_rules.yar /mnt/linux_mount/usr/local/lib/ 2>/dev/null
```

### 3. Add Linux Velociraptor artifacts

Add alongside the existing Windows artifacts table:

| Artifact | Purpose |
|----------|---------|
| `Linux.Sys.Pslist` | Process listing |
| `Linux.Sys.Crontab` | All cron jobs |
| `Linux.Persistence.CronJob` | Detect suspicious cron entries |
| `Linux.Sys.Users` | User accounts (/etc/passwd) |
| `Linux.Network.Netstat` | Active network connections |
| `Linux.Forensics.BashHistory` | Shell command history |
| `Linux.Forensics.Wtmp` | Login/logout history |
| `Linux.Sys.Lsmod` | Loaded kernel modules |
| `Linux.Sys.Services` | Systemd service state |
| `Linux.Sys.OpenFiles` | Open file descriptors (per process) |
| `Linux.Detection.Yara.Process` | YARA scan of process memory |
| `Linux.Detection.Yara.File` | YARA scan of files on disk |
| `Linux.Detection.Rootkit` | Common rootkit indicators |

---

## Minor — Update: `global/settings.json`

Add to the `permissions.allow` array:

```json
"Bash(journalctl *)",
"Bash(ausearch *)",
"Bash(aureport *)",
"Bash(rkhunter *)",
"Bash(chkrootkit *)",
"Bash(last *)",
"Bash(lastb *)",
"Bash(lsmod *)",
"Bash(modinfo *)",
"Bash(getfattr *)",
"Bash(systemctl *)",
"Bash(dwarf2json *)"
```

---

## Minor — Update: `case-templates/CLAUDE.md`

Add a Linux case template section (or create `case-templates/linux-CLAUDE.md`).
A Linux case needs different metadata fields than a Windows domain investigation:

```markdown
## Case Overview

| Field | Value |
|-------|-------|
| **Client** | <Client Name> |
| **Host(s)** | <hostname(s)> — <role: web server / jump box / build server / etc.> |
| **OS** | Ubuntu 22.04 / Debian 11 / RHEL 8 / etc. |
| **Kernel** | <uname -r output — needed for Volatility Linux symbols> |
| **Init System** | systemd / SysV |
| **Timezone** | <e.g. America/New_York — affects syslog/auth.log timestamps; journald/auditd readable in UTC regardless> |
| **Auditd Running** | Yes / No / Unknown |
| **Threat Actor** | <name if known> |
| **Incident Declared** | <date UTC> |
| **Your Role** | External IR consultant |

## Evidence Files

| File | System | Notes |
|------|--------|-------|
| `/cases/<case>/disk.E01` | <hostname> | Full disk (~X GB) |
| `/cases/<case>/memory.lime` | <hostname> | LiME memory capture (X GB) |

## Common Commands

### Mount image (read-only)
```bash
sudo mkdir -p /mnt/ewf /mnt/linux_mount
sudo ewfmount /cases/<case>/disk.E01 /mnt/ewf
OFFSET=$(sudo mmls /mnt/ewf/ewf1 | awk '/Linux/{print $3; exit}')
sudo mount -o ro,loop,nosuid,noexec,nodev,norecovery,offset=$((OFFSET*512)) /mnt/ewf/ewf1 /mnt/linux_mount
```

### Key paths on this host
- Web root: `/var/www/html/` 
- App directory: `<path if known>`
- Non-standard services: `<list>`

## Network Topology
...

## Key Accounts

| Account | UID | Role |
|---------|-----|------|
| root | 0 | System root |
| <attacker-added account> | <uid> | Backdoor account |

## Known IOCs

| Indicator | Type | Detail |
|-----------|------|--------|
| `<sha256>` | ELF hash | Dropped binary at `/tmp/<name>` |
| `<ip>` | C2 IP | Seen in `linux.netstat` and auth.log |
| `<service-name>.service` | Systemd persistence | Unit at `/etc/systemd/system/` |

## Incident Timeline (UTC)
...
```

---

## Minor — Update: `install.sh`

Add `linux-artifacts` skill directory to the mkdir and cp blocks:

```bash
# In the mkdir block:
mkdir -p ~/.claude/skills/linux-artifacts \

# In the cp block:
cp skills/linux-artifacts/SKILL.md ~/.claude/skills/linux-artifacts/SKILL.md
```

And add the manual install reference in `README.md`.

---

## Implementation Order

1. `skills/linux-artifacts/SKILL.md` — new file, highest value, unblocks all Linux IR
2. `skills/memory-analysis/SKILL.md` — Linux Volatility section (symbol workflow is non-obvious)
3. `global/CLAUDE.md` — routing + tool paths (enables Claude to find the new skill)
4. `skills/plaso-timeline/SKILL.md` — linux parser workflow examples
5. `skills/sleuthkit/SKILL.md` — Linux extraction paths
6. `skills/yara-hunting/SKILL.md` — ELF module + Linux Velociraptor
7. `global/settings.json` — Linux tool permissions
8. `case-templates/CLAUDE.md` — Linux case template
9. `install.sh` + `README.md` — installer and documentation updates
