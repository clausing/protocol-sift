# Skill: Linux Persistence Mechanisms

## Overview
Use this skill for Linux persistence mechanism analysis on the SIFT workstation.
Covers all common attacker-controlled execution-at-boot or execution-at-login
locations found on Debian/Ubuntu and RHEL/CentOS/Fedora hosts.

> **Part of the Linux artifacts workflow.** This skill is loaded on-demand for
> persistence checks. For the full investigation workflow — mount procedures, logs,
> auditd, shell history, rootkits, and timeline integration — see
> `@~/.claude/skills/linux-artifacts/SKILL.md`.
>
> **Evidence mount assumption:** Commands below use `/mnt/linux_mount` as the
> read-only mount point for the target Linux filesystem. For ext4/XFS/Btrfs/LVM
> mount procedures, see `@~/.claude/skills/sleuthkit/SKILL.md`.

---

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
