# Skill: File System & Carving (The Sleuth Kit / EWF Tools)

## Overview
Use this skill for disk image analysis, filesystem navigation, file extraction, and
file carving on the SIFT workstation. Evidence images are commonly in E01 (Expert Witness
Format). Always mount read-only to preserve evidence integrity.

> **TSK filesystem support:** The Sleuth Kit tools (`fls`, `icat`, `fsstat`, `mactime`,
> `ils`, `blkls`) support **ext2/3/4**, NTFS, FAT, exFAT, and HFS+ only.
> They **cannot** read XFS, Btrfs, or LVM logical volumes.
>
> For Linux evidence on XFS, Btrfs, or LVM:
> - `ewfmount`, `mmls`, `ewfinfo`, `ewfverify`, `bulk_extractor`, and file carving still work
> - Mount the image and work from `/mnt/linux_mount/` using native Linux tools and Plaso
> - See the **LVM Activation** and **XFS / Btrfs** sections below for mount workflows
> - See `@~/.claude/skills/linux-artifacts/SKILL.md` for artifact extraction from the mounted path

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| `ewfinfo` | Display E01 image metadata and embedded hash values |
| `ewfverify` | Verify E01 image integrity against stored hashes |
| `ewfmount` | Mount E01/EWF images as a raw disk device |
| `img_stat` | Display image format and sector size |
| `mmls` | Display partition table (MBR and GPT) |
| `fsstat` | Filesystem metadata (cluster size, MFT location, etc.) |
| `fls` | List files and directories (includes deleted entries) |
| `icat` | Extract file content by inode/MFT number |
| `istat` | Display inode metadata (MAC times, size, allocated blocks) |
| `ffind` | Find filename for an inode |
| `ils` | List inodes (including orphan/deleted) |
| `blkls` | Extract unallocated disk blocks (for carving) |
| `tsk_recover` | Bulk extract all allocated and/or unallocated files |
| `mactime` | Generate timeline from bodyfile |
| `blkcat` | Extract raw data unit content |
| `bulk_extractor` | Carve email addresses, URLs, domains, credit cards, etc. |
| `photorec` | File carving by file signature |

---

## Workflow

### 1. Verify the Image

```bash
# Display E01 metadata (acquisition hash, timestamps, notes)
ewfinfo /cases/<casename>/<image>.E01

# Verify integrity — compare computed vs stored hash
ewfverify /cases/<casename>/<image>.E01
```

Record the MD5/SHA1 from `ewfinfo` output in your case notes. `ewfverify` must complete
without errors before any analysis proceeds.

### 2. Mount E01 Image (Read-Only)

```bash
# Create mount points
sudo mkdir -p /mnt/ewf /mnt/windows_mount

# Mount the E01 via ewfmount (exposes as /mnt/ewf/ewf1)
# For multi-segment images (E01, E02, ... or .e01, .e02, ...), point to the first segment only
sudo ewfmount /cases/<casename>/<image>.E01 /mnt/ewf/

# Confirm the raw device is present
ls /mnt/ewf/
# Expected: ewf1
```

**Multi-segment E01:** `ewfmount` automatically detects and joins all segments when you
specify the first segment. No glob or special syntax needed.

### 3. Check Sector Size

```bash
# Default is 512 bytes; some modern drives use 4096 (4K) sector size
img_stat /mnt/ewf/ewf1

# Look for "Sector Size" in output — use this value in offset calculations
# If 4096: OFFSET = Start_sector * 4096
```

### 4. Inspect Partition Table

```bash
sudo mmls /mnt/ewf/ewf1
# Note the Start sector and sector size for the target partition
```

Example output (512-byte sectors):
```
     Slot    Start        End          Length       Description
00:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
01:  -----   0000000000   0000002047   0000002048   Unallocated
02:  000:00  0000002048   0000534527   0000532480   NTFS / exFAT (0x07)
03:  000:01  0000534528   ...          ...          Recovery
```

**GPT disks:** `mmls` handles GPT automatically — look for partition type GUIDs.

**LVM detection:** If `mmls` shows a partition type of `Linux LVM` (MBR type `0x8e`)
or GPT GUID `E6D6D379-F507-44C2-A23C-238F2A3DF928`, do not proceed to Step 5 below —
go to **LVM Activation** instead. Mounting an LVM PV directly will fail.

```bash
# Identify filesystem type without mounting (works for non-LVM partitions)
OFFSET=$(sudo mmls /mnt/ewf/ewf1 | awk '/Linux filesystem|Linux LVM/{print $3; exit}')
sudo blkid -o value -s TYPE --offset $((OFFSET * 512)) /mnt/ewf/ewf1
# Output will be: ext4, xfs, btrfs, LVM2_member, etc.
```

### 5. Mount Filesystem (Read-Only)

```bash
# Byte offset = Start_sector * sector_size (usually 512)
OFFSET=$(( 2048 * 512 ))   # adjust sector start and size from mmls output

sudo mount -o ro,loop,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount

# Verify
ls /mnt/windows_mount/
```

**If mount fails (filesystem dirty / hibernation):**
```bash
# norecovery prevents journal replay — works for NTFS, ext3/ext4, and XFS
sudo mount -o ro,loop,norecovery,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount
sudo mount -o ro,loop,nosuid,noexec,nodev,norecovery,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/linux_mount

# Btrfs: ro alone is sufficient (no separate journal replay)
```

---

### LVM Activation (when partition type is Linux LVM)

TSK cannot read inside LVM. Use `kpartx` to surface logical volumes, then mount them.

```bash
# Step 1: Set up a loop device on the EWF raw image
sudo losetup -f --show /mnt/ewf/ewf1
# Note the loop device name, e.g., /dev/loop0

# Step 2: Map all partitions from the loop device
sudo kpartx -av /dev/loop0
# Creates /dev/mapper/loop0p1, /dev/mapper/loop0p2, etc.

# Step 3: Scan for LVM volume groups
sudo pvscan          # confirm physical volume(s) are recognised
sudo vgscan          # discover volume group names

# Step 4: Activate volume group(s) read-only where possible
# Note: -ay is required to surface logical volumes; -an deactivates
sudo vgchange -ay

# Step 5: List logical volumes
sudo lvs             # summary: LV name, VG name, size
sudo lvdisplay       # full details including device path

# Step 6: Mount the logical volume of interest (read-only)
sudo mkdir -p /mnt/linux_mount

# ext4 or XFS: norecovery prevents journal replay
sudo mount -o ro,nosuid,noexec,nodev,norecovery /dev/vgname/lvname /mnt/linux_mount

# Btrfs: ro alone is sufficient
sudo mount -o ro,nosuid,noexec,nodev /dev/vgname/lvname /mnt/linux_mount

# Cleanup (reverse order)
sudo umount /mnt/linux_mount
sudo vgchange -an vgname     # deactivate volume group
sudo kpartx -dv /dev/loop0
sudo losetup -d /dev/loop0
sudo umount /mnt/ewf
```

Common logical volume names: `root`, `home`, `var`, `swap`.
The device path is `/dev/<vgname>/<lvname>` or equivalently `/dev/mapper/<vgname>-<lvname>`.

---

### Btrfs Subvolumes

Btrfs uses subvolumes — a naive `mount` often lands in the top-level subvolume
rather than the actual root filesystem. The root OS is usually in subvolume `@`.

```bash
# Mount at the top level first to list subvolumes
sudo mount -o ro,nosuid,noexec,nodev /dev/... /mnt/linux_mount
sudo btrfs subvolume list /mnt/linux_mount

# Example output:
# ID 256 gen 45 top level 5 path @
# ID 257 gen 44 top level 5 path @home

# Remount to the correct subvolume (usually @)
sudo umount /mnt/linux_mount
sudo mount -o ro,nosuid,noexec,nodev,subvol=@ /dev/... /mnt/linux_mount
```

### 6. Filesystem Metadata

```bash
# Filesystem statistics (NTFS version, cluster size, MFT offset, volume ID)
# ext2/3/4 and NTFS only — fails on XFS and Btrfs
sudo fsstat /mnt/ewf/ewf1

# With partition offset (if fsstat is run against the raw image directly)
sudo fsstat -o 2048 /mnt/ewf/ewf1

# For XFS / Btrfs: check filesystem type and basic stats from the mounted path
df -Th /mnt/linux_mount
```

### 7. Filesystem Navigation with TSK

> **ext2/3/4 only.** `fls`, `icat`, `ils`, `blkls`, `mactime` cannot read XFS or Btrfs.
> For those filesystems, navigate from the mounted path using standard Linux tools
> and generate the filesystem timeline with the `find`-based method in Step 11.

```bash
# List all files recursively (includes deleted entries — marked with *)
sudo fls -r -p /mnt/ewf/ewf1 > ./analysis/fls_output.txt

# List with MAC times in bodyfile format (for timeline creation)
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/bodyfile.txt

# List a specific directory by inode
sudo fls /mnt/ewf/ewf1 <inode_number>

# List root directory (inode 5 on NTFS; inode 2 on ext)
sudo fls /mnt/ewf/ewf1 5

# Show only deleted entries
sudo fls -r -p /mnt/ewf/ewf1 | grep "^\*"

# With partition offset (bypass filesystem mount)
sudo fls -r -o 2048 /mnt/ewf/ewf1
```

**fls flags:**
| Flag | Description |
|------|-------------|
| `-r` | Recursive |
| `-p` | Full path (vs relative) |
| `-m /` | Bodyfile format (prefix `/` = mount point) |
| `-o <sectors>` | Partition offset in sectors |
| `-f <type>` | Force filesystem type (`ntfs`, `fat32`, `ext4`) |
| `-l` | Long format (include all timestamps) |
| `-d` | Show only deleted entries |
| `-D` | Show only directories |
| `-F` | Show only files (non-dirs) |
| `-h` | Hash file contents (MD5, for use with mactime) |
| `-z ZONE` | Display timestamps in specified timezone (e.g., `UTC`) |

### 8. Extract Files by Inode

```bash
# Get inode metadata (MAC times, allocated blocks, file size)
sudo istat /mnt/ewf/ewf1 <inode_number>

# Extract file content to local path
sudo icat /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>

# Extract a deleted file (recover from unallocated blocks)
sudo icat -r /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>

# Extract file slack space (data after EOF in last cluster)
sudo icat -s /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>_slack

# Find filename for a known inode
sudo ffind /mnt/ewf/ewf1 <inode_number>

# With partition offset
sudo icat -o 2048 /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>
```

### 9. Inode and Block-Level Analysis

```bash
# List all inodes (orphan entries = deleted with no directory entry)
sudo ils /mnt/ewf/ewf1 > ./analysis/ils_output.txt

# List only orphan (unlinked) inodes — deleted files with no directory entry
sudo ils -p /mnt/ewf/ewf1 > ./analysis/ils_orphan.txt

# List all inodes (allocated + unallocated)
sudo ils -e /mnt/ewf/ewf1 > ./analysis/ils_all.txt

# List only allocated inodes
sudo ils -a /mnt/ewf/ewf1 > ./analysis/ils_allocated.txt

# List only unallocated inodes
sudo ils -A /mnt/ewf/ewf1 > ./analysis/ils_unallocated.txt

# Mactime bodyfile format (combine with fls bodyfile for timeline)
sudo ils -m /mnt/ewf/ewf1 > ./analysis/ils_bodyfile.txt

# Extract raw unallocated blocks (for carving on tight storage budgets)
sudo blkls /mnt/ewf/ewf1 > ./analysis/unallocated.raw
# or targeted:
sudo blkls -a /mnt/ewf/ewf1 > ./analysis/allocated.raw     # allocated blocks only
sudo blkls -A /mnt/ewf/ewf1 > ./analysis/unallocated.raw   # unallocated blocks only
sudo blkls -s /mnt/ewf/ewf1 > ./analysis/slack.raw         # file slack space only
sudo blkls -e /mnt/ewf/ewf1 > ./analysis/every.raw         # every block (all types)
```

### 10. Bulk File Recovery

```bash
# Recover all allocated files, preserving directory structure (default)
sudo tsk_recover /mnt/ewf/ewf1 ./exports/tsk_recover/

# Recover allocated files only (explicit)
sudo tsk_recover -a /mnt/ewf/ewf1 ./exports/tsk_recover_alloc/

# Recover ALL files including unallocated/deleted
sudo tsk_recover -e /mnt/ewf/ewf1 ./exports/tsk_recover_all/

# Recover from a specific directory inode only
sudo tsk_recover -d <dir_inode> /mnt/ewf/ewf1 ./exports/tsk_recover_subdir/
```

### 11. Generate Filesystem Timeline

#### Method A — TSK (ext2/3/4 only)

```bash
# Step 1: Create bodyfile via fls
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/bodyfile.txt

# Step 2: Convert to sorted timeline (UTC)
mactime -b ./analysis/bodyfile.txt -z UTC -d > ./exports/fs_timeline.csv

# Step 2 (alt): ISO 8601 timestamps
mactime -b ./analysis/bodyfile.txt -z UTC -y > ./exports/fs_timeline_iso.txt

# Step 3 (optional): Filter by date range
mactime -b ./analysis/bodyfile.txt -z UTC -d 2023-01-01 2023-12-31 \
  > ./exports/fs_timeline_filtered.txt
```

#### Method B — find + mactime (XFS / Btrfs / any mounted filesystem)

When the filesystem is XFS, Btrfs, or any other type TSK cannot navigate, generate
the bodyfile from the **mounted path** using `find`. The output format is compatible
with `mactime`.

```bash
# Step 1: Generate bodyfile from mounted path
# Format: MD5|path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
sudo find /mnt/linux_mount -xdev -printf \
  "0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n" 2>/dev/null \
  > ./analysis/bodyfile.txt

# Step 2: Convert to timeline with mactime (same as Method A)
mactime -b ./analysis/bodyfile.txt -z UTC -d > ./exports/fs_timeline.csv
```

`find -printf` field mapping:
| Specifier | Description |
|-----------|-------------|
| `%p` | Full path |
| `%i` | Inode number |
| `%M` | Permission string (e.g., `-rwxr-xr-x`) |
| `%U` / `%G` | Username / group name |
| `%s` | File size in bytes |
| `%A@` | Last access time (Unix epoch) |
| `%T@` | Last modification time (Unix epoch) |
| `%C@` | Last status change time (Unix epoch) |

Note: Linux (ext4, XFS, Btrfs) does not reliably expose creation time (`crtime`).
The final `0` is a placeholder — `mactime` ignores it in most output modes.

#### Method C — Plaso (all filesystems, recommended for Linux IR)

Plaso's `linux` parser extracts filesystem MAC times directly from the mounted
filesystem, supporting ext4, XFS, Btrfs, and any other mountable filesystem.
Always use the mounted path (`/mnt/linux_mount/`), never the raw image, for
non-ext4 Linux evidence.

```bash
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_linux.plaso \
  --parsers linux \
  --timezone UTC \
  /mnt/linux_mount/
```

See `@~/.claude/skills/plaso-timeline/SKILL.md` for full Plaso workflow.

**mactime flags:**
| Flag | Description |
|------|-------------|
| `-b <file>` | Input bodyfile |
| `-z ZONE` | Timezone (always use `UTC`) |
| `-d` | CSV output (comma-separated, easier for spreadsheet tools) |
| `-y` | ISO 8601 date format (YYYY-MM-DD) instead of US format |
| `-h` | Add session header with metadata and column names |
| `-i [day\|hour] <file>` | Write hourly/daily index file for navigation |

### 12. Targeted Artifact Extraction

```bash
# Windows event logs
sudo find /mnt/windows_mount/Windows/System32/winevt/Logs/ -name "*.evtx" \
  -exec cp {} ./exports/evtx/ \;

# Registry hives
for hive in SYSTEM SOFTWARE SECURITY SAM; do
  sudo cp /mnt/windows_mount/Windows/System32/config/$hive ./exports/registry/
done

# User NTUSER.DAT hives (all users)
sudo find /mnt/windows_mount/Users/ -name "NTUSER.DAT" \
  -exec cp --parents {} ./exports/registry/ \;

# UsrClass.dat (shellbags, file associations — in each user's Local profile)
sudo find /mnt/windows_mount/Users/ -name "UsrClass.dat" \
  -exec cp --parents {} ./exports/registry/ \;

# Prefetch files
sudo mkdir -p ./exports/prefetch/
sudo cp -r /mnt/windows_mount/Windows/Prefetch/ ./exports/prefetch/

# MFT (inode 0 on NTFS)
sudo icat /mnt/ewf/ewf1 0 > ./exports/mft/\$MFT

# UsnJrnl (inode 11 on NTFS) — $J data stream contains the change journal
sudo icat /mnt/ewf/ewf1 11-128-4 > ./exports/mft/\$J 2>/dev/null || \
sudo icat /mnt/ewf/ewf1 11 > ./exports/mft/\$J

# Amcache
sudo cp /mnt/windows_mount/Windows/AppCompat/Programs/Amcache.hve ./exports/registry/

# SRUM database
sudo mkdir -p ./exports/srum/
sudo cp /mnt/windows_mount/Windows/System32/sru/SRUDB.dat ./exports/srum/

# Browser profiles (Chrome/Edge)
sudo find /mnt/windows_mount/Users/ \
  -path "*/Google/Chrome/User Data/Default/History" \
  -exec cp --parents {} ./exports/browser/ \;
sudo find /mnt/windows_mount/Users/ \
  -path "*/Microsoft/Edge/User Data/Default/History" \
  -exec cp --parents {} ./exports/browser/ \;

# Recycle Bin
sudo cp -r "/mnt/windows_mount/\$Recycle.Bin/" ./exports/recyclebin/

# Scheduled tasks (XML definitions)
sudo cp -r /mnt/windows_mount/Windows/System32/Tasks/ ./exports/tasks/

# PowerShell transcript logs (if enabled)
sudo find /mnt/windows_mount/Users/ -name "PowerShell_transcript*.txt" \
  -exec cp --parents {} ./exports/pslogs/ \;
```

### Linux Targeted Artifact Extraction

When the evidence is a Linux disk image, extract these artifacts instead of
(or in addition to) the Windows artifacts above.

```bash
# /etc — accounts, SSH config, sudoers, cron, systemd, PAM
sudo mkdir -p ./exports/etc/
sudo cp -rp /mnt/linux_mount/etc/passwd \
            /mnt/linux_mount/etc/shadow \
            /mnt/linux_mount/etc/group \
            /mnt/linux_mount/etc/sudoers \
            /mnt/linux_mount/etc/ssh/ \
            ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/sudoers.d  ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/ld.so.preload ./exports/etc/ 2>/dev/null
sudo cp -p  /mnt/linux_mount/etc/crontab    ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/cron.d     ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/systemd    ./exports/etc/ 2>/dev/null
sudo cp -rp /mnt/linux_mount/etc/profile.d  ./exports/etc/ 2>/dev/null

# Logs (full /var/log)
sudo mkdir -p ./exports/logs/
sudo cp -rp /mnt/linux_mount/var/log ./exports/logs/

# Systemd journal (binary format — read with journalctl --directory)
sudo mkdir -p ./exports/journal/
sudo find /mnt/linux_mount/var/log/journal -name "*.journal" \
  -exec cp --parents {} ./exports/journal/ \; 2>/dev/null

# Audit log
sudo mkdir -p ./exports/audit/
sudo cp -p /mnt/linux_mount/var/log/audit/audit.log ./exports/audit/ 2>/dev/null

# Shell histories (all users)
sudo mkdir -p ./exports/shell_history/
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  \( -name ".bash_history" -o -name ".zsh_history" \) \
  -exec cp --parents {} ./exports/shell_history/ \; 2>/dev/null

# Per-user crontabs
sudo mkdir -p ./exports/cron/
sudo cp -rp /mnt/linux_mount/var/spool/cron ./exports/cron/spool/ 2>/dev/null

# SSH authorized_keys (all users)
sudo mkdir -p ./exports/ssh_keys/
sudo find /mnt/linux_mount/home /mnt/linux_mount/root \
  -name "authorized_keys" \
  -exec cp --parents {} ./exports/ssh_keys/ \; 2>/dev/null

# Staging areas (attacker drop zones)
sudo mkdir -p ./exports/staging/
sudo find /mnt/linux_mount/tmp \
          /mnt/linux_mount/var/tmp \
          /mnt/linux_mount/dev/shm \
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

**ext4 / Linux filesystem notes:**
- TSK tools (`fls`, `icat`, `mactime`, etc.) support **ext2/3/4 only** for Linux filesystems
- Root directory inode on ext4 is **inode 2** (not inode 5 as on NTFS)
- `norecovery` prevents journal replay on NTFS, ext3/ext4, and XFS; for Btrfs `-o ro` alone is sufficient
- For XFS or Btrfs evidence: skip TSK filesystem navigation entirely — use Method B or C above
- For LVM evidence: activate with `kpartx` + `vgchange -ay` before mounting (see LVM section)
- For Btrfs: list subvolumes after initial mount and remount with `-o ro,subvol=@` if needed

---

## File Carving

### bulk_extractor

```bash
# Full carve from raw image (default: 4 threads in v2.0+)
sudo bulk_extractor -o ./exports/carved/ /mnt/ewf/ewf1

# Targeted feature types only (faster for specific IOC hunting)
sudo bulk_extractor -o ./exports/carved/ -e email -e url -e domain /mnt/ewf/ewf1

# Increase thread count for speed on multi-core SIFT
sudo bulk_extractor -j 8 -o ./exports/carved/ /mnt/ewf/ewf1

# Carve from unallocated space only
sudo blkls -u /mnt/ewf/ewf1 > /tmp/unalloc.raw
sudo bulk_extractor -o ./exports/carved_unalloc/ /tmp/unalloc.raw
```

Output: feature files for email addresses, URLs, domains, credit cards, BTC addresses,
telephone numbers, and more — each with byte offset back to image.

### PhotoRec (Signature-Based File Recovery)

```bash
sudo photorec /mnt/ewf/ewf1
# Interactive: select partition → file types → output directory
# Use ./exports/photorec/ as output directory
```

---

## Hash Verification and Known-File Filtering

```bash
# Compute MD5 hash of an extracted file
md5sum ./exports/files/<filename>

# Generate MD5 hashes of all extracted files for case documentation
find ./exports/files/ -type f -exec md5sum {} \; > ./exports/files/md5_manifest.txt

# Filter against NSRL (known-good software) with hashdeep
# (hashdeep must be installed: apt install hashdeep)
hashdeep -r /mnt/windows_mount/Windows/ -l > ./analysis/windows_hashes.txt
```

---

## Unmounting

```bash
# Always unmount in reverse order (filesystem first, then EWF)
sudo umount /mnt/windows_mount
sudo umount /mnt/ewf
```

---

## Output Paths

| Output | Path |
|--------|------|
| Bodyfile | `./analysis/` |
| FLS output | `./analysis/fls_output.txt` |
| Filesystem timeline | `./exports/fs_timeline.txt` |
| Extracted files | `./exports/files/` |
| Registry hives | `./exports/registry/` |
| Event logs | `./exports/evtx/` |
| MFT + UsnJrnl | `./exports/mft/` |
| SRUM | `./exports/srum/` |
| Prefetch | `./exports/prefetch/` |
| Carved files | `./exports/carved/` |
| Recovered files (tsk) | `./exports/tsk_recover/` |

---

## Notes

- Never write to `/mnt/` paths — read-only mounts only
- `fls -p` flag shows full paths (more readable than relative paths)
- Deleted files appear with a `*` prefix in `fls` output
- Use `-o <sectors>` flag with all TSK tools when bypassing mount (more reliable than loopback)
- `img_stat` before `mmls` catches 4K sector drives — wrong sector size = wrong byte offset
- `norecovery` prevents journal replay on NTFS, ext3/ext4, and XFS — always use with `-o ro` for evidence mounts of these types
- `icat` is preferred over `cp` for extracting files — bypasses OS file locking and VSS
- The bodyfile from `fls` can be fed directly to `log2timeline.py` as an input source
- VSS (Volume Shadow Copies) can be mounted: use `mmls` on VSS metadata and `icat` with offsets
