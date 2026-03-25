# Protocol SIFT

Rob Lee developed Protocol SIFT and all the files found within this repository.

## Claude Code + SANS SIFT Workstation Setup

> [!IMPORTANT]
> Replication Guide for SANS SIFT + Unconfigured Claude Code

This repository contains everything needed to replicate the DFIR-tuned Claude Code
configuration on a bare SANS SIFT Ubuntu workstation. It covers global behavioral
rules, forensic tool skill files, per-case project templates, and PDF report tooling.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| SANS SIFT Workstation | Ubuntu x86-64, standard SIFT tool set installed |
| Claude Code CLI | `npm install -g @anthropic-ai/claude-code` (or via your org's approved channel) |
| Anthropic API key | Set in `~/.claude/.credentials.json` after first `claude` run — **never copy** this file |
| Python 3 + WeasyPrint | `pip3 install weasyprint` — required for PDF report generation |
| dotnet runtime v6 | Pre-installed on SIFT; EZ Tools run against `/opt/zimmermantools/` |

---

## Installation

Choose one of three methods. All three end up with the same files in `~/.claude/`.

---

### Method 1 — curl one-liner (recommended)

Requires `git` on the target machine (standard on SIFT).

```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```

The script will:
- Clone this repo into a temporary directory (cleaned up on exit)
- Back up any existing `~/.claude/{CLAUDE.md,settings.json,settings.local.json}` to `.bak-<timestamp>` before overwriting
- Install global config, all skills, the case template, and the PDF analysis script into `~/.claude/`
- Print WeasyPrint install instructions (WeasyPrint prompt is skipped when stdin is piped)

To also install WeasyPrint in the same step, run the script directly instead:

```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh -o /tmp/install.sh
bash /tmp/install.sh
```

---

### Method 2 — Clone the repo

```bash
git clone --depth=1 https://github.com/teamdfir/protocol-sift.git
cd protocol-sift
bash install.sh
```

Keep the cloned directory around if you want to pull updates later (`git pull && bash install.sh`).

---

### Method 3 — Download as ZIP archive

1. Go to `https://github.com/teamdfir/protocol-sift` → **Code → Download ZIP**
2. Extract the archive:
   ```bash
   unzip protocol-sift-main.zip
   cd protocol-sift-main
   ```
3. Either run the bundled script:
   ```bash
   bash install.sh
   ```
   Or follow the manual file-by-file steps in the [File-by-File Installation Instructions](#file-by-file-installation-instructions) section below.

---

## Repository Structure

```
protocol-sift/
├── README.md                          ← this file
├── install.sh                         ← automated installer
├── global/
│   ├── CLAUDE.md                      ← global behavioral instructions (1)
│   ├── settings.json                  ← tool permissions + Stop hook    (2)
│   └── settings.local.json            ← local sudo / apt overrides      (3)
├── skills/
│   ├── memory-analysis/SKILL.md       ← Volatility 3 skill              (4)
│   ├── plaso-timeline/SKILL.md        ← Plaso / log2timeline skill      (5)
│   ├── sleuthkit/SKILL.md             ← Sleuth Kit / TSK skill          (6)
│   ├── windows-artifacts/SKILL.md     ← EZ Tools / EVTX / Registry      (7)
│   └── yara-hunting/SKILL.md          ← YARA / threat hunting skill     (8)
├── case-templates/
│   └── CLAUDE.md                      ← per-case project template       (9)
└── analysis-scripts/
    └── generate_pdf_report.py         ← WeasyPrint PDF generator        (10)
```

---

## File-by-File Installation Instructions

### (1) global/CLAUDE.md → `~/.claude/CLAUDE.md`

**What it is:** The global system prompt that loads for every Claude Code session,
regardless of working directory. Sets the operator role (Principal DFIR Orchestrator),
evidence integrity rules, tool routing table, installed tool paths, and the no-questions
autonomous operation preference.

**Install:**
```bash
cp global/CLAUDE.md ~/.claude/CLAUDE.md
```

**Customise:**
- Update the `Installed Tool Paths` table if your SIFT instance has tools in different locations.
- If you use MemProcFS or VSCMount (Windows VMs only), add them to the table.
- The `## Operator Preferences` section sets fully autonomous mode — adjust if you prefer confirmations.

---

### (2) global/settings.json → `~/.claude/settings.json`

**What it is:** The main Claude Code permission policy. Pre-approves all DFIR CLI tools
(Volatility, Sleuth Kit, EZ Tools, Plaso, bulk_extractor, YARA, hash tools, etc.) so
Claude never pauses to ask permission mid-investigation. Also contains a `Stop` hook
that writes a forensic audit log entry to `./analysis/forensic_audit.log` at the end
of every conversation.

**Install:**
```bash
cp global/settings.json ~/.claude/settings.json
```

**Key sections:**
- `permissions.allow` — all forensic CLIs are pre-approved
- `permissions.deny` — blocks `rm -rf`, `dd`, `wget`, `curl`, `ssh`, and `WebFetch`
  (prevents Claude from exfiltrating data or wiping evidence)
- `permissions.defaultMode` — `"acceptEdits"` means file edits in allowed paths
  auto-approve without a prompt
- `hooks.Stop` — appends conversation summary to `./analysis/forensic_audit.log`
  for chain-of-custody documentation

**Important — Write path restrictions:**
The `Write` and `Edit` allow-list is scoped to `./analysis/*`, `./reports/*`, and
`./exports/*` (relative to whichever case directory you `cd` into before launching
`claude`). This is intentional — it prevents writing to evidence directories. Do **not**
broaden this to `/cases/**` or `/mnt/**`.

---

### (3) global/settings.local.json → `~/.claude/settings.local.json`

**What it is:** Machine-local overrides. Currently allows `sudo apt` installs and the
`psort.py` Plaso command. This file is intentionally minimal — it holds only things
that differ per-machine, not per-case.

**Install:**
```bash
cp global/settings.local.json ~/.claude/settings.local.json
```

---

### (4–8) skills/ → `~/.claude/skills/`

**What they are:** Skill files are domain-specific prompt libraries that Claude loads
on demand. Each `SKILL.md` contains exact CLI invocations, common flags, known
gotchas, and output interpretation guidance for a specific forensic toolset.

| Skill file | Domain | Key tools covered |
|------------|--------|-------------------|
| `memory-analysis/SKILL.md` | Memory forensics | Volatility 3 plugins, symbol resolution, memory baseliner |
| `plaso-timeline/SKILL.md` | Timeline generation | log2timeline.py, psort.py, pinfo.py, super-timeline filters |
| `sleuthkit/SKILL.md` | Filesystem forensics | fls, icat, mmls, mactime, tsk_recover, ewfmount offsets |
| `windows-artifacts/SKILL.md` | Windows artifacts | EZ Tools suite, EvtxECmd, MFTECmd, RECmd, AmcacheParser |
| `yara-hunting/SKILL.md` | Threat hunting | YARA rules, IOC sweeps, bulk scanning |

**Install:**
```bash
mkdir -p ~/.claude/skills/memory-analysis \
         ~/.claude/skills/plaso-timeline \
         ~/.claude/skills/sleuthkit \
         ~/.claude/skills/windows-artifacts \
         ~/.claude/skills/yara-hunting

cp skills/memory-analysis/SKILL.md  ~/.claude/skills/memory-analysis/SKILL.md
cp skills/plaso-timeline/SKILL.md   ~/.claude/skills/plaso-timeline/SKILL.md
cp skills/sleuthkit/SKILL.md        ~/.claude/skills/sleuthkit/SKILL.md
cp skills/windows-artifacts/SKILL.md ~/.claude/skills/windows-artifacts/SKILL.md
cp skills/yara-hunting/SKILL.md     ~/.claude/skills/yara-hunting/SKILL.md
```

**How Claude uses them:** The global `CLAUDE.md` contains a routing table that
tells Claude which skill file to consult before using each tool category. Claude
reads the skill file at task time — you do not need to invoke them manually.

---

### (9) case-templates/CLAUDE.md → `/cases/<casename>/CLAUDE.md`

**What it is:** A per-case project CLAUDE.md. When you `cd /cases/<casename>` and
launch `claude`, this file is loaded automatically as project-level instructions,
layered on top of the global `~/.claude/CLAUDE.md`.

**Install for a new case:**

If you used the installer (`install.sh` or the curl one-liner), the template is already
at `~/.claude/case-templates/CLAUDE.md`:
```bash
mkdir -p /cases/<CASENAME>
cp ~/.claude/case-templates/CLAUDE.md /cases/<CASENAME>/CLAUDE.md
```

If you have the repo or archive available, copy from there instead:
```bash
mkdir -p /cases/<CASENAME>
cp case-templates/CLAUDE.md /cases/<CASENAME>/CLAUDE.md
```

**Required customisations for each new case:**
1. Update `## Case Overview` — client name, domain, threat actor, incident date, role
2. Update `## Evidence Files` — list all E01/img files with their system/role
3. Update `## Common Commands` — adjust image paths and filenames
4. Update `## Network Topology` — subnet map for the specific engagement
5. Update `## Domain Accounts` — DA and service accounts discovered
6. Update `## Known IOCs` — populate as artifacts are confirmed
7. Update `## Incident Timeline` — build out as analysis progresses

The template as shipped reflects the SRL FOR508 lab scenario. Strip the SRL-specific
content and fill in new case details before use.

---

### (10) analysis-scripts/generate_pdf_report.py → `/cases/<casename>/analysis/generate_pdf_report.py`

**What it is:** A reusable WeasyPrint-based PDF report generator. Claude uses this
as its output engine for all forensic PDF reports. It accepts a `data` dict and an
`output_path` string and renders an HTML template to PDF.

**Install:**

If you used the installer, copy from `~/.claude/analysis-scripts/`:
```bash
mkdir -p /cases/<CASENAME>/analysis
cp ~/.claude/analysis-scripts/generate_pdf_report.py /cases/<CASENAME>/analysis/generate_pdf_report.py
```

If you have the repo or archive available:
```bash
mkdir -p /cases/<CASENAME>/analysis
cp analysis-scripts/generate_pdf_report.py /cases/<CASENAME>/analysis/generate_pdf_report.py
```

**Dependency:**
```bash
pip3 install weasyprint
# If weasyprint fails, also install:
sudo apt-get install -y python3-gi python3-gi-cairo gir1.2-gtk-3.0 libpango-1.0-0
```

**Usage pattern:** Claude generates a `generate_<topic>_report.py` script per
investigation that imports this module:
```python
import sys
sys.path.insert(0, './analysis')
from generate_pdf_report import generate_report

DATA = {
    "case_id":     "CASE-ID-001",
    "client":      "Client Name",
    "prepared_by": "DFIR Consultant",
    "title":       "Report Title",
    "subtitle":    "Evidence source · System · Key Finding",
    "body_html":   BODY,   # MUST be r"""...""" raw string if body contains Windows paths
}
generate_report(DATA, "./analysis/report-name.pdf")
```

**Critical gotcha:** The `body_html` variable must use a Python **raw string**
(`r"""..."""`) if it contains Windows filesystem paths (e.g. `C:\Users\...`).
Otherwise Python will raise a `SyntaxError: unicode error 'unicodeescape'` on `\U`
and `\S` escape sequences.

---

## Manual Install Script (copy-paste)

If you prefer not to run `install.sh` directly, copy-paste the following from the
root of your cloned repo or extracted archive. This is exactly what `install.sh`
does, without the backup logic or prompts.

```bash
#!/bin/bash
set -e

# 1. Global config
mkdir -p ~/.claude
cp global/CLAUDE.md ~/.claude/CLAUDE.md
cp global/settings.json ~/.claude/settings.json
cp global/settings.local.json ~/.claude/settings.local.json

# 2. Skills
mkdir -p ~/.claude/skills/memory-analysis \
         ~/.claude/skills/plaso-timeline \
         ~/.claude/skills/sleuthkit \
         ~/.claude/skills/windows-artifacts \
         ~/.claude/skills/yara-hunting

cp skills/memory-analysis/SKILL.md   ~/.claude/skills/memory-analysis/SKILL.md
cp skills/plaso-timeline/SKILL.md    ~/.claude/skills/plaso-timeline/SKILL.md
cp skills/sleuthkit/SKILL.md         ~/.claude/skills/sleuthkit/SKILL.md
cp skills/windows-artifacts/SKILL.md ~/.claude/skills/windows-artifacts/SKILL.md
cp skills/yara-hunting/SKILL.md      ~/.claude/skills/yara-hunting/SKILL.md

# 3. Case template and analysis scripts (reusable across cases)
mkdir -p ~/.claude/case-templates ~/.claude/analysis-scripts
cp case-templates/CLAUDE.md ~/.claude/case-templates/CLAUDE.md
cp analysis-scripts/generate_pdf_report.py ~/.claude/analysis-scripts/generate_pdf_report.py

# 4. Python dependency for PDF reports
pip3 install weasyprint

echo "Done. Start a new case with:"
echo "  export CASE=CLIENT-IR-2025-001"
echo "  mkdir -p /cases/\${CASE}/{analysis,exports,reports}"
echo "  cp ~/.claude/case-templates/CLAUDE.md /cases/\${CASE}/CLAUDE.md"
echo "  cp ~/.claude/analysis-scripts/generate_pdf_report.py /cases/\${CASE}/analysis/"
echo "  nano /cases/\${CASE}/CLAUDE.md"
echo "  cd /cases/\${CASE} && claude"
```

---

## What Is NOT Included (and Why)

| Excluded | Reason |
|----------|--------|
| `~/.claude/.credentials.json` | Contains your Anthropic API key — never share or copy this |
| `~/.claude/history.jsonl` | Session command history — machine/session specific |
| `~/.claude/projects/` | Session memory and conversation state — case specific |
| `~/.claude/debug/` | Session debug logs — not portable |
| `~/.claude/telemetry/` | Usage telemetry — machine specific |
| `~/.claude/cache/` | Auto-regenerated on first run |
| `~/.claude/backups/` | Auto-generated config backups |
| `~/.claude/plugins/` | Auto-downloaded from Anthropic marketplace on first run |
| `/cases/srl/analysis/*.py` (generated) | Case-specific report scripts — not reusable as-is |
| Evidence files (*.E01, *.img) | Read-only evidence — never copy or share |

---

## Starting a Fresh Investigation

After running the installer, the case template and analysis script live in `~/.claude/`
and are ready to copy into any new case directory — no need to keep the repo around.

```bash
# 1. Prepare case directory
export CASE=CLIENT-IR-2025-001
mkdir -p /cases/${CASE}/{analysis,exports,reports}
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md
cp ~/.claude/analysis-scripts/generate_pdf_report.py /cases/${CASE}/analysis/
nano /cases/${CASE}/CLAUDE.md   # fill in case details

# 2. Mount evidence (example — adjust paths)
sudo mkdir -p /mnt/ewf_rd01 /mnt/rd01
sudo ewfmount /cases/${CASE}/suspect.E01 /mnt/ewf_rd01
OFFSET=$(sudo mmls /mnt/ewf_rd01/ewf1 | awk '/NTFS/{print $3; exit}')
sudo mount -o ro,loop,noatime,offset=$((OFFSET*512)) /mnt/ewf_rd01/ewf1 /mnt/rd01

# 3. Launch Claude from case root (critical — sets relative Write paths)
cd /cases/${CASE}
claude
```

---

## Notes on Chain of Custody

- Claude never writes to `/cases/`, `/mnt/`, or `/media/` — enforced by `settings.json`
- The `Stop` hook appends an audit log entry to `./analysis/forensic_audit.log`
  after every session — review this log as part of your case documentation
- All tool outputs use `tee` to write to `./exports/` — raw tool output is preserved
- Always verify image integrity before analysis: `ewfverify /cases/${CASE}/*.E01`
