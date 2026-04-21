#!/usr/bin/env bash
# protocol-sift install script
# Usage: curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
set -euo pipefail

REPO_URL="https://github.com/teamdfir/protocol-sift.git"
CLAUDE_DIR="${HOME}/.claude"
TMPDIR_PREFIX="protocol-sift-install"

# ── helpers ──────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m[info]\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m[ ok ]\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m[warn]\033[0m  %s\n' "$*"; }
die()   { printf '\033[1;31m[fail]\033[0m  %s\n' "$*" >&2; exit 1; }

backup_if_exists() {
    local target="$1"
    if [[ -e "$target" ]]; then
        local bak="${target}.bak-$(date +%Y%m%d%H%M%S)"
        mv "$target" "$bak"
        warn "Backed up existing $(basename "$target") → $bak"
    fi
}

# ── preflight ────────────────────────────────────────────────────────────────

command -v curl >/dev/null 2>&1 || die "curl is required but not found. Install curl and retry."
command -v git  >/dev/null 2>&1 || die "git is required but not found. Install git and retry."

info "protocol-sift — DFIR SIFT Claude Code installer"
echo

# ── Claude Code ───────────────────────────────────────────────────────────────

if command -v claude >/dev/null 2>&1; then
    ok "Claude Code already installed: $(command -v claude)"
else
    info "Claude Code not found — running official installer…"
    CLAUDE_INSTALLER="$(mktemp -t claude-install.XXXXXX.sh)"
    curl -fsSL https://claude.ai/install.sh -o "$CLAUDE_INSTALLER"
    bash "$CLAUDE_INSTALLER"
    rm -f "$CLAUDE_INSTALLER"
    # Re-source shell profile in case the installer added claude to PATH
    for profile in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc"; do
        # shellcheck disable=SC1090
        [[ -f "$profile" ]] && source "$profile" 2>/dev/null || true
    done
    command -v claude >/dev/null 2>&1 || \
        warn "Claude Code installed but 'claude' not yet in PATH. Open a new shell after this script finishes."
    ok "Claude Code installed."
fi
echo

# ── locate repo files ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/global/CLAUDE.md" && -f "$SCRIPT_DIR/global/settings.json" ]]; then
    info "Running from local repo/archive — skipping clone."
    REPO_DIR="$SCRIPT_DIR"
    WORK_DIR=""
else
    WORK_DIR="$(mktemp -d -t "${TMPDIR_PREFIX}.XXXXXX")"
    trap 'rm -rf "$WORK_DIR"' EXIT
    info "Cloning protocol-sift into temp directory…"
    git clone --depth=1 --quiet "$REPO_URL" "$WORK_DIR/repo"
    REPO_DIR="$WORK_DIR/repo"
    ok "Clone complete."
fi
echo

# ── create ~/.claude if missing ───────────────────────────────────────────────

mkdir -p "$CLAUDE_DIR"

# ── global config files ───────────────────────────────────────────────────────

info "Installing global config files…"

for f in CLAUDE.md settings.json settings.local.json; do
    src="$REPO_DIR/global/$f"
    dst="$CLAUDE_DIR/$f"
    if [[ ! -f "$src" ]]; then
        warn "Source not found, skipping: global/$f"
        continue
    fi
    backup_if_exists "$dst"
    cp "$src" "$dst"
    ok "  global/$f → $dst"
done
echo

# ── skills ────────────────────────────────────────────────────────────────────

SKILLS=(
    memory-analysis
    plaso-timeline
    sleuthkit
    windows-artifacts
    yara-hunting
    linux-artifacts
)

info "Installing skills…"
for skill in "${SKILLS[@]}"; do
    src="$REPO_DIR/skills/$skill/SKILL.md"
    dst_dir="$CLAUDE_DIR/skills/$skill"
    if [[ ! -f "$src" ]]; then
        warn "  Skill not found, skipping: skills/$skill/SKILL.md"
        continue
    fi
    mkdir -p "$dst_dir"
    cp "$src" "$dst_dir/SKILL.md"
    ok "  skills/$skill/SKILL.md → $dst_dir/SKILL.md"
done
echo

# ── analysis-scripts (kept in ~/.claude for reuse across cases) ───────────────

info "Installing analysis scripts…"
mkdir -p "$CLAUDE_DIR/analysis-scripts"
src="$REPO_DIR/analysis-scripts/generate_pdf_report.py"
if [[ -f "$src" ]]; then
    cp "$src" "$CLAUDE_DIR/analysis-scripts/generate_pdf_report.py"
    ok "  generate_pdf_report.py → $CLAUDE_DIR/analysis-scripts/"
else
    warn "  analysis-scripts/generate_pdf_report.py not found, skipping."
fi
echo

# ── case template (kept in ~/.claude for reuse) ───────────────────────────────

info "Installing case template…"
mkdir -p "$CLAUDE_DIR/case-templates"
src="$REPO_DIR/case-templates/CLAUDE.md"
if [[ -f "$src" ]]; then
    cp "$src" "$CLAUDE_DIR/case-templates/CLAUDE.md"
    ok "  case-templates/CLAUDE.md → $CLAUDE_DIR/case-templates/CLAUDE.md"
else
    warn "  case-templates/CLAUDE.md not found, skipping."
fi

src="$REPO_DIR/case-templates/linux-CLAUDE.md"
if [[ -f "$src" ]]; then
    cp "$src" "$CLAUDE_DIR/case-templates/linux-CLAUDE.md"
    ok "  case-templates/linux-CLAUDE.md → $CLAUDE_DIR/case-templates/linux-CLAUDE.md"
else
    warn "  case-templates/linux-CLAUDE.md not found, skipping."
fi
echo

# ── optional: WeasyPrint ──────────────────────────────────────────────────────

if [[ -t 0 ]]; then
    # stdin is a terminal — we can prompt
    read -rp "Install WeasyPrint PDF dependency now? (pip3 install weasyprint) [y/N] " yn
else
    # piped install — skip interactive prompt, print manual instructions instead
    yn="n"
fi

if [[ "$yn" =~ ^[Yy]$ ]]; then
    info "Installing WeasyPrint…"
    if pip3 install weasyprint; then
        ok "WeasyPrint installed."
    else
        warn "pip3 install failed. Try manually:"
        warn "  pip3 install weasyprint"
        warn "  sudo apt-get install -y python3-gi python3-gi-cairo gir1.2-gtk-3.0 libpango-1.0-0"
    fi
else
    info "Skipping WeasyPrint. Install it manually when needed:"
    echo "    pip3 install weasyprint"
    echo "    # if that fails:"
    echo "    sudo apt-get install -y python3-gi python3-gi-cairo gir1.2-gtk-3.0 libpango-1.0-0"
fi
echo

# ── done ─────────────────────────────────────────────────────────────────────

ok "Installation complete."
echo
echo "── Next steps ────────────────────────────────────────────────────────────"
echo
echo "  Start a new case:"
echo
echo "    export CASE=CLIENT-IR-2025-001"
echo "    mkdir -p /cases/\${CASE}/{analysis,exports,reports}"
echo "    cp \${HOME}/.claude/case-templates/CLAUDE.md /cases/\${CASE}/CLAUDE.md"
echo "    cp \${HOME}/.claude/analysis-scripts/generate_pdf_report.py \\"
echo "       /cases/\${CASE}/analysis/"
echo "    nano /cases/\${CASE}/CLAUDE.md   # fill in case details"
echo "    cd /cases/\${CASE} && claude"
echo
echo "  Customise the case template before use — it ships with SRL FOR508 demo data."
echo
echo "  Do NOT copy ~/.claude/.credentials.json — it contains your API key."
echo "──────────────────────────────────────────────────────────────────────────"
