#!/usr/bin/env bash
# Quarry — one-shot blank-VPS bootstrap. Idempotent; safe to re-run.
# Installs the framework, then `quarry install` provisions everything else
# (system packages, Go toolchain, all recon tools, wordlists, resolvers,
#  gf patterns, nuclei templates).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="$(mktemp -t quarry-bootstrap.XXXXXX.log)"

# ── banner FIRST — before the noisy dependency install. A static copy of quarry's own; `quarry install` skips
#    its banner under QUARRY_FROM_INSTALLER so it is not printed twice. ──
printf '\n  \033[36m◤ QUARRY — methodology-driven recon automation\033[0m\n'
printf '  \033[33m⏳ Full install builds ~25 Go tools + fetches wordlists/templates — this takes several minutes.\n'
printf '     It is not stuck; grab a coffee.\033[0m\n\n'

# ── install the framework + its OS deps QUIETLY (all output -> $LOG, so the noisy apt/pipx bootstrap does not
#    spam the screen). If apt is needed, pre-authenticate sudo up front so its password prompt stays VISIBLE
#    even though the install output is hidden. ──
echo "[*] Installing framework + dependencies…"
if ! command -v pipx >/dev/null 2>&1; then
  sudo -v || true                                        # cache sudo creds (visible prompt) before the quiet block
fi
{
  command -v pipx >/dev/null 2>&1 || {
    # a blank VPS needs fresh lists or the pipx install fails
    sudo apt-get update -qq && sudo apt-get install -y -qq pipx || \
      python3 -m pip install --user --break-system-packages pipx
  }
  pipx install --force "$HERE"
} >>"$LOG" 2>&1 || { echo "  framework install FAILED — last lines of $LOG:"; tail -n 20 "$LOG"; exit 1; }
export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

# ── persist PATH BEFORE provisioning — so `quarry` and the recon tools resolve in new shells even if a later
#    tool install fails. Otherwise a nonzero `quarry install` (under set -e) would abort before this block, and
#    the retry commands it prints (`quarry install --only <tool>`) could not resolve `quarry`. (quiet) ──
pipx ensurepath >>"$LOG" 2>&1 || true
# pick the rc file for the user's actual shell (zsh reads ~/.zshrc, bash ~/.bashrc)
case "${SHELL##*/}" in
  zsh)  RC="$HOME/.zshrc" ;;
  bash) RC="$HOME/.bashrc" ;;
  *)    RC="$HOME/.profile" ;;
esac
[ -e "$RC" ] || touch "$RC"
if ! grep -q '>>> quarry path >>>' "$RC" 2>/dev/null; then
  {
    echo ''
    echo '# >>> quarry path >>>'
    echo 'export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"'
    echo '# <<< quarry path <<<'
  } >> "$RC"
fi

echo "[*] Provisioning tools + data…"
# A tool failure must NOT abort the bootstrap before the PATH block above has run. Capture the exit code
# instead of letting `set -e` abort here. Optional-tool failures are already non-fatal (exit 0) inside
# `quarry install`; a nonzero here means a REQUIRED tool (or a host below minimum requirements) failed.
set +e
QUARRY_FROM_INSTALLER=1 quarry install --include-optional
rc=$?
set -e

echo
if [ "$rc" -ne 0 ]; then
  printf '    \033[33minstall completed with failures (exit %s)\033[0m — PATH is set; re-run: quarry install --only <tool>\n' "$rc"
else
  printf '    \033[32minstall complete\033[0m\n'
  rm -f "$LOG"
fi
echo
echo "    Almost there — load quarry onto your PATH:"
echo "      open a new shell, or run:  source ~/${RC#"$HOME"/}"
echo
echo "    Set API keys:"
echo "      quarry:    ~/.config/quarry/secrets.yaml"
echo "      subfinder: ~/.config/subfinder/provider-config.yaml"
echo "      waymore:   ~/.config/waymore/config.yml"

# honor a REQUIRED-tool / host-requirement failure so automation sees it — PATH is already persisted above
exit "$rc"
