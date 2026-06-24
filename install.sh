#!/usr/bin/env bash
# Quarry — one-shot blank-VPS bootstrap. Idempotent; safe to re-run.
# Installs the framework, then `quarry install` provisions everything else
# (system packages, Go toolchain, all recon tools, wordlists, resolvers,
#  gf patterns, nuclei templates).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing quarry framework (pipx)…"
command -v pipx >/dev/null 2>&1 || {
  echo "    bootstrapping pipx"
  # -qq keeps apt quiet; a blank VPS needs fresh lists or the pipx install fails
  sudo apt-get update -qq && sudo apt-get install -y -qq pipx || python3 -m pip install --user --break-system-packages pipx
}
pipx install --force "$HERE"
export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

echo "[*] Provisioning tools + data (quarry install)…"
# individual tool failures are handled inside `quarry install`; a non-zero exit here means a
# hard stop (e.g. host below minimum requirements) — honor it and stop the bootstrap.
# QUARRY_FROM_INSTALLER tells it to skip its own end banner — this script prints the final one.
QUARRY_FROM_INSTALLER=1 quarry install --include-optional

# ── persist PATH so `quarry` and the recon tools are found in new shells ──
echo
echo "[*] Persisting PATH (~/.local/bin, ~/go/bin, /usr/local/go/bin)…"
pipx ensurepath >/dev/null 2>&1 || true
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

echo
echo "[✓] Done."
printf '    \033[32minstall complete\033[0m\n'
echo
echo "    IMPORTANT: open a new shell, or run:  source ~/${RC#"$HOME"/}"
echo "    (so 'quarry' and the recon tools are on your PATH)"
echo
echo "    Set API keys (see README.md):"
echo "      quarry:    ~/.config/quarry/secrets.yaml"
echo "      subfinder: ~/.config/subfinder/provider-config.yaml"
echo "      waymore:   ~/.config/waymore/config.yml"
