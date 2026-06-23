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
  sudo apt-get update -y && sudo apt-get install -y pipx || python3 -m pip install --user --break-system-packages pipx
}
pipx install --force "$HERE"
export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

echo "[*] Provisioning tools + data (quarry install)…"
quarry install --include-optional || true   # never abort bootstrap on one item

# ── persist PATH so `quarry` and the recon tools are found in new shells ──
echo "[*] Persisting PATH (~/.local/bin, ~/go/bin, /usr/local/go/bin)…"
pipx ensurepath >/dev/null 2>&1 || true
RC="$HOME/.bashrc"; [ -f "$RC" ] || RC="$HOME/.profile"
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
echo
echo "    IMPORTANT: open a new shell, or run:  source $RC"
echo "    (so 'quarry' and the recon tools are on your PATH)"
echo
echo "    Then:"
echo "      quarry doctor"
echo "      quarry init-target acme -o targets/acme.yaml && \$EDITOR targets/acme.yaml"
echo "      quarry run -t targets/acme.yaml"
echo
echo "    API keys (see README.md):"
echo "      subfinder: ~/.config/subfinder/provider-config.yaml"
echo "      waymore:   ~/.config/waymore/config.yml"
echo "      github:    ~/.config/quarry/github-tokens.txt"
