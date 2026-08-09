# Installation

Quarry runs on Linux (Debian/Kali/Ubuntu-family tested). It installs a Python CLI plus ~25 Go and
Python tools, DNS resolvers, wordlists, and Nuclei templates. Chromium is needed for screenshots.

**Prerequisites:** Git, Python 3.10+, outbound internet, and root or a working `sudo` (system packages
are installed during the build).

## Full install (blank host)

```bash
git clone https://github.com/0xLumpy/quarry.git
cd quarry
./install.sh
quarry doctor
```

`install.sh` provisions `pipx` if absent, installs the `quarry` CLI, then builds the toolset and fetches
wordlists and templates. The full build takes several minutes.

> If `quarry` is not found afterwards, the PATH change has not reached your shell yet — run
> `source ~/.bashrc` (or `~/.zshrc`), or open a new shell, then `quarry doctor` again.

When `pipx` already exists you can install without the repo:

```bash
pipx install "git+https://github.com/0xLumpy/quarry.git"
pipx ensurepath
quarry install --include-optional
quarry doctor
```

`quarry install` provisions the **standard** toolset; add `--include-optional` for the optional tools
(porch-pirate, caduceus, smap, gungnir, …). A missing optional tool is reported by `doctor` as info, not
a failure, and its lane skips.

## What each setup command owns

| Command | Owns |
|---------|------|
| `install.sh` | the whole blank-host bootstrap — pipx, the CLI, then everything `quarry install` does |
| `quarry install` | system packages → Go → the pinned toolset → wordlists / templates / resolvers |
| `quarry update` | reinstall installed tools at their pinned lock; refresh templates, resolvers, gf patterns |
| `quarry set <name>` | fetch or refresh a single managed data file (resolvers, a wordlist) by name |
| `quarry lock` | capture installed tool versions as a reviewable pin set; flag drift and unpinned tools |
| `quarry doctor` | audit the host — tools on PATH, versions, chromium, resolvers, wordlists, configured keys |

Quarry manages its own resolvers, wordlists, gf patterns, and Nuclei templates through these commands.
A tool's *own* API keys (subfinder, waymore) are not — see [external-integrations.md](external-integrations.md).

## Verify

`quarry doctor` confirms the recon tools are on PATH, chromium is present, and
`~/.config/quarry/{resolvers.txt,trusted-resolvers.txt}` and `~/.config/quarry/wordlists/dns.txt` exist.
Run it after install and after any `update`.

## Common install issues

- **`quarry: command not found`** — PATH not refreshed; source your shell rc or open a new shell.
- **A required tool fails to build** — `install.sh` still writes the PATH block and exits non-zero with a
  recovery hint (`quarry install --only <tool>`); re-run that in a new shell.
- **Screenshots skipped** — chromium is missing; install it, then re-run with `MODES.SCREENSHOTS`.
- **A provider lane skips** — its key is unset; see [secrets.md](secrets.md).

Next: [quickstart.md](quickstart.md).
