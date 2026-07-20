"""Blank-VPS provisioning: system packages, Golang, framework data files, extras.

This is what makes `quarry install` a complete installer (design principle 12) rather than
just a per-tool runner: on a fresh VPS it installs the OS deps, Go toolchain, wordlists,
resolvers, gf patterns and nuclei templates the methodology needs. Anything it cannot
automate (no sudo, unsupported OS) is reported, never silently skipped.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from importlib import resources
from pathlib import Path

import yaml


def load_bootstrap() -> dict:
    return yaml.safe_load(
        resources.files("quarry_recon.data").joinpath("bootstrap.yaml").read_text())


def detect_pkg_manager() -> tuple[str | None, str]:
    """Return (manager_key, install_prefix). manager_key matches bootstrap.yaml."""
    if platform.system() == "Darwin":
        return ("brew", "brew install")
    for mgr, prefix in (("apt", "apt-get install -y"),
                        ("dnf", "dnf install -y"),
                        ("pacman", "pacman -Sy --noconfirm")):
        if shutil.which(mgr) or shutil.which(mgr.replace("apt", "apt-get")):
            return (mgr, prefix)
    if Path("/etc/debian_version").exists():
        return ("apt", "apt-get install -y")
    return (None, "")


def _sudo() -> str:
    if os.geteuid() == 0 or platform.system() == "Darwin":
        return ""
    return "sudo " if shutil.which("sudo") else ""


def _sh(cmd: str, dry: bool, timeout: int = 1800) -> tuple[int, str]:
    if dry:
        return 0, "(dry-run)"
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        tail = "\n".join((p.stdout + p.stderr).strip().splitlines()[-3:])
        return p.returncode, tail
    except subprocess.SubprocessError as e:
        return 1, str(e)


def _curl_to(url: str, dest: Path, dry: bool, timeout: int = 300) -> tuple[int, str]:
    """Download `url` → `dest` via argv (NO shell). `quarry set --url <src>` is user input, so a
    shell-string `curl '...'` is injectable (a single quote in the URL breaks out). subprocess.run
    with a list passes the URL as one opaque argv element — nothing to escape, nothing to inject."""
    if dry:
        return 0, "(dry-run)"
    try:
        p = subprocess.run(["curl", "-sSL", url, "-o", str(dest)],
                           capture_output=True, text=True, timeout=timeout)
        tail = "\n".join((p.stdout + p.stderr).strip().splitlines()[-3:])
        return p.returncode, tail
    except subprocess.SubprocessError as e:
        return 1, str(e)


def _tool_deps(mgr: str) -> list[str]:
    """Union of per-tool `deps:` from tools.yaml (apt names). Other managers: best-effort
    name-map for the few that differ."""
    from .registry import load_tools
    apt_to = {
        "pacman": {"libpcap-dev": "libpcap", "libxml2-dev": "libxml2",
                   "libxslt1-dev": "libxslt", "zlib1g-dev": "zlib",
                   "build-essential": "base-devel"},
        "dnf": {"libpcap-dev": "libpcap-devel", "libxml2-dev": "libxml2-devel",
                "libxslt1-dev": "libxslt-devel", "zlib1g-dev": "zlib-devel",
                "build-essential": "@Development Tools"},
    }
    out = set()
    for t in load_tools():
        for d in (t.deps or []):
            out.add(apt_to.get(mgr, {}).get(d, d) if mgr in apt_to else d)
    return sorted(out)


def install_system_packages(echo, dry: bool) -> bool:
    bs = load_bootstrap()
    mgr, prefix = detect_pkg_manager()
    if mgr is None:
        echo("  ! unsupported OS — install system packages manually (see README.md)")
        return False

    base = list(bs["system_packages"].get(mgr, []))
    tool_deps = _tool_deps(mgr)
    extra = [d for d in tool_deps if d not in base]
    pkgs = base + extra
    echo(f"  pkg manager: {mgr} — {len(base)} base + {len(extra)} tool-specific deps")
    if extra:
        echo(f"    tool deps: {', '.join(extra)}")

    if mgr == "apt":
        _sh(f"{_sudo()}apt-get update -qq", dry, 600)
    code, tail = _sh(f"{_sudo()}{prefix} {' '.join(pkgs)}", dry, 1800)
    echo(f"  base packages: {'ok' if code == 0 else 'some failed — ' + tail[:80]}")

    # ── chromium group (separate, with fallbacks) ──
    cg = bs.get("chromium_packages", {}).get(mgr)
    if cg:
        cc, _ = _sh(f"{_sudo()}{prefix} {' '.join(cg['primary'])}", dry, 600)
        if cc != 0 and cg.get("fallback"):
            cc, _ = _sh(f"{_sudo()}{prefix} {' '.join(cg['fallback'])}", dry, 600)
        libs = cg.get("libs", [])
        if libs:
            lc, _ = _sh(f"{_sudo()}{prefix} {' '.join(libs + cg.get('libs_primary_extra', []))}", dry, 900)
            if lc != 0 and cg.get("libs_fallback"):
                lc, _ = _sh(f"{_sudo()}{prefix} {' '.join(libs + cg['libs_fallback'])}", dry, 900)
            echo(f"  chromium + headless libs: {'ok' if (cc == 0 and lc == 0) else 'check log (some libs optional)'}")
        else:
            echo(f"  chromium: {'ok' if cc == 0 else 'manual install needed'}")
    return code == 0


def ensure_golang(echo, dry: bool) -> bool:
    bs = load_bootstrap()["golang"]
    min_version = tuple(int(p) for p in str(bs.get("min_version", "0")).split("."))
    if shutil.which("go"):
        try:
            v = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=10)
            label = v.stdout.strip()
            found = re.search(r"go([0-9]+(?:\.[0-9]+)+)", label)
            version = tuple(int(p) for p in found.group(1).split(".")) if found else (0,)
            if version >= min_version:
                echo(f"  go present: {label}")
                return True
            echo(f"  go present but too old: {label}; need >= {bs['min_version']}")
        except subprocess.SubprocessError:
            pass
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
            "arm64": "arm64"}.get(platform.machine().lower())
    if arch is None:                                        # review-C08.2r4#7: an unknown arch must FAIL LOUD, not
        echo(f"  unsupported CPU architecture {platform.machine()!r} — cannot install a verified Go toolchain")
        return False                                       # silently installing an amd64 archive would be unusable
    osname = "darwin" if platform.system() == "Darwin" else "linux"
    # review-C08.2r3#3 (Go toolchain policy): the Go compiler is a BUILD TOOLCHAIN — policy is min_version (keep
    # an adequate existing/distro Go, kept as-is above). When absent/too old we install the DECLARED `version`
    # (not floating latest) AND VERIFY the archive sha256 before replacing /usr/local/go (C08 supply-chain).
    target = bs["version"]
    plat = f"{osname}/{arch}"
    sha = (bs.get("sha256") or {}).get(plat)
    if not (isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha)):
        echo(f"  Go archive sha256 not pinned for {plat} — refusing an UNVERIFIED /usr/local/go replacement (C08)")
        return False
    url = bs["url"].format(version=f"go{target}", os=osname, arch=arch)
    echo(f"  installing Go {target} ({osname}-{arch}) [declared version, sha256-verified; min {bs['min_version']}]")
    cmd = (f"wget -q {url} -O /tmp/go.tgz && echo '{sha}  /tmp/go.tgz' | sha256sum -c - && "
           f"{_sudo()}rm -rf /usr/local/go && "
           f"{_sudo()}tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz && "
           f"{_sudo()}ln -sf /usr/local/go/bin/go /usr/local/bin/go")
    code, tail = _sh(cmd, dry, 600)
    echo(f"  go install: {'ok' if code == 0 else 'FAILED — ' + tail[:80]}")
    return code == 0


def install_data_files(echo, dry: bool, update: bool = False) -> None:
    bs = load_bootstrap()
    for df in bs.get("data_files", []):
        dest = Path(os.path.expanduser(df["dest"]))
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 0 and not (update and df.get("update")):
            echo(f"  {df['name']}: present")
            continue
        code, _ = _curl_to(df["url"], dest, dry)
        if (code != 0 or (not dry and (not dest.exists() or dest.stat().st_size == 0))) and df.get("fallback"):
            if not dry:
                dest.write_text(df["fallback"])
            code = 0
        echo(f"  {df['name']}: {'ok' if code == 0 else 'FAILED'}")

    # framework secrets store — created once, chmod 600, NEVER overwritten
    sp = Path.home() / ".config" / "quarry" / "secrets.yaml"
    if sp.exists():
        echo("  secrets.yaml: present")
    else:
        sp.parent.mkdir(parents=True, exist_ok=True)
        if not dry:
            tpl = resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()
            sp.write_text(tpl)
            sp.chmod(0o600)
        echo("  secrets.yaml: created")

    # non-secret runtime config (PERFORMANCE / local paths) — created once, NEVER overwritten
    cp = Path.home() / ".config" / "quarry" / "config.yaml"
    if cp.exists():
        echo("  config.yaml: present")
    else:
        cp.parent.mkdir(parents=True, exist_ok=True)
        if not dry:
            tpl = resources.files("quarry_recon.data").joinpath("config.template.yaml").read_text()
            cp.write_text(tpl)
        echo("  config.yaml: created")


def set_data_file(name: str, url: str | None, echo, dry: bool = False) -> bool:
    """Fetch/refresh ONE data file by name — the granular alternative to a full `quarry install`.

    The NAME (from bootstrap.yaml `data_files`) always determines the destination; `url` only
    overrides the SOURCE (e.g. point resolvers at a fresher list). Overwrites unconditionally — the
    whole point is to refresh a single file. Robust on failure: falls back to the bundled default when
    one exists (and no custom url was given), else reports the failure and returns False."""
    bs = load_bootstrap()
    df = next((d for d in bs.get("data_files", []) if d["name"] == name), None)
    if df is None:
        names = ", ".join(d["name"] for d in bs.get("data_files", []))
        echo(f"  unknown data file '{name}'. valid names: {names}")
        return False
    dest = Path(os.path.expanduser(df["dest"]))
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = url or df["url"]
    code, tail = _curl_to(src, dest, dry)
    if not dry and (code != 0 or not dest.exists() or dest.stat().st_size == 0):
        if df.get("fallback") and not url:                      # custom url = user's problem, no fallback
            dest.write_text(df["fallback"])
            echo(f"  {name}: fetch failed — wrote bundled fallback → {dest}")
            return True
        echo(f"  {name}: FAILED ({tail[:100] or 'empty output'})")
        return False
    echo(f"  {name}: ok → {dest}")
    return True


def run_extras(echo, dry: bool) -> None:
    bs = load_bootstrap()
    for ex in bs.get("extras", []):
        if ex.get("needs") and not shutil.which(ex["needs"]):
            echo(f"  {ex['name']}: skipped (needs {ex['needs']})")
            continue
        if ex.get("test") and not dry:
            test_code, _ = _sh(ex["test"], False, 30)
            if test_code == 0:
                echo(f"  {ex['name']}: present")
                continue
        code, tail = _sh(ex["run"], dry, 600)
        echo(f"  {ex['name']}: {'ok' if code == 0 else 'failed — ' + tail[:60]}")


def cleanup(echo, dry: bool) -> None:
    """Reclaim disk after a bulk install (Go module/build caches are GBs after building ~25
    Go tools; package-manager download caches add more). Tools keep working — only caches go."""
    steps = []
    if shutil.which("go"):
        # build cache + downloaded module sources + test cache (the big ones)
        steps.append(("go caches", "go clean -cache -modcache -testcache"))
    steps.append(("pip cache", "rm -rf ~/.cache/pip"))
    mgr, _ = detect_pkg_manager()
    if mgr == "apt":                                       # clean takes no -y (older apt rejects it)
        steps.append(("apt cache", f"{_sudo()}apt-get clean"))
    elif mgr == "dnf":
        steps.append(("dnf cache", f"{_sudo()}dnf clean all"))
    elif mgr == "pacman":
        steps.append(("pacman cache", f"{_sudo()}pacman -Sc --noconfirm"))
    for label, cmd in steps:
        code, _ = _sh(cmd, dry, 600)
        echo(f"  {label}: {'cleared' if code == 0 else 'skip'}")


# Tiered baseline (long DNS/HTTP scans are CPU/RAM hungry; crawl/screenshots/JSONL eat disk).
# Recommended = silent ok · Minimum..Recommended = warn + proceed · below Minimum = abort.
REC_CPU, REC_RAM_GB = 4, 8          # recommended (documented + displayed)
MIN_CPU, MIN_RAM_GB = 2, 4          # hard floor — below this, abort
RAM_DRIFT = 0.88                    # MemTotal sits under physical (kernel/hypervisor reserve):
                                    # an 8 GB VPS reports ~7.4–7.8 → gate at 8*0.88=7.04 clears it,
                                    # while a true sub-8 box (~6.7) still warns. Same for the 4 GB floor.
# Disk-free floors differ by context: install needs transient build space (Go modcache balloons
# mid-build, freed in the cleanup stage) PLUS run headroom; after install only run space matters.
# Install floors loosened 2026-07-04: a clean VPS git-clone + full install measured ~3.6 GB used
# (go build/module caches balloon transiently, then bootstrap.cleanup reclaims them). The old
# 20/30 GB install floors were far too conservative. RUN floors stay — run-time output growth on
# big targets (crawl/screenshots/JSONL) is the real disk driver.
DISK_MIN = {"install": 5, "run": 10}     # below -> abort
DISK_WARN = {"install": 10, "run": 20}   # below -> warn
REC_DISK_GB = 40                         # recommended free for comfortable runs (80+ for large targets)

_RANK = {"ok": 0, "warn": 1, "abort": 2}


def system_info() -> tuple[int, float]:
    """(cpu_count, total_ram_GB). ram is 0.0 when it can't be determined."""
    cpu = os.cpu_count() or 0
    ram_gb = 0.0
    try:
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            for line in meminfo.read_text().splitlines():
                if line.startswith("MemTotal:"):
                    ram_gb = int(line.split()[1]) / (1024 * 1024)   # kB -> GiB
                    break
        else:  # non-Linux fallback
            ram_gb = (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")) / (1024 ** 3)
    except (OSError, ValueError, AttributeError):
        pass
    return cpu, ram_gb


def disk_free_gb(path: Path | None = None) -> float:
    """Free space (GB) on the partition holding $HOME (where tools/wordlists/runs land). 0.0 if unknown."""
    try:
        return shutil.disk_usage(path or Path.home()).free / (1024 ** 3)
    except OSError:
        return 0.0


def system_report(context: str = "install") -> dict:
    """Assess cpu/ram + disk against the tiers. Unknown (0) values never fail.

    `context` ('install' | 'run') only changes the disk floors — install needs transient build
    space + run headroom; 'run' (doctor) needs only run space. Returns
    {'level': 'ok'|'warn'|'abort', 'checks': [(text, level), ...]}.
    """
    cpu, ram = system_info()
    disk = disk_free_gb()

    cpu_s = f"{cpu} vCPU" if cpu else "unknown vCPU"
    ram_s = f"{ram:.1f} GB" if ram else "unknown"
    # drift tolerance on RAM both tiers — a 4 GB box reports ~3.8, an 8 GB box ~7.8 (kernel reserve)
    if (cpu and cpu < MIN_CPU) or (ram and ram < MIN_RAM_GB * RAM_DRIFT):
        cr = "abort"
    elif (cpu and cpu < REC_CPU) or (ram and ram < REC_RAM_GB * RAM_DRIFT):
        cr = "warn"
    else:
        cr = "ok"

    dmin = DISK_MIN.get(context, DISK_MIN["install"])
    dwarn = DISK_WARN.get(context, DISK_WARN["install"])
    disk_s = f"{disk:.0f} GB free" if disk else "unknown"
    if disk and disk < dmin:
        dk = "abort"
    elif disk and disk < dwarn:
        dk = "warn"
    else:
        dk = "ok"

    checks = [
        (f"cpu/ram: {cpu_s} · {ram_s} RAM", cr),
        (f"disk:    {disk_s}", dk),
    ]
    level = max((c[1] for c in checks), key=lambda lv: _RANK[lv])
    return {"level": level, "checks": checks}
