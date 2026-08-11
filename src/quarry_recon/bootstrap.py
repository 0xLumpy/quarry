"""Blank-VPS provisioning: system packages, Go toolchain, framework data files, extras.

Anything that cannot be automated (no sudo, unsupported OS) is reported, never silently skipped.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml


@dataclass
class InstallResult:
    """One install/bootstrap step's typed outcome; `blocks` is true only for a failed required step."""
    name: str
    ok: bool
    required: bool
    kind: str | None = None          # required_tool_missing | optional_tool_failed | machinery
    detail: str | None = None

    @property
    def blocks(self) -> bool:
        return self.required and not self.ok


def _ok(name: str, *, required: bool = True) -> InstallResult:
    return InstallResult(name, True, required)


def _failed(name: str, detail: str, *, required: bool = True,
            kind: str = "machinery") -> InstallResult:
    return InstallResult(name, False, required,
                         kind=("optional_tool_failed" if not required else kind), detail=detail)


class _ArchiveError(Exception):
    """A downloaded archive failed verification or carries an unsafe member — never extracted."""


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
    """Download `url` -> `dest` via argv (`--fail` makes an HTTP 4xx/5xx a nonzero exit); returns (rc, tail)."""
    if dry:
        return 0, "(dry-run)"
    try:
        p = subprocess.run(["curl", "--fail", "-sSL", url, "-o", str(dest)],
                           capture_output=True, text=True, timeout=timeout)
        tail = "\n".join((p.stdout + p.stderr).strip().splitlines()[-3:])
        return p.returncode, tail
    except subprocess.SubprocessError as e:
        return 1, str(e)


def _download_atomic(url: str, dest: Path, dry: bool, timeout: int = 300) -> tuple[int, str]:
    """Download to a temp sibling then atomic-replace `dest` only on non-empty success; returns (rc, tail)."""
    if dry:
        return _curl_to(url, dest, True, timeout)   # dry-run still shows the url->dest routing
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    code, tail = _curl_to(url, tmp, False, timeout)
    if code != 0 or not tmp.exists() or tmp.stat().st_size == 0:
        with contextlib.suppress(OSError):
            tmp.unlink()
        return (code or 1), tail
    os.replace(str(tmp), str(dest))
    return 0, tail


def _write_atomic(dest: Path, text: str) -> None:
    """Write `text` to a temp sibling then atomic-replace `dest` — never truncates the live file in place."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    tmp.write_text(text)
    os.replace(str(tmp), str(dest))


def _tool_deps(mgr: str) -> list[str]:
    """Union of per-tool `deps:` from tools.yaml (apt names), name-mapped for dnf/pacman."""
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


def _chromium_bin() -> "str | None":
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        p = shutil.which(b)
        if p:
            return p
    return None


def _chromium_state(dry: bool, cc: int, lc: int, tail: str) -> str:
    """One line for what the screenshot lane gets: it runs, it is missing, or it will not start
    (naming chromium's own reason)."""
    if dry:
        return "(dry-run)"
    exe = _chromium_bin()
    if not exe:
        why = (tail or "").strip().splitlines()
        return ("MISSING — screenshots/headless will be skipped"
                + (f" ({why[-1][:100]})" if why else "")
                + "; install it and re-run `quarry install`")
    try:
        r = subprocess.run([exe, "--headless", "--no-sandbox", "--disable-gpu",
                            "--dump-dom", "about:blank"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return f"{exe} present but WOULD NOT START ({type(e).__name__}: {e}) — screenshots will fail"
    if r.returncode == 0:
        return "ok"
    err = [l for l in (r.stderr or "").strip().splitlines() if l.strip()]
    return (f"{exe} present but headless FAILED (exit {r.returncode}) — screenshots will fail"
            + (f": {err[-1][:120]}" if err else ""))


def install_system_packages(echo, dry: bool) -> InstallResult:
    bs = load_bootstrap()
    mgr, prefix = detect_pkg_manager()
    if mgr is None:
        echo("  ! unsupported OS — install system packages manually (see README.md)")
        return _failed("system-packages", "unsupported OS — no package manager")

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
            lc, tail = _sh(f"{_sudo()}{prefix} {' '.join(libs + cg.get('libs_primary_extra', []))}", dry, 900)
            if lc != 0 and cg.get("libs_fallback"):
                # renamed-package fallback (libasound2 -> libasound2t64); a first-attempt failure is normal
                lc, tail = _sh(f"{_sudo()}{prefix} {' '.join(libs + cg['libs_fallback'])}", dry, 900)
            # the state comes from launching chromium, not from apt's exit codes
            echo(f"  chromium + headless libs: {_chromium_state(dry, cc, lc, tail)}")
        else:
            echo(f"  chromium: {'ok' if cc == 0 else 'manual install needed'}")
    return _ok("system-packages") if code == 0 else _failed("system-packages", tail[:80] or "some packages failed")


def _safe_tar_members(tf: tarfile.TarFile, base: Path) -> list:
    """Reject absolute/traversal/symlink/special members; every member must resolve inside `base`."""
    safe = []
    for m in tf.getmembers():
        if m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
            raise _ArchiveError(f"unsafe archive member (link/special): {m.name!r}")
        target = (base / m.name).resolve()
        if target != base and base not in target.parents:
            raise _ArchiveError(f"archive member escapes extraction dir: {m.name!r}")
        safe.append(m)
    return safe


def _verify_and_extract(archive: Path, sha: str, dest: Path) -> None:
    """Hash and extract from the same no-follow descriptor (verified bytes == extracted bytes)."""
    fd = os.open(str(archive), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise _ArchiveError("archive is not a regular file")
        h = hashlib.sha256()
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
        got = h.hexdigest()
        if got != sha:
            raise _ArchiveError(f"sha256 mismatch: {got} != {sha}")
        fh.seek(0)
        dest.mkdir(parents=True, exist_ok=True)
        base = dest.resolve()
        with tarfile.open(fileobj=fh, mode="r:gz") as tf:
            tf.extractall(dest, members=_safe_tar_members(tf, base))


def _renameat2_exchange_cmd(sudo: str, a: str, b: str) -> str:
    """Shell command that atomically swaps two pathnames via glibc renameat2(RENAME_EXCHANGE); nonzero when unavailable."""
    py = ("import ctypes,sys\n"
          "l=ctypes.CDLL(None,use_errno=True)\n"
          "try:\n"
          " r=l.renameat2(-100,sys.argv[1].encode(),-100,sys.argv[2].encode(),2)\n"
          "except AttributeError:\n"
          " sys.exit(1)\n"
          "sys.exit(0 if r==0 else 1)")
    return f"{sudo}python3 -c {shlex.quote(py)} {shlex.quote(a)} {shlex.quote(b)}"


def _swap_in_golang(cand: Path) -> tuple[bool, str]:
    """Activate the verified go tree via atomic RENAME_EXCHANGE (move/fallback otherwise), keeping .last-good for rollback."""
    sudo = _sudo()
    new = f"/usr/local/go.new.{os.getpid()}"
    lastgood = "/usr/local/go.last-good"
    if _sh(f"{sudo}rm -rf {new} {lastgood}", False, 60)[0] != 0:
        return False, "could not clear prior staging dirs"
    if _sh(f"{sudo}cp -a {shlex.quote(str(cand))} {new}", False, 300)[0] != 0:
        _sh(f"{sudo}rm -rf {new}", False, 60)                 # live tree untouched — only staging is cleared
        return False, "staging copy failed"

    live_exists = _sh(f"{sudo}sh -c 'test -e /usr/local/go'", False, 30)[0] == 0
    have_lastgood = False
    if not live_exists:
        if _sh(f"{sudo}mv {new} /usr/local/go", False, 120)[0] != 0:
            _sh(f"{sudo}rm -rf {new}", False, 60)
            return False, "activation move failed"
    elif _sh(_renameat2_exchange_cmd(sudo, new, "/usr/local/go"), False, 60)[0] == 0:
        # exchanged (go=new, new=old); preserve old as last-good, else exchange back and drop the new tree
        if _sh(f"{sudo}mv {new} {lastgood}", False, 120)[0] != 0:
            if _sh(_renameat2_exchange_cmd(sudo, new, "/usr/local/go"), False, 60)[0] != 0:
                return False, ("could NOT preserve the previous tree AND could not restore it — /usr/local/go "
                               "may be inconsistent")
            _sh(f"{sudo}rm -rf {new}", False, 60)             # `new` now holds the rejected new tree
            return False, "could NOT preserve the previous tree — restored the original, live install unchanged"
        have_lastgood = True
    else:
        # no renameat2: displace the live tree only now that the replacement is proven staged
        if _sh(f"{sudo}sh -c 'mv /usr/local/go {lastgood} && mv {new} /usr/local/go'", False, 120)[0] != 0:
            _sh(f"{sudo}sh -c 'rm -rf {new}; if [ ! -e /usr/local/go ] && [ -e {lastgood} ]; then "
                f"mv {lastgood} /usr/local/go; fi'", False, 60)
            return False, "activation swap failed"
        have_lastgood = _sh(f"{sudo}sh -c 'test -e {lastgood}'", False, 30)[0] == 0

    if _sh(f"{sudo}ln -sf /usr/local/go/bin/go /usr/local/bin/go", False, 60)[0] != 0:
        # post-activation failure: restore last-good only if we truly have it, and report honestly either way
        if not have_lastgood:
            return False, "symlink step failed after activation and there is no last-good — /usr/local/go may be inconsistent"
        restored = _sh(_renameat2_exchange_cmd(sudo, lastgood, "/usr/local/go"), False, 60)[0] == 0
        if not restored:
            restored = _sh(f"{sudo}sh -c 'rm -rf /usr/local/go && mv {lastgood} /usr/local/go'", False, 120)[0] == 0
        _sh(f"{sudo}sh -c 'rm -rf {lastgood}; ln -sf /usr/local/go/bin/go /usr/local/bin/go'", False, 60)
        if restored:
            return False, "symlink step failed after activation — restored last-good"
        return False, "symlink step failed AND last-good could NOT be restored — /usr/local/go may be inconsistent"
    _sh(f"{sudo}rm -rf {lastgood}", False, 60)                # activation confirmed; drop the rollback copy
    return True, ""


def _install_golang_safe(echo, url: str, sha: str) -> tuple[bool, str]:
    """Full staged go install in a private 0700 op dir; the current toolchain is untouched until verified."""
    op = Path(tempfile.mkdtemp(prefix="quarry-go."))
    try:
        arc = op / "go.tgz"
        code, tail = _curl_to(url, arc, False)
        if code != 0 or not arc.exists():
            return False, f"download failed: {tail[:60]}"
        stage = op / "root"
        try:
            _verify_and_extract(arc, sha, stage)
        except (_ArchiveError, OSError, tarfile.TarError) as e:
            return False, str(e)
        cand = stage / "go"
        if not (cand / "bin" / "go").is_file():
            return False, "archive did not contain go/bin/go"
        return _swap_in_golang(cand)
    finally:
        shutil.rmtree(op, ignore_errors=True)


def ensure_golang(echo, dry: bool) -> InstallResult:
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
                return _ok("go")
            echo(f"  go present but too old: {label}; need >= {bs['min_version']}")
        except subprocess.SubprocessError:
            pass
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
            "arm64": "arm64"}.get(platform.machine().lower())
    if arch is None:
        echo(f"  unsupported CPU architecture {platform.machine()!r} — cannot install a verified Go toolchain")
        return _failed("go", f"unsupported CPU architecture {platform.machine()!r}",
                       kind="required_tool_missing")
    osname = "darwin" if platform.system() == "Darwin" else "linux"
    # policy: an existing Go passes on min_version; an install takes the declared `version`, sha256-verified
    target = bs["version"]
    plat = f"{osname}/{arch}"
    sha = (bs.get("sha256") or {}).get(plat)
    if not (isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha)):
        echo(f"  Go archive sha256 not pinned for {plat} — refusing an UNVERIFIED /usr/local/go replacement (C08)")
        return _failed("go", f"archive sha256 not pinned for {plat}", kind="required_tool_missing")
    url = bs["url"].format(version=f"go{target}", os=osname, arch=arch)
    echo(f"  installing Go {target} {osname}/{arch}")
    if dry:
        return _ok("go")
    # under the same shared-resource install lock as the tool paths
    from .registry import _install_lock
    with _install_lock("go-toolchain") as locked:
        if not locked:
            echo("  go install: another install/update is in progress — skipped")
            return _failed("go", "another install/update is in progress", kind="required_tool_missing")
        ok, detail = _install_golang_safe(echo, url, sha)
    echo(f"  go install: {'ok' if ok else 'FAILED — ' + detail[:80]}")
    return _ok("go") if ok else _failed("go", detail, kind="required_tool_missing")


def install_data_files(echo, dry: bool, update: bool = False) -> InstallResult:
    bs = load_bootstrap()
    failures = []
    for df in bs.get("data_files", []):
        dest = Path(os.path.expanduser(df["dest"]))
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 0 and not (update and df.get("update")):
            echo(f"  {df['name']}: present")
            continue
        # download to a temp then atomic-replace: a failed/empty fetch leaves the previous file intact
        code, _ = _download_atomic(df["url"], dest, dry)
        if code == 0:
            echo(f"  {df['name']}: ok")
            continue
        # a failed refresh keeps an existing valid file (no fallback clobber) but is recorded so update reports it
        if not dry and dest.exists() and dest.stat().st_size > 0:
            echo(f"  {df['name']}: refresh FAILED — kept existing file")
            failures.append(df["name"])
            continue
        if df.get("fallback"):                                # first-time provisioning only
            if not dry:
                _write_atomic(dest, df["fallback"])
            echo(f"  {df['name']}: fetch failed — wrote bundled fallback")
            continue
        echo(f"  {df['name']}: FAILED")
        failures.append(df["name"])

    # framework secrets store — created once, chmod 600, never overwritten
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

    # non-secret runtime config (performance / local paths) — created once, never overwritten
    cp = Path.home() / ".config" / "quarry" / "config.yaml"
    if cp.exists():
        echo("  config.yaml: present")
    else:
        cp.parent.mkdir(parents=True, exist_ok=True)
        if not dry:
            tpl = resources.files("quarry_recon.data").joinpath("config.template.yaml").read_text()
            cp.write_text(tpl)
        echo("  config.yaml: created")

    if failures:
        return _failed("data-files", "failed: " + ", ".join(failures))
    return _ok("data-files")


def set_data_file(name: str, url: str | None, echo, dry: bool = False) -> bool:
    """Fetch/refresh one data file by name; on failure keep an existing valid file or write the bundled fallback, else False."""
    bs = load_bootstrap()
    df = next((d for d in bs.get("data_files", []) if d["name"] == name), None)
    if df is None:
        names = ", ".join(d["name"] for d in bs.get("data_files", []))
        echo(f"  unknown data file '{name}'. valid names: {names}")
        return False
    dest = Path(os.path.expanduser(df["dest"]))
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = url or df["url"]
    # atomic replace: a failed/empty refresh leaves the existing resolver/wordlist file intact
    code, tail = _download_atomic(src, dest, dry)
    if not dry and code != 0:
        # a failed refresh must not overwrite an existing valid file with fallback content, nor report success
        if dest.exists() and dest.stat().st_size > 0:
            echo(f"  {name}: refresh FAILED ({tail[:80] or 'empty output'}) — kept existing file → {dest}")
            return False
        if df.get("fallback") and not url:                      # first-time provisioning only; custom url = no fallback
            _write_atomic(dest, df["fallback"])
            echo(f"  {name}: fetch failed — wrote bundled fallback → {dest}")
            return True
        echo(f"  {name}: FAILED ({tail[:100] or 'empty output'})")
        return False
    echo(f"  {name}: ok → {dest}")
    return True


def run_extras(echo, dry: bool) -> InstallResult:
    bs = load_bootstrap()
    failures = []
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
        if code != 0:
            failures.append(ex["name"])
    # extras are optional: a failure is reported but never blocks the install
    return _ok("extras", required=False) if not failures else \
        _failed("extras", "failed: " + ", ".join(failures), required=False)


def cleanup(echo, dry: bool) -> None:
    """Reclaim disk after a bulk install: caches only (Go build/module, pip, package manager)."""
    steps = []
    if shutil.which("go"):
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


# Tiered baseline: recommended = silent ok · minimum..recommended = warn + proceed · below minimum = abort.
REC_CPU, REC_RAM_GB = 4, 8          # recommended (documented + displayed)
MIN_CPU, MIN_RAM_GB = 2, 4          # hard floor — below this, abort
RAM_DRIFT = 0.88                    # MemTotal sits under physical: an 8 GB VPS reports ~7.4–7.8
# install floors cover transient build space (Go modcache, freed by cleanup) plus run headroom;
# run floors cover output growth alone (crawl/screenshots/JSONL)
DISK_MIN = {"install": 5, "run": 10}     # below -> abort
DISK_WARN = {"install": 10, "run": 20}   # below -> warn
REC_DISK_GB = 40                         # recommended free (80+ for large targets)

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
    """Assess cpu/ram + disk against the tiers; unknown (0) values never fail.

    `context` ('install' | 'run') selects the disk floors. Returns
    {'level': 'ok'|'warn'|'abort', 'checks': [(text, level), ...]}.
    """
    cpu, ram = system_info()
    disk = disk_free_gb()

    cpu_s = f"{cpu} vCPU" if cpu else "unknown vCPU"
    ram_s = f"{ram:.1f} GB" if ram else "unknown"
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
