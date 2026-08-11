"""Tool registry — load tool definitions (data/tools.yaml), audit installs, drive install/update/doctor."""
from __future__ import annotations

import contextlib
import fcntl
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# version token, not part of a longer dotted number (excludes IPs like 127.0.0.1)
_VER_RE = re.compile(r"(?<![\w.])v?\d+\.\d+(?:\.\d+)?(?![\w.])")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SENTINEL_PINS = {"installed", "latest", "main", "master", "head"}   # floating refs — never a valid pin
_MAINTENANCE_STATES = {"active", "monitor", "frozen", "distro"}      # refresh cadence (planning only)


class LockError(ValueError):
    """A tools.yaml lock field is malformed — loading fails rather than trusting it."""


class _ActivationError(Exception):
    """A staged binary was swapped in but failed a post-swap identity/receipt check — triggers rollback."""


@contextlib.contextmanager
def _install_lock(bin_: str):
    """Serialize concurrent installs/updates of one binary (non-blocking flock); yields False if held."""
    lock_dir = Path.home() / ".local" / "bin" / ".stage"
    lock_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_dir / f".{bin_}.installing.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError:
            acquired = False
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _validate_lock(bin_: str, t: dict) -> None:
    def _bad(msg):
        raise LockError(f"{bin_}: {msg}")
    v = t.get("version")
    if v is not None:
        if not isinstance(v, str) or not v.strip():
            _bad(f"version must be a non-empty string, got {v!r}")
        if v.strip().lower() in _SENTINEL_PINS:
            _bad(f"version {v!r} is a floating sentinel (installed/latest/…) — pin an exact release")
        # a version tag alone doesn't fix downloaded bytes; go/pipx verify their own hashes
        if t.get("runtime") == "binary" and not t.get("artifacts"):
            _bad("a binary tool with a version pin must declare per-platform `artifacts` (url + sha256)")
        # without a parseable module installed_identity can never prove the built binary
        if t.get("runtime", "go") == "go" and not re.search(r"go install\s+(\S+?)@", t.get("install") or ""):
            _bad("a pinned go tool needs a parseable `go install <module>@…` install command")
    ref = t.get("ref")
    if ref is not None:
        if not str(ref).strip():
            _bad("source `ref` must be a non-empty commit/tag")
        if str(ref).strip().lower() in _SENTINEL_PINS:
            _bad(f"ref {ref!r} is a floating sentinel — pin an exact commit/tag")
    for _codes_key in ("cap_codes", "version_codes"):        # same shape rules for both
        cc = t.get(_codes_key)
        if cc is not None:
            if (not isinstance(cc, list) or not cc or len(cc) != len(set(cc))
                    or not all(type(x) is int and 0 <= x <= 255 for x in cc)):  # bool is an int subclass
                _bad(f"{_codes_key} must be a non-empty list of unique ints (not bools) in 0..255, got {cc!r}")
    for key in ("ref", "policy", "capability", "release"):
        val = t.get(key)
        if val is not None and (not isinstance(val, str) or not val.strip()):
            _bad(f"{key} must be a non-empty string, got {val!r}")
    ms = t.get("maintenance_state")                          # refresh-policy metadata (planning only)
    if ms is not None and ms not in _MAINTENANCE_STATES:
        _bad(f"maintenance_state must be one of {sorted(_MAINTENANCE_STATES)}, got {ms!r}")
    # checked unconditionally, so either field alone is rejected rather than silently accepted
    if (ms == "distro") != (t.get("policy") == "distro"):
        _bad("maintenance_state 'distro' and policy: distro must agree (set both or neither)")
    rel = t.get("release")
    if rel is not None:
        if str(rel).strip().lower() in _SENTINEL_PINS:
            _bad(f"release {rel!r} is a floating sentinel — a release is an EXACT human tag")
        pinref = t.get("version") or t.get("ref")
        if not pinref:
            _bad("release requires a pin (version) or ref to differ from")
        # a plain normalized compare, not version_eq — validation is a pure data check
        elif str(rel).strip().lstrip("vV") == str(pinref).strip().lstrip("vV"):
            _bad(f"release {rel!r} == pin {pinref!r} — record `release` ONLY when it differs (a pseudo-version pin)")
    arts = t.get("artifacts")
    if arts is not None:
        if not isinstance(arts, dict) or not arts:
            _bad(f"artifacts must be a non-empty mapping, got {arts!r}")
        for plat, a in arts.items():
            if not isinstance(plat, str) or "/" not in plat:
                _bad(f"artifact platform key must be '<os>/<arch>', got {plat!r}")
            if not isinstance(a, dict) or not isinstance(a.get("url"), str) or not a["url"].strip():
                _bad(f"artifact {plat}: needs a non-empty url")
            if not (isinstance(a.get("sha256"), str) and _SHA256_RE.match(a["sha256"])):
                _bad(f"artifact {plat}: sha256 must be 64 hex chars, got {a.get('sha256')!r}")

import yaml


@dataclass
class Tool:
    bin: str
    phase: str
    role: str
    install: str | None = None
    update: str | None = None
    version_cmd: str | None = None
    doc: str | None = None
    keys: str | None = None
    optional: bool = False
    notes: str | None = None
    runtime: str = "go"            # go | pipx | source | binary — toolchain it needs
    deps: list[str] | None = None  # extra apt packages this specific tool needs
    needs_chromium: bool = False   # runtime needs a chromium browser
    # a language runtime another tool needs (bun), provisioned here but reported with go/pipx/chromium
    dependency: bool = False
    # lock, one shape per runtime: go/pipx pin version, binary pins tag+artifacts, source pins ref, distro sets policy
    pin: str | None = None
    artifacts: dict | None = None          # {"linux/amd64": {"url": str, "sha256": <64-hex>}, ...}
    ref: str | None = None                 # exact source commit/tag (source runtime)
    policy: str | None = None              # e.g. "distro" — pinning delegated (apt)
    capability: str | None = None
    cap_codes: list | None = None          # accepted capability exit codes (default [0]); explicit per tool
    # accepted exit codes for the version probe (default [0]); separate axis from cap_codes
    version_codes: list | None = None
    # upstream "owner/name" for binary/source tools — the identity a future `quarry lock --refresh` queries
    repo: str | None = None
    # refresh policy, planning only — never affects verify/drift/install/runtime; `release` = the human tag
    maintenance_state: str | None = None
    release: str | None = None
    # install lock key for tools sharing one on-disk asset; defaults to the bin (each tool locks only itself)
    lock_key: str | None = None

    @property
    def installed(self) -> bool:
        return shutil.which(self.bin) is not None

    @property
    def path(self) -> str | None:
        return shutil.which(self.bin)

    def version(self) -> str:
        """Clean version string from the version probe (gated on version_codes, default {0}); "" when none parses."""
        if not self.installed or not self.version_cmd:
            return ""
        rc, out = _probe(self.version_cmd)
        return _parse_version(out) if _version_ok(rc, self.version_codes) else ""


_PROBE_NOT_RUN = -1     # "not executed / timed out" — distinct from any exit code a tool could accept


def _probe(cmd: str, timeout: int = 15, pass_fd: int | None = None) -> tuple[int, str]:
    """Run a shell probe -> (rc, ANSI-stripped output); _PROBE_NOT_RUN on timeout/launch failure. `pass_fd` is inherited by the child via pass_fds."""
    kwargs = {"pass_fds": (pass_fd,)} if pass_fd is not None else {}
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, **kwargs)
        return p.returncode, _ANSI_RE.sub("", p.stdout + p.stderr)
    except (subprocess.SubprocessError, OSError):
        return _PROBE_NOT_RUN, ""


def _parse_version(text: str) -> str:
    """First version-like token from probe output (prefer a line that names a version); "" if none."""
    for line in (text or "").splitlines():
        if "version" in line.lower():
            m = _VER_RE.search(line)
            if m:
                return m.group(0)
    m = _VER_RE.search(text or "")
    return m.group(0) if m else ""


def load_tools() -> list[Tool]:
    data = yaml.safe_load(resources.files("quarry_recon.data").joinpath("tools.yaml").read_text())
    tools = []
    for t in data.get("tools", []):
        _validate_lock(t.get("bin", "?"), t)
        tools.append(Tool(
            bin=t["bin"], phase=t.get("phase", "?"), role=t.get("role", ""),
            install=t.get("install"), update=t.get("update"),
            version_cmd=t.get("version_cmd"), doc=t.get("doc"),
            keys=t.get("keys"), optional=bool(t.get("optional", False)),
            notes=t.get("notes"), runtime=t.get("runtime", "go"),
            deps=t.get("deps") or [], needs_chromium=bool(t.get("needs_chromium", False)),
            dependency=bool(t.get("dependency", False)),
            pin=t.get("version"), artifacts=t.get("artifacts"), ref=t.get("ref"),
            policy=t.get("policy"), capability=t.get("capability"), cap_codes=t.get("cap_codes"),
            repo=t.get("repo"), maintenance_state=t.get("maintenance_state"), release=t.get("release"),
            version_codes=t.get("version_codes"), lock_key=t.get("lock_key"),
        ))
    return tools


def tools_by_phase(phase: str) -> list[Tool]:
    return [t for t in load_tools() if t.phase == phase]


def tool_phases() -> set[str]:
    """The phase names any tool declares — the valid `--phase` domain for doctor/install selectors."""
    return {t.phase for t in load_tools()}


def version_eq(a: str | None, b: str | None) -> bool:
    """Tolerant version compare (normalize leading 'v'/whitespace); empty/None never matches."""
    def _norm(s):
        return (s or "").strip().lstrip("vV")
    na, nb = _norm(a), _norm(b)
    return bool(na) and na == nb


def _go_mod_and_version(path: str) -> tuple[str, str]:
    """The Go module path + version embedded in a built binary (`go version -m`); ('', '') if unreadable."""
    if not path:
        return "", ""
    try:
        p = subprocess.run(["go", "version", "-m", path], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "", ""
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "mod":
            return parts[1], parts[2]                       # "mod <module> <version>"
    return "", ""


def _expected_go_module(t: "Tool") -> str:
    """The module path a go tool should be built from — its `go install <path>@ver`, `/cmd/...` stripped."""
    m = re.search(r"go install\s+(\S+?)@", t.install or "")
    return re.sub(r"/cmd/.*$", "", m.group(1)) if m else ""


def _pipx_pkg(t: "Tool") -> str:
    m = re.search(r"pipx install\s+(\S+)", t.install or "")
    return m.group(1) if m else t.bin


def _norm_pkg(name: str) -> str:
    """PEP 503 name normalization — pipx keys venvs by the normalized name (xnLinkFinder -> xnlinkfinder)."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _pipx_meta(pkg: str) -> tuple[str, list]:
    """(version, app_paths) for the installed pipx package from `pipx list --json`; ('', []) if unreadable."""
    try:
        import json
        p = subprocess.run(["pipx", "list", "--json"], capture_output=True, text=True, timeout=25)
        root = json.loads(p.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return "", []
    if not isinstance(root, dict) or not isinstance(root.get("venvs"), dict):
        return "", []
    want = _norm_pkg(pkg)
    for k, v in root["venvs"].items():
        if not isinstance(v, dict):
            continue
        meta = v.get("metadata") if isinstance(v.get("metadata"), dict) else {}
        mp = meta.get("main_package") if isinstance(meta.get("main_package"), dict) else {}
        if _norm_pkg(k) == want or _norm_pkg(str(mp.get("package", ""))) == want:
            raw = mp.get("app_paths") or []
            paths = [a.get("__Path__", "") if isinstance(a, dict) else str(a) for a in raw if a]
            return str(mp.get("package_version", "") or ""), [p for p in paths if p]
    return "", []


def _receipt_path(bin_: str):
    return Path.home() / ".local" / "bin" / f".{bin_}.lock"      # receipt: pin/ref + activated sha256


def _file_sha256(path) -> str:
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _fd_sha256(fd: int) -> str:
    """sha256 of the bytes behind an open descriptor — the identity we record is the object we activate."""
    import hashlib
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(fd, 65536), b""):
        h.update(chunk)
    return h.hexdigest()


def _relink(src: Path, dst: Path) -> None:
    """Hardlink `src` -> `dst` (same inode, same filesystem), replacing any existing `dst`; `src` stays put."""
    dst.unlink(missing_ok=True)
    os.link(str(src), str(dst))


def _publish_verified(fd: int, stage: Path, work: Path, dest: Path) -> None:
    """Activate the exact inode behind `fd`: hardlink to a private name, verify inode identity, rename into `dest`, confirm the landed inode."""
    os.link(str(stage), str(work), follow_symlinks=False)
    try:
        vst, wst = os.fstat(fd), os.lstat(work)
        if not stat.S_ISREG(wst.st_mode) or (wst.st_dev, wst.st_ino) != (vst.st_dev, vst.st_ino):
            raise _ActivationError("staged pathname no longer resolves to the verified artifact — NOT activated")
        os.replace(str(work), str(dest))
        dfd = os.open(str(dest), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            pst = os.fstat(dfd)
            if (pst.st_dev, pst.st_ino) != (vst.st_dev, vst.st_ino):
                raise _ActivationError("published object is not the verified inode — NOT activated")
        finally:
            os.close(dfd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(work)
        raise


def _restore_last_good(had_prev: bool, dest: Path, backup: Path,
                       receipt: Path, receipt_backup: Path) -> None:
    """Restore dest+receipt to the last-good pair; a binary-restore failure propagates, the receipt is restored or else deleted."""
    if had_prev:
        os.replace(str(backup), str(dest))                   # raises on failure -> caller reports it loudly
        try:
            if receipt_backup.exists():
                os.replace(str(receipt_backup), str(receipt))
            else:
                receipt.unlink(missing_ok=True)
        except OSError:
            receipt.unlink(missing_ok=True)
    else:
        dest.unlink(missing_ok=True)
        receipt.unlink(missing_ok=True)


def _read_receipt(bin_: str) -> dict:
    try:
        import json
        rp = _receipt_path(bin_)
        rec = json.loads(rp.read_text()) if rp.exists() else {}
    except (OSError, ValueError):
        return {}
    return rec if isinstance(rec, dict) else {}            # a list/scalar receipt is not usable


def _write_receipt(bin_: str, ident: str, sha: str) -> None:
    """Write the receipt {ident, sha256} atomically (temp + rename to a new inode)."""
    import json
    rp = _receipt_path(bin_)
    tmp = rp.with_name(f".{rp.name}.{os.urandom(6).hex()}.tmp")
    tmp.write_text(json.dumps({"ident": ident, "sha256": sha}))
    os.replace(str(tmp), str(rp))


def installed_identity(t: "Tool") -> str:
    """Installed version by runtime identity (go: `go version -m`; pipx: `pipx list`; binary/source: the receipt `ident` with sha rechecked; distro: 'distro'); "" when unprovable."""
    if not t.installed:
        return ""
    if t.policy == "distro":
        return "distro"
    # identity is of the executable that resolves on PATH (binary/source shadowing is caught in install_one)
    which = shutil.which(t.bin)
    if t.runtime in ("go", "pipx") and not which:
        return ""
    if t.runtime == "go":
        mod, ver = _go_mod_and_version(which)               # the resolved binary, not just t.path
        exp = _expected_go_module(t)
        # exact module; an unparseable expected module fails closed rather than accepting any module
        if not mod or not exp or mod != exp:
            return ""
        return ver
    if t.runtime == "pipx":
        # an out-of-pipx shadow must not borrow this env's version, and an empty app_paths proves nothing
        ver, app_paths = _pipx_meta(_pipx_pkg(t))
        if not ver:
            return ""
        if not app_paths or Path(which).resolve() not in {Path(a).resolve() for a in app_paths}:
            return ""                                       # resolved binary isn't the pipx-installed one
        return ver
    if t.runtime in ("binary", "source"):
        # no receipt (an unverified pre-lock binary) -> unknown identity -> reinstall; a changed sha -> drift
        rec = _read_receipt(t.bin)
        ident, sha = rec.get("ident"), rec.get("sha256")
        if not ident or not sha or _file_sha256(which or t.path) != sha:
            return ""
        return str(ident)
    return t.version()


def _drift_status(t: "Tool", installed: bool, iv: str) -> str:
    """Pin status from identity `iv`: not-installed | distro | version-unknown | unpinned | ok | drift."""
    if not installed:
        return "not-installed"
    if t.policy == "distro":
        return "distro"                                     # pinning delegated, not drift-checked
    expected = t.pin or t.ref
    if not iv:
        return "version-unknown"
    if not expected:
        return "unpinned"
    if t.runtime == "source":
        return "ok" if iv == expected else "DRIFT"          # exact commit match
    return "ok" if version_eq(iv, expected) else "DRIFT"


def drift(t: Tool) -> str:
    return _drift_status(t, t.installed, installed_identity(t) if t.installed else "")


def capture_lock() -> list[dict]:
    """Each managed tool's installed identity vs its pin/ref with drift status (probes each once), for `quarry lock`."""
    rows = []
    for t in load_tools():
        installed = t.installed
        iv = installed_identity(t) if installed else ""     # probe once
        rows.append({"bin": t.bin, "installed": iv or None, "pin": t.pin or t.ref,
                     "runtime": t.runtime, "optional": t.optional,
                     "drift": _drift_status(t, installed, iv),
                     # refresh-policy metadata (planning only)
                     "maintenance": t.maintenance_state, "release": t.release or t.pin or t.ref})
    return rows


def current_platform() -> str:
    """Install-host platform key ('linux/amd64' | 'linux/arm64' …) selecting a binary artifact."""
    import platform as _p
    m = _p.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)
    return f"linux/{arch}"


def pinned_install(t: Tool) -> str | None:
    """Version-locked install command (go @pin, pipx install --force pkg==pin, binary url+sha, source ref); None when a binary has no artifact here."""
    cmd = t.install
    if not cmd:
        return cmd
    if t.runtime == "go" and t.pin:
        return cmd.replace("@latest", "@" + t.pin)
    if t.runtime == "pipx" and t.pin:
        # `pipx install pkg==ver` leaves an existing env alone; only --force applies the pin (or a downgrade)
        return re.sub(r"pipx install\s+(\S+).*",
                      lambda m: f'pipx install --force "{m.group(1)}=={t.pin}"', cmd, count=1)
    if t.runtime == "binary" and t.artifacts:
        art = t.artifacts.get(current_platform())
        if not art:
            return None                                     # no artifact here -> uninstallable
        return cmd.format(url=art["url"], sha256=art["sha256"], bin=t.bin)
    if t.runtime == "source" and t.ref:
        return cmd.format(ref=t.ref, bin=t.bin)
    return cmd


def _go_bin_dir() -> "Path | None":
    """The go-install output dir (GOBIN, else GOPATH/bin, else ~/go/bin); None when unresolved."""
    for var in ("GOBIN", "GOPATH"):
        try:
            out = subprocess.run(["go", "env", var], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            out = ""
        if out:
            d = Path(out) if var == "GOBIN" else Path(out) / "bin"
            return d
    d = Path.home() / "go" / "bin"
    return d if d.exists() else None


def _reclaim_go_shadow(bin_: str, shadow: "Path") -> "Path | None":
    """Relocate a shadowing legacy `go install` binary to `<bin>.quarry-replaced-<ts>` within the go-bin dir; path, or None if untouchable."""
    gb = _go_bin_dir()
    try:
        if not gb or shadow.resolve().parent != gb.resolve():
            return None                                     # shadow isn't the go-install dir -> hands off
        bak = shadow.with_name(f"{bin_}.quarry-replaced-{int(time.time())}")
        os.replace(str(shadow), str(bak))
        return bak
    except OSError:
        return None


def _capability_ok(rc: int, accepted=None) -> bool:
    """Capability probe passes only on the accepted exit codes (default {0})."""
    return rc in (accepted or {0})


def _version_ok(rc: int, declared=None) -> bool:
    """Whether a version may be read from a probe that exited `rc` (default accepts {0})."""
    return rc in (set(declared) if declared else {0})


def health(t: Tool) -> dict:
    """Single-probe health snapshot for verify_installed + doctor: installed · identity · drift · capability · ok."""
    if not t.installed:
        return {"installed": False, "identity": "", "drift": "not-installed", "capability": None, "ok": False}
    iv = installed_identity(t)                               # probe once, reuse for drift + display
    d = _drift_status(t, True, iv)
    cap = None
    probe = t.capability or t.version_cmd
    if probe:
        cap = _capability_ok(_probe(probe)[0], set(t.cap_codes) if t.cap_codes else None)
    return {"installed": True, "identity": iv, "drift": d, "capability": cap,
            "ok": d in ("ok", "distro") and cap is not False}


def verify_installed(t: Tool) -> bool:
    """Whether an installed tool is healthy — drift 'ok'/'distro' and capability probe passed."""
    return health(t)["ok"]


def install_one(t: Tool, echo, dry_run: bool = False) -> bool:
    """One version-locked install/update path: binary/source stage+verify+atomic-activate, go/pipx install-in-place+verify. True on success."""
    cmd = pinned_install(t)
    if cmd is None:                                        # binary with no artifact for this platform
        echo(f"unsupported platform ({current_platform()}) — no {t.bin} artifact")
        return False
    if not cmd:                                           # no install command (manual)
        echo(f"{t.bin}: manual install — {t.doc}")
        return False
    if dry_run:
        echo(f"{t.bin} @ {t.pin or t.ref or t.policy or 'installed'}")
        return True

    accepted = set(t.cap_codes) if t.cap_codes else None

    if t.runtime in ("binary", "source"):
        stage_dir = Path.home() / ".local" / "bin" / ".stage"
        stage_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(stage_dir, 0o700)                            # 0700: no other user can plant in the stage dir
        stage = stage_dir / t.bin
        with _install_lock(t.lock_key or t.bin) as locked:   # lock the shared resource, not the bin
            if not locked:
                echo(f"{t.bin}: another install/update is in progress — skipped")
                return False
            # clear any pre-planted name (a dangling symlink too) and stage a fresh regular file to overwrite
            if stage.is_symlink() or stage.exists():
                stage.unlink()
            os.close(os.open(str(stage), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600))
            code, out = run_shell(cmd, False)
            staged_ok = stage.is_file() and not stage.is_symlink() and stage.stat().st_size > 0
            if code != 0 or not staged_ok:
                # surface the command's own output, not a guessed cause
                why = (f"exit {code}" if code != 0 else "exited 0 but staged no binary")
                detail = (out or "").strip()
                stage.unlink(missing_ok=True)
                echo(f"{t.bin}: install FAILED ({why})"
                     + (f" — {detail}" if detail else " — the command produced no output"))
                return False
            # one no-follow descriptor drives probe, hash and publish
            try:
                sfd = os.open(str(stage), os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as e:
                stage.unlink(missing_ok=True)
                echo(f"{t.bin}: staged artifact is not a regular file ({e}) — NOT activated")
                return False
            try:
                if not stat.S_ISREG(os.fstat(sfd).st_mode):
                    stage.unlink(missing_ok=True)
                    echo(f"{t.bin}: staged artifact is not a regular file — NOT activated")
                    return False
                os.fchmod(sfd, 0o755)                          # active binary must be executable
                # probe the fd via /proc, inherited by the child (pass_fd)
                proc_fd = f"/proc/self/fd/{sfd}"
                use_proc = os.path.exists(proc_fd)
                probe_path = proc_fd if use_proc else str(stage)
                probe_fd = sfd if use_proc else None
                # verify the staged binary before replacing the working one
                if t.capability or t.version_cmd:
                    capcmd = (t.capability or t.version_cmd).replace(t.bin, probe_path, 1)
                    if not _capability_ok(_probe(capcmd, pass_fd=probe_fd)[0], accepted):
                        stage.unlink(missing_ok=True)
                        echo(f"{t.bin}: CAPABILITY FAILED on staged binary — existing binary kept")
                        return False
                # reject a wrong-release binary (source is covered by the receipt)
                if t.pin and t.runtime == "binary" and t.version_cmd:
                    # independent version probe — a capability pass says nothing about the pin
                    _rc, _out = _probe(t.version_cmd.replace(t.bin, probe_path, 1), pass_fd=probe_fd)
                    sv = _parse_version(_out) if _version_ok(_rc, t.version_codes) else ""
                    if not version_eq(sv, t.pin):
                        stage.unlink(missing_ok=True)
                        echo(f"{t.bin}: staged version {sv!r} != pin {t.pin} — wrong release, NOT activated")
                        return False
                staged_sha = _fd_sha256(sfd)
                if not _SHA256_RE.fullmatch(staged_sha):
                    stage.unlink(missing_ok=True)
                    echo(f"{t.bin}: could not hash the staged binary for its receipt — NOT activated")
                    return False
                dest = Path.home() / ".local" / "bin" / t.bin
                backup = stage_dir / f".{t.bin}.last-good"
                receipt = _receipt_path(t.bin)
                receipt_backup = stage_dir / f".{t.bin}.last-good.receipt"
                work = stage_dir / f".{t.bin}.{os.urandom(8).hex()}.activating"
                had_prev = dest.exists()
                # hardlink the working binary + its receipt as a last-good pair, rolled back together
                if had_prev:
                    _relink(dest, backup)
                    if receipt.exists():
                        _relink(receipt, receipt_backup)
                    else:
                        receipt_backup.unlink(missing_ok=True)
                try:
                    _publish_verified(sfd, stage, work, dest)   # activate the exact verified inode
                    stage.unlink(missing_ok=True)               # drop the writable staging name; only dest holds the inode
                    _write_receipt(t.bin, t.ref or t.pin, staged_sha)
                    # the active binary must resolve on PATH, unshadowed
                    which = shutil.which(t.bin)
                    if not which:
                        raise _ActivationError(
                            f"{t.bin}: activated but does NOT resolve on PATH (~/.local/bin not on PATH?)")
                    if Path(which).resolve() != dest.resolve():
                        # reclaim a legacy go-install copy earlier in PATH (runtime migration); a shadow elsewhere fails loud
                        shadow_orig = Path(which)
                        relocated = _reclaim_go_shadow(t.bin, shadow_orig)
                        if relocated:
                            echo(f"{t.bin}: relocated legacy go binary {which} -> {relocated} (runtime migration)")
                            which = shutil.which(t.bin)
                        if not which or Path(which).resolve() != dest.resolve():
                            if relocated:                    # migration failed -> restore the legacy binary
                                try:
                                    os.replace(str(relocated), str(shadow_orig))
                                except OSError:
                                    pass
                            raise _ActivationError(
                                f"{t.bin}: SHADOWED — {which} resolves before the managed {dest}")
                    # active bytes must still equal the receipt digest (nothing rewrote them post-verify)
                    if _file_sha256(dest) != staged_sha:
                        raise _ActivationError(f"{t.bin}: active bytes changed after verification — NOT activated")
                except (OSError, _ActivationError) as e:
                    # restore the last-good binary+receipt pair; delete an unrestorable receipt, report a failed binary restore loudly
                    try:
                        _restore_last_good(had_prev, dest, backup, receipt, receipt_backup)
                    except OSError as re:
                        echo(f"{t.bin}: CRITICAL — activation failed ({e}) AND rollback failed ({re}); "
                             f"binary may be inconsistent — reinstall with `quarry install --only {t.bin}`")
                        return False
                    echo(str(e) if isinstance(e, _ActivationError)
                         else f"{t.bin}: activation failed ({e}) — rolled back to last-good")
                    return False
                if had_prev:
                    backup.unlink(missing_ok=True)           # activation confirmed; drop the rollback pair
                    receipt_backup.unlink(missing_ok=True)
                echo(f"{t.bin}: ok ({t.pin or t.ref})")
            finally:
                os.close(sfd)
        return True

    # go / pipx — install in place under the shared-resource lock, then verify identity + capability
    with _install_lock(t.lock_key or t.bin) as locked:
        if not locked:
            echo(f"{t.bin}: another install/update is in progress — skipped")
            return False
        code, _ = run_shell(cmd, False)
        if code != 0 or not t.installed:
            echo(f"{t.bin}: install FAILED")
            return False
        if (t.pin or t.ref) and drift(t) != "ok":         # drift or an unknown identity is a failure
            echo(f"{t.bin}: identity NOT VERIFIED ({drift(t)}) "
                 f"installed={installed_identity(t)!r} != pin {t.pin or t.ref!r}")
            return False
        probe = t.capability or t.version_cmd
        if probe and not _capability_ok(_probe(probe)[0], accepted):
            echo(f"{t.bin}: CAPABILITY FAILED")
            return False
        echo(f"{t.bin}: ok ({installed_identity(t) or t.pin})")
        return True


def run_shell(cmd: str, dry_run: bool) -> tuple[int, str]:
    """Run an install/update shell command. Returns (exit_code, short_output)."""
    if dry_run:
        return 0, "(dry-run)"
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
        tail = "\n".join((p.stdout + p.stderr).strip().splitlines()[-4:])
        return p.returncode, tail
    except subprocess.SubprocessError as e:
        return 1, str(e)
