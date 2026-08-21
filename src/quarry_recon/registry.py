"""Tool registry — load tool definitions (data/tools.yaml), audit installs, drive install/update/doctor."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
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
_RUNTIME_RECEIPT_SCHEMA = "quarry.runtime-receipt.v1"
_RUNTIME_RECEIPT_NAME = ".quarry-runtime-receipt.json"
_RUNTIME_ROOT_NAME = "toolchains"
_max_closure_files = 200_000
_max_closure_bytes = 2 * 1024 * 1024 * 1024
_install_context = threading.local()


class LockError(ValueError):
    """A tools.yaml lock field is malformed — loading fails rather than trusting it."""


class _ActivationError(Exception):
    """A staged binary was swapped in but failed a post-swap identity/receipt check — triggers rollback."""


class _RollbackError(_ActivationError):
    """Activation faulted and rollback could not be proven; recovery bytes were deliberately retained."""

    def __init__(self, message: str, recovery: Path):
        super().__init__(message)
        self.recovery = recovery


@contextlib.contextmanager
def _install_lock(bin_: str):
    """Serialize concurrent installs/updates of one binary (non-blocking flock); yields False if held."""
    lock_dir = Path.home() / ".local" / "bin" / ".stage"
    _private_directory(lock_dir)
    lock_name = f".{_safe_lock_key(bin_)}.installing.lock"
    directory_fd = os.open(lock_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(lock_name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600,
                     dir_fd=directory_fd)
    except BaseException:
        os.close(directory_fd)
        raise
    observed = os.fstat(fd)
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
            or observed.st_nlink != 1):
        os.close(fd)
        os.close(directory_fd)
        raise _ActivationError("install lock is not an owner-controlled regular file")
    os.fchmod(fd, 0o600)
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
        os.close(directory_fd)


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
    for key in ("env_allow", "credential_env", "runtime_bins", "runtime_argv_prefix"):
        values = t.get(key)
        if values is not None and (
            not isinstance(values, list)
            or len(values) != len(set(values))
            or not all(isinstance(value, str) and value for value in values)
        ):
            _bad(f"{key} must be a unique list of non-empty strings")
    if set(t.get("env_allow") or ()) & set(t.get("credential_env") or ()):
        _bad("env_allow and credential_env must be disjoint")
    for key in ("runtime_exec", "runtime_entry"):
        value = t.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            _bad(f"{key} must be a non-empty string")
    runtime_env = t.get("runtime_entry_env")
    if runtime_env is not None and (
        not isinstance(runtime_env, dict)
        or not all(isinstance(k, str) and k and isinstance(v, str) and v
                   for k, v in runtime_env.items())
    ):
        _bad("runtime_entry_env must map non-empty environment names to non-empty relative paths")
    payloads = t.get("runtime_payloads")
    if payloads is not None:
        if not isinstance(payloads, list) or not payloads:
            _bad("runtime_payloads must be a non-empty list")
        seen_payloads = set()
        for payload in payloads:
            if not isinstance(payload, dict) or set(payload) != {"path", "sha256"}:
                _bad("runtime_payloads entries need exactly path + sha256")
            path, digest = payload["path"], payload["sha256"]
            if (not isinstance(path, str) or not path or path.startswith("/")
                    or ".." in Path(path).parts or path in seen_payloads):
                _bad(f"runtime payload path is unsafe or duplicate: {path!r}")
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                _bad(f"runtime payload {path!r} has an invalid sha256")
            seen_payloads.add(path)
    if (t.get("runtime_entry") is None) != (t.get("runtime_exec") is None):
        _bad("runtime_entry and runtime_exec must be declared together")
    if t.get("runtime_entry_env") and not t.get("runtime_entry"):
        _bad("runtime_entry_env requires runtime_entry")

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
    # Runtime admission. Environment names are allowlists, never values. A wrapper can be bypassed by
    # naming its exact payload entry and interpreter; runtime_payloads pins mutable files outside the shim.
    env_allow: list[str] | None = None
    credential_env: list[str] | None = None
    runtime_bins: list[str] | None = None
    runtime_exec: str | None = None
    runtime_entry: str | None = None
    runtime_argv_prefix: list[str] | None = None
    runtime_entry_env: dict[str, str] | None = None
    runtime_payloads: list[dict] | None = None

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


def _probe(cmd: str, timeout: int = 15, pass_fd: int | None = None,
           env: "dict[str, str] | None" = None) -> tuple[int, str]:
    """Run a shell probe -> (rc, ANSI-stripped output); _PROBE_NOT_RUN on timeout/launch failure. `pass_fd` is inherited by the child via pass_fds."""
    kwargs = {"pass_fds": (pass_fd,)} if pass_fd is not None else {}
    if env is not None:
        kwargs["env"] = dict(env)
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
            env_allow=t.get("env_allow") or [], credential_env=t.get("credential_env") or [],
            runtime_bins=t.get("runtime_bins") or [], runtime_exec=t.get("runtime_exec"),
            runtime_entry=t.get("runtime_entry"), runtime_argv_prefix=t.get("runtime_argv_prefix") or [],
            runtime_entry_env=t.get("runtime_entry_env") or {},
            runtime_payloads=t.get("runtime_payloads") or [],
        ))
    return tools


def tool_for_bin(bin_: str) -> "Tool | None":
    """Return the one declared tool for ``bin_``; duplicate registry identities fail closed."""
    matches = [tool for tool in load_tools() if tool.bin == bin_]
    if len(matches) > 1:
        raise LockError(f"duplicate tool identity {bin_!r}")
    return matches[0] if matches else None


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
        environment = getattr(_install_context, "environment", None)
        p = subprocess.run(
            ["go", "version", "-m", path], capture_output=True, text=True, timeout=15,
            env=(dict(environment) if environment is not None else None),
        )
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


def _pipx_meta(pkg: str, *, env: "dict[str, str] | None" = None) -> tuple[str, list]:
    """(version, app_paths) for the installed pipx package from `pipx list --json`; ('', []) if unreadable."""
    try:
        import json
        p = subprocess.run(["pipx", "list", "--json"], capture_output=True, text=True, timeout=25,
                           env=(dict(env) if env is not None else None))
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
    if not isinstance(rec, dict):
        return {}
    if rec.get("schema_version") == _RUNTIME_RECEIPT_SCHEMA:
        tool = rec.get("tools", {}).get(bin_) if isinstance(rec.get("tools"), dict) else None
        rows = rec.get("files") if isinstance(rec.get("files"), list) else []
        if isinstance(tool, dict):
            row = next((item for item in rows if isinstance(item, dict)
                        and item.get("path") == tool.get("executable")), None)
            if row is not None:
                return {"ident": tool.get("identity"), "sha256": row.get("sha256"),
                        "schema_version": _RUNTIME_RECEIPT_SCHEMA}
        return {}
    return rec


def _write_receipt(bin_: str, ident: str, sha: str) -> None:
    """Write the receipt {ident, sha256} atomically (temp + rename to a new inode)."""
    import json
    rp = _receipt_path(bin_)
    tmp = rp.with_name(f".{rp.name}.{os.urandom(6).hex()}.tmp")
    tmp.write_text(json.dumps({"ident": ident, "sha256": sha}))
    os.replace(str(tmp), str(rp))


def _safe_lock_key(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value):
        raise _ActivationError("install lock identity is unsafe")
    return value


def _managed_root(t: "Tool") -> Path:
    key = _safe_lock_key(t.lock_key or t.bin)
    return Path.home() / ".local" / "share" / "quarry" / _RUNTIME_ROOT_NAME / key


def _private_directory(path: Path) -> None:
    """Create one owner-private directory and refuse an existing alias/non-directory."""
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        observed = path.lstat()
    except OSError as exc:
        raise _ActivationError(f"private install directory is unavailable: {exc}") from exc
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid()
            or path.is_symlink()):
        raise _ActivationError(f"private install directory is unsafe: {path}")
    os.chmod(path, 0o700)


def _active_version(root: Path) -> "Path | None":
    current = root / "current"
    try:
        observed = current.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(observed.st_mode):
        raise _ActivationError("managed current pointer is not a symlink")
    target = os.readlink(current)
    parts = Path(target).parts
    if (len(parts) != 2 or parts[0] != "versions"
            or not re.fullmatch(r"[a-f0-9]{32}", parts[1])):
        raise _ActivationError("managed current pointer target is unsafe")
    version = root.joinpath(*parts)
    resolved_root, resolved_version = root.resolve(), version.resolve(strict=True)
    if resolved_version.parent != (resolved_root / "versions"):
        raise _ActivationError("managed current pointer escapes its versions directory")
    observed_version = resolved_version.stat()
    if (not stat.S_ISDIR(observed_version.st_mode)
            or observed_version.st_uid != os.geteuid()
            or stat.S_IMODE(observed_version.st_mode) != 0o500):
        raise _ActivationError("managed current version is unsafe")
    return resolved_version


def _tree_rows(root: Path) -> list[dict]:
    """Describe every payload object below a candidate, excluding the self-describing receipt.

    Directories are identity-bearing objects too. A pipx venv's external interpreter symlink is accepted
    only as an explicit, revalidated external regular-file dependency; it is never mistaken for contained
    payload.
    """
    rows, total = [], 0
    root = root.resolve(strict=True)
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        if relative == _RUNTIME_RECEIPT_NAME:
            continue
        observed = path.lstat()
        if observed.st_uid != os.geteuid():
            raise _ActivationError(f"runtime closure object is not owner-controlled: {relative}")
        mode = stat.S_IMODE(observed.st_mode)
        if len(rows) >= _max_closure_files:
            raise _ActivationError("runtime closure exceeds its object-count bound")
        if stat.S_ISDIR(observed.st_mode):
            if mode & 0o022:
                raise _ActivationError(f"runtime closure directory is group/world writable: {relative}")
            rows.append({"bytes": 0, "kind": "directory", "mode": mode,
                         "path": relative, "sha256": hashlib.sha256(b"").hexdigest()})
            continue
        if stat.S_ISREG(observed.st_mode):
            if mode & 0o022:
                raise _ActivationError(f"runtime closure file is group/world writable: {relative}")
            size = observed.st_size
            total += size
            if total > _max_closure_bytes:
                raise _ActivationError("runtime closure exceeds its byte bound")
            digest = _file_sha256(path)
            if not _SHA256_RE.fullmatch(digest):
                raise _ActivationError(f"runtime closure file could not be hashed: {relative}")
            rows.append({"bytes": size, "kind": "file", "mode": mode,
                         "path": relative, "sha256": digest})
            continue
        if stat.S_ISLNK(observed.st_mode):
            target = os.readlink(path)
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                external = None
            except ValueError:
                try:
                    target_stat = resolved.stat()
                except OSError as exc:
                    raise _ActivationError(
                        f"runtime closure external link is unavailable: {relative}"
                    ) from exc
                if not stat.S_ISREG(target_stat.st_mode):
                    raise _ActivationError(
                        f"runtime closure external link is not a regular file: {relative}"
                    )
                digest = _file_sha256(resolved)
                if not _SHA256_RE.fullmatch(digest):
                    raise _ActivationError(
                        f"runtime closure external link could not be hashed: {relative}"
                    )
                external = {
                    "bytes": target_stat.st_size,
                    "mode": stat.S_IMODE(target_stat.st_mode),
                    "path": str(resolved),
                    "sha256": digest,
                }
            except OSError as exc:
                raise _ActivationError(f"runtime closure link dangles: {relative}") from exc
            encoded = target.encode("utf-8", "strict")
            total += len(encoded)
            if external is not None:
                total += external["bytes"]
            if total > _max_closure_bytes:
                raise _ActivationError("runtime closure exceeds its byte bound")
            row = {"bytes": len(encoded), "kind": "symlink", "mode": mode,
                   "path": relative, "sha256": hashlib.sha256(encoded).hexdigest(),
                   "target": target}
            if external is not None:
                row["external"] = external
            rows.append(row)
            continue
        raise _ActivationError(f"runtime closure contains an unsupported object: {relative}")
    return rows


def _strict_json(path: Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise _ActivationError(f"runtime receipt is unreadable: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise _ActivationError("runtime receipt is not an object")
    return value


def _closure_identity(rows: list[dict]) -> str:
    body = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8", "strict",
    )
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _validate_runtime_receipt(root: Path, receipt: dict, *, tool: "Tool | None" = None) -> dict:
    if set(receipt) != {"schema_version", "lock_key", "generation", "tools", "files"}:
        raise _ActivationError("runtime receipt has an unknown shape")
    if receipt.get("schema_version") != _RUNTIME_RECEIPT_SCHEMA:
        raise _ActivationError("runtime receipt schema is unsupported")
    _safe_lock_key(receipt.get("lock_key"))
    if not isinstance(receipt.get("generation"), str) or not re.fullmatch(
            r"[a-f0-9]{32}", receipt["generation"]):
        raise _ActivationError("runtime receipt generation is invalid")
    if receipt["generation"] != root.resolve(strict=True).name:
        raise _ActivationError("runtime receipt generation does not name its version root")
    tools = receipt.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise _ActivationError("runtime receipt has no tool identities")
    for name, record in tools.items():
        if (not isinstance(name, str) or not name
                or not isinstance(record, dict)
                or set(record) != {"executable", "identity", "runtime", "content_identity"}
                or not all(isinstance(record.get(key), str) and record[key]
                           for key in ("executable", "identity", "runtime", "content_identity"))
                or not record["content_identity"].startswith("sha256:")
                or not _SHA256_RE.fullmatch(record["content_identity"][7:])):
            raise _ActivationError("runtime receipt tool identity is invalid")
        rel = Path(record["executable"])
        if rel.is_absolute() or ".." in rel.parts:
            raise _ActivationError("runtime receipt executable path is unsafe")
    rows = receipt.get("files")
    if not isinstance(rows, list) or len(rows) > _max_closure_files:
        raise _ActivationError("runtime receipt file inventory is invalid")
    if rows != _tree_rows(root):
        raise _ActivationError("runtime closure bytes no longer match their receipt")
    paths = {row.get("path") for row in rows if isinstance(row, dict)}
    if len(paths) != len(rows):
        raise _ActivationError("runtime receipt contains duplicate file identities")
    if any(record["executable"] not in paths for record in tools.values()):
        raise _ActivationError("runtime receipt executable is absent from its closure")
    content_identity = _closure_identity(rows)
    if any(record["content_identity"] != content_identity for record in tools.values()):
        raise _ActivationError("runtime receipt content identity does not match its closure")
    if tool is not None:
        expected_identity = tool.pin or tool.ref
        record = tools.get(tool.bin)
        if receipt["lock_key"] != _safe_lock_key(tool.lock_key or tool.bin):
            raise _ActivationError("runtime receipt belongs to another install lock")
        if not isinstance(record, dict):
            raise _ActivationError(f"runtime receipt does not name requested tool {tool.bin}")
        if record["runtime"] != tool.runtime:
            raise _ActivationError("runtime receipt changes the requested tool runtime")
        if expected_identity is None or record["identity"] != str(expected_identity):
            raise _ActivationError("runtime receipt changes the requested declared identity")
    return receipt


def managed_runtime_receipt(t: "Tool") -> "tuple[Path, dict] | None":
    """Return and revalidate the active version root plus its complete receipt."""
    root = _managed_root(t)
    try:
        active = _active_version(root)
    except FileNotFoundError:
        return None
    if active is None:
        return None
    receipt_path = active / _RUNTIME_RECEIPT_NAME
    observed = receipt_path.lstat()
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o600 or observed.st_nlink != 1):
        raise _ActivationError("runtime receipt file identity is unsafe")
    return active, _validate_runtime_receipt(active, _strict_json(receipt_path), tool=t)


def _canonical_receipt_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8", "strict")


def _write_runtime_receipt(candidate: Path, value: dict) -> None:
    path = candidate / _RUNTIME_RECEIPT_NAME
    data = _canonical_receipt_bytes(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("runtime receipt write made no progress")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _install_environment(environment: dict[str, str], tool: "Tool | None" = None):
    previous = getattr(_install_context, "environment", None)
    previous_tool = getattr(_install_context, "tool", None)
    _install_context.environment = dict(environment)
    _install_context.tool = tool
    try:
        yield
    finally:
        if previous is None:
            with contextlib.suppress(AttributeError):
                del _install_context.environment
        else:
            _install_context.environment = previous
        if previous_tool is None:
            with contextlib.suppress(AttributeError):
                del _install_context.tool
        else:
            _install_context.tool = previous_tool


def _installer_environment(candidate: Path, t: "Tool") -> dict[str, str]:
    ambient = os.environ
    environment = {
        key: ambient[key]
        for key in ("LANG", "LC_ALL", "LC_CTYPE", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
        if key in ambient
    }
    home = candidate / "home"
    bindir = home / ".local" / "bin"
    cache = candidate / "cache"
    for directory in (home, bindir, bindir / ".stage", cache):
        _private_directory(directory)
    environment.update({
        "HOME": str(home),
        # Never give a caller-controlled PATH precedence during provenance construction. The final owner
        # bin directory remains last only for a separately registry-managed dependency such as bun.
        "PATH": os.pathsep.join((
            "/usr/local/go/bin", "/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
            "/usr/bin", "/sbin", "/bin", str(Path.home() / ".local" / "bin"),
        )),
        "XDG_CACHE_HOME": str(cache),
        "GOBIN": str(bindir),
        "GOMODCACHE": str(cache / "gomod"),
        "GOCACHE": str(cache / "gobuild"),
        "PIPX_HOME": str(candidate / "pipx"),
        "PIPX_BIN_DIR": str(bindir),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    })
    return environment


def _probe_candidate(t: "Tool", executable: Path, environment: dict[str, str]) -> bool:
    accepted = set(t.cap_codes) if t.cap_codes else None
    probe = t.capability or t.version_cmd
    with tempfile.TemporaryDirectory(prefix="quarry-tool-probe-") as temporary:
        probe_environment = dict(environment)
        probe_root = Path(temporary)
        for variable, relative in (
            ("HOME", "home"),
            ("TMPDIR", "tmp"),
            ("XDG_CACHE_HOME", "xdg-cache"),
            ("XDG_CONFIG_HOME", "xdg-config"),
            ("XDG_DATA_HOME", "xdg-data"),
            ("PIPX_LOG_DIR", "pipx-log"),
        ):
            directory = probe_root / relative
            directory.mkdir(mode=0o700)
            probe_environment[variable] = str(directory)
        if probe:
            command = probe.replace(t.bin, shlex_quote(str(executable)), 1)
            if not _capability_ok(_probe(command, env=probe_environment)[0], accepted):
                return False
        if t.pin and t.runtime == "binary" and t.version_cmd:
            command = t.version_cmd.replace(t.bin, shlex_quote(str(executable)), 1)
            rc, output = _probe(command, env=probe_environment)
            version = _parse_version(output) if _version_ok(rc, t.version_codes) else ""
            if not version_eq(version, t.pin):
                return False
        if t.runtime == "pipx":
            version, app_paths = _pipx_meta(_pipx_pkg(t), env=probe_environment)
            admitted = {Path(path).resolve() for path in app_paths}
            if not version_eq(version, t.pin) or executable.resolve() not in admitted:
                return False
    if t.runtime == "go":
        module, version = _go_mod_and_version(str(executable))
        if module != _expected_go_module(t) or not version_eq(version, t.pin):
            return False
    return True


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def _install_output_detail(output: str) -> str:
    from . import secrets
    cleaned = (secrets.redact(output or "") or "").strip()
    return cleaned[:500] if cleaned else "produced no output"


def installed_identity(t: "Tool") -> str:
    """Installed version by runtime identity (go: `go version -m`; pipx: `pipx list`; binary/source: the receipt `ident` with sha rechecked; distro: 'distro'); "" when unprovable."""
    if not t.installed:
        return ""
    if t.policy == "distro":
        return "distro"
    try:
        managed = managed_runtime_receipt(t)
    except (OSError, _ActivationError):
        return ""
    if managed is not None:
        root, receipt = managed
        record = receipt["tools"].get(t.bin)
        resolved = Path(shutil.which(t.bin) or "").resolve()
        expected = root / record["executable"] if isinstance(record, dict) else None
        if record is None or expected is None or resolved != expected.resolve():
            return ""
        return record["identity"]
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


def _reclaim_go_shadow(bin_: str, shadow: "Path", *, settlement: "dict | None" = None) -> "Path | None":
    """Relocate a legacy Go shadow and reconcile a rename that reports failure after landing."""
    gb = _go_bin_dir()
    bak = None
    try:
        if not gb or shadow.resolve().parent != gb.resolve():
            return None                                     # shadow isn't the go-install dir -> hands off
        bak = shadow.with_name(f"{bin_}.quarry-replaced-{int(time.time())}")
        os.replace(str(shadow), str(bak))
        _fsync_directory(gb)
        return bak
    except BaseException as primary:
        if bak is not None and not os.path.lexists(shadow) and os.path.lexists(bak):
            # The authoritative names prove replace landed even though the syscall reported an error.
            if settlement is not None:
                settlement["pair"] = (shadow, bak)
            _fsync_directory(gb)
            if isinstance(primary, Exception):
                return bak
            raise primary.with_traceback(primary.__traceback__)
        if not isinstance(primary, Exception):
            raise primary.with_traceback(primary.__traceback__)
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


def _copy_active_version(active: "Path | None", candidate: Path) -> dict:
    if active is None:
        return {}
    receipt = _validate_runtime_receipt(active, _strict_json(active / _RUNTIME_RECEIPT_NAME))
    for child in active.iterdir():
        if child.name == _RUNTIME_RECEIPT_NAME:
            continue
        destination = candidate / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, destination, symlinks=True)
        elif child.is_symlink():
            os.symlink(os.readlink(child), destination)
        else:
            shutil.copy2(child, destination, follow_symlinks=False)
    return dict(receipt["tools"])


def _set_candidate_writable(candidate: Path) -> None:
    """Give the private builder write access to a copied last-known-good candidate."""
    paths = (candidate, *sorted(candidate.rglob("*"), key=lambda item: len(item.parts)))
    for path in paths:
        observed = path.lstat()
        if observed.st_uid != os.geteuid():
            raise _ActivationError(f"candidate contains an object owned by another uid: {path}")
        if stat.S_ISDIR(observed.st_mode):
            os.chmod(path, stat.S_IMODE(observed.st_mode) | 0o700)
        elif stat.S_ISREG(observed.st_mode):
            os.chmod(path, stat.S_IMODE(observed.st_mode) | 0o600)
        elif not stat.S_ISLNK(observed.st_mode):
            raise _ActivationError(f"candidate contains an unsupported object: {path}")


def _freeze_candidate_payload(candidate: Path) -> None:
    """Remove write bits from candidate descendants before their closure is receipted."""
    for path in sorted(candidate.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.name == _RUNTIME_RECEIPT_NAME:
            continue
        observed = path.lstat()
        if observed.st_uid != os.geteuid():
            raise _ActivationError(f"candidate contains an object owned by another uid: {path}")
        if stat.S_ISDIR(observed.st_mode):
            os.chmod(path, (stat.S_IMODE(observed.st_mode) | 0o500) & ~0o222)
        elif stat.S_ISREG(observed.st_mode):
            os.chmod(path, (stat.S_IMODE(observed.st_mode) | 0o400) & ~0o222)
        elif not stat.S_ISLNK(observed.st_mode):
            raise _ActivationError(f"candidate contains an unsupported object: {path}")


def _durably_settle_candidate_payload(candidate: Path) -> None:
    """Flush every payload inode and directory after bytes and modes reach their final form."""
    directories = [candidate]
    for path in sorted(candidate.rglob("*"), key=lambda item: item.relative_to(candidate).parts):
        if path.name == _RUNTIME_RECEIPT_NAME:
            continue
        observed = path.lstat()
        if stat.S_ISDIR(observed.st_mode):
            directories.append(path)
        elif stat.S_ISREG(observed.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        elif not stat.S_ISLNK(observed.st_mode):
            raise _ActivationError(f"candidate contains an unsupported object: {path}")
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)


def _seal_candidate_root(candidate: Path) -> None:
    """Remove mutation authority from the version root after its receipt is durably written."""
    observed = candidate.lstat()
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid():
        raise _ActivationError("candidate version root is not owner-controlled")
    os.chmod(candidate, 0o500)
    if stat.S_IMODE(candidate.lstat().st_mode) != 0o500:
        raise _ActivationError("candidate version root could not be sealed")


def _set_candidate_removable(candidate: Path) -> None:
    """Restore directory traversal/removal authority without mutating retained file inode modes."""
    paths = (candidate, *sorted(candidate.rglob("*"), key=lambda item: len(item.parts)))
    for path in paths:
        observed = path.lstat()
        if observed.st_uid != os.geteuid():
            raise _ActivationError(f"candidate contains an object owned by another uid: {path}")
        if stat.S_ISDIR(observed.st_mode):
            os.chmod(path, stat.S_IMODE(observed.st_mode) | 0o700)
        elif not (stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode)):
            raise _ActivationError(f"candidate contains an unsupported object: {path}")


def _discard_candidate(candidate: Path) -> None:
    """Remove a rejected candidate and return only after proving its version name absent."""
    errors = []
    try:
        _set_candidate_removable(candidate)
    except BaseException as exc:
        errors.append(exc)
    try:
        shutil.rmtree(candidate)
    except FileNotFoundError:
        pass
    except BaseException as exc:
        errors.append(exc)
    cancellation = next((exc for exc in errors if not isinstance(exc, Exception)), None)
    if os.path.lexists(candidate):
        residue = _RollbackError(
            "rejected install candidate could not be settled",
            candidate,
        )
        if cancellation is not None:
            cancellation.add_note(f"install candidate residue also remains: {candidate}")
            raise cancellation.with_traceback(cancellation.__traceback__)
        raise residue
    try:
        _fsync_directory(candidate.parent)
    except FileNotFoundError:
        pass
    if cancellation is not None:
        raise cancellation.with_traceback(cancellation.__traceback__)


def _candidate_executable(candidate: Path, t: Tool) -> Path:
    bindir = candidate / "home" / ".local" / "bin"
    staged, final = bindir / ".stage" / t.bin, bindir / t.bin
    if staged.is_symlink() or staged.exists():
        if final.is_symlink() or final.exists():
            final.unlink()
        os.replace(staged, final)
    try:
        resolved = final.resolve(strict=True)
        resolved.relative_to(candidate.resolve(strict=True))
        observed = resolved.stat()
    except (OSError, ValueError) as exc:
        raise _ActivationError(f"{t.bin}: install produced no contained executable") from exc
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
            or observed.st_size == 0):
        raise _ActivationError(f"{t.bin}: candidate executable identity is unsafe")
    os.chmod(resolved, stat.S_IMODE(observed.st_mode) | stat.S_IXUSR)
    return final


def _validate_declared_payloads(candidate: Path, t: Tool) -> None:
    home = candidate / "home"
    for declaration in t.runtime_payloads or []:
        path = home / declaration["path"]
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(candidate.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise _ActivationError(f"{t.bin}: declared runtime payload is absent or escapes") from exc
        if _file_sha256(resolved) != declaration["sha256"]:
            raise _ActivationError(f"{t.bin}: declared runtime payload digest does not match")


def _validate_retained_tools(candidate: Path, records: dict[str, dict], current: Tool,
                             environment: dict[str, str]) -> None:
    """Re-prove every companion copied under a shared install lock before publication."""
    declarations = {tool.bin: tool for tool in load_tools()}
    lock_key = _safe_lock_key(current.lock_key or current.bin)
    for name, record in sorted(records.items()):
        if name == current.bin:
            continue
        declared = declarations.get(name)
        if (declared is None
                or _safe_lock_key(declared.lock_key or declared.bin) != lock_key
                or record.get("runtime") != declared.runtime
                or record.get("identity") != str(declared.pin or declared.ref or "")):
            raise _ActivationError(f"retained shared tool {name!r} has no exact registry identity")
        executable = _candidate_executable(candidate, declared)
        if executable.relative_to(candidate).as_posix() != record.get("executable"):
            raise _ActivationError(f"retained shared tool {name!r} changed executable identity")
        _validate_declared_payloads(candidate, declared)
        with _install_environment(environment, declared):
            if not _probe_candidate(declared, executable.resolve(), environment):
                raise _ActivationError(f"retained shared tool {name!r} failed revalidation")


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _link_snapshot(path: Path, backup_dir: Path) -> tuple[str, str | None]:
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return "absent", None
    if stat.S_ISLNK(observed.st_mode):
        return "symlink", os.readlink(path)
    if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid():
        raise _ActivationError(f"activation destination is unsafe: {path}")
    backup = backup_dir / f"{path.name}.{os.urandom(8).hex()}.backup"
    os.link(path, backup, follow_symlinks=False)
    return "file", str(backup)


def _restore_link(path: Path, snapshot: tuple[str, str | None]) -> None:
    kind, value = snapshot
    tmp = path.with_name(f".{path.name}.{os.urandom(8).hex()}.rollback")
    if kind == "absent":
        path.unlink(missing_ok=True)
        _fsync_directory(path.parent)
        return
    if kind == "symlink":
        os.symlink(value, tmp)
    else:
        os.link(value, tmp, follow_symlinks=False)
    os.replace(tmp, path)
    _fsync_directory(path.parent)


def _snapshot_matches(path: Path, snapshot: tuple[str, str | None]) -> bool:
    """Whether an alias already reached its requested snapshot despite a syscall raising after effect."""
    kind, value = snapshot
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return kind == "absent"
    if kind == "symlink":
        return stat.S_ISLNK(observed.st_mode) and os.readlink(path) == value
    if kind == "file" and stat.S_ISREG(observed.st_mode):
        try:
            backup = Path(value).lstat()
        except OSError:
            return False
        return (observed.st_dev, observed.st_ino) == (backup.st_dev, backup.st_ino)
    return False


def _pointer_target(root: Path) -> "str | None":
    current = root / "current"
    try:
        observed = current.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(observed.st_mode):
        raise _ActivationError("managed current pointer became a non-symlink")
    return os.readlink(current)


def _candidate_is_current(root: Path, candidate: "Path | None") -> bool:
    """Reconcile the authoritative pointer before any exception path removes candidate bytes."""
    if candidate is None:
        return False
    try:
        target = _pointer_target(root)
        return target is not None and (root / target).resolve(strict=True) == candidate.resolve(strict=True)
    except (OSError, ValueError, _ActivationError):
        return False


def _replace_symlink(path: Path, target: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.urandom(8).hex()}.link")
    os.symlink(target, tmp)
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _activate_candidate(root: Path, candidate: Path, receipt: dict,
                        t: Tool) -> "tuple[Path | None, Path]":
    """Publish stable aliases first, then make the complete candidate visible with one pointer rename."""
    bindir = Path.home() / ".local" / "bin"
    _private_directory(bindir / ".stage")
    old_active = _active_version(root)
    old_target = None if old_active is None else os.path.relpath(old_active, root)
    backups = root / f".rollback-{os.urandom(8).hex()}"
    _private_directory(backups)
    _fsync_directory(root)
    snapshots: dict[Path, tuple[str, str | None]] = {}
    reclaimed_shadow: tuple[Path, Path] | None = None
    shadow_settlement: dict = {}
    pointer_tmp: Path | None = None
    try:
        for bin_name, record in sorted(receipt["tools"].items()):
            for path, destination in (
                (bindir / bin_name, root / "current" / record["executable"]),
                (_receipt_path(bin_name), root / "current" / _RUNTIME_RECEIPT_NAME),
            ):
                snapshots[path] = _link_snapshot(path, backups)
                target = os.path.relpath(destination, path.parent)
                _replace_symlink(path, target)
        _fsync_directory(backups)
        _fsync_directory(bindir)
        pointer_tmp = root / f".current-{os.urandom(8).hex()}"
        os.symlink(os.path.relpath(candidate, root), pointer_tmp)
        os.replace(pointer_tmp, root / "current")
        _fsync_directory(root)
        managed = managed_runtime_receipt(t)
        if managed is None or managed[0] != candidate.resolve():
            raise _ActivationError(f"{t.bin}: activated receipt does not name the candidate")
        expected = candidate / receipt["tools"][t.bin]["executable"]
        if (bindir / t.bin).resolve(strict=True) != expected.resolve(strict=True):
            raise _ActivationError(f"{t.bin}: activated alias does not resolve to the verified executable")
        selected = shutil.which(t.bin)
        if selected and Path(selected).resolve() != expected.resolve(strict=True):
            shadow = Path(selected)
            backup = _reclaim_go_shadow(t.bin, shadow, settlement=shadow_settlement)
            if backup is None:
                raise _ActivationError(f"{t.bin}: PATH still selects an unmanaged executable")
            reclaimed_shadow = (shadow, backup)
            selected = shutil.which(t.bin)
        if not selected or Path(selected).resolve() != expected.resolve(strict=True):
            raise _ActivationError(f"{t.bin}: verified executable is not the admitted PATH identity")
        confirmed = managed_runtime_receipt(t)
        if confirmed is None or confirmed[0] != candidate.resolve():
            raise _ActivationError(f"{t.bin}: activated closure changed during final reconciliation")
        result = reclaimed_shadow[1] if reclaimed_shadow is not None else None
    except BaseException as primary:
        rollback_errors = []
        if reclaimed_shadow is None:
            reclaimed_shadow = shadow_settlement.get("pair")
        if pointer_tmp is not None and os.path.lexists(pointer_tmp):
            try:
                pointer_tmp.unlink()
            except BaseException as exc:
                rollback_errors.append(exc)
        try:
            observed_target = _pointer_target(root)
        except BaseException as exc:
            observed_target = "<unverifiable>"
            rollback_errors.append(exc)
        if observed_target != old_target:
            try:
                if old_target is None:
                    (root / "current").unlink(missing_ok=True)
                else:
                    _replace_symlink(root / "current", old_target)
                _fsync_directory(root)
            except BaseException as exc:
                # A syscall may report failure after landing. Reconcile the authoritative name before
                # declaring rollback uncertain.
                try:
                    settled = _pointer_target(root) == old_target
                except BaseException:
                    settled = False
                if not settled:
                    rollback_errors.append(exc)
        for path, snapshot in reversed(tuple(snapshots.items())):
            try:
                _restore_link(path, snapshot)
            except BaseException as exc:
                try:
                    settled = _snapshot_matches(path, snapshot)
                except BaseException:
                    settled = False
                if settled:
                    if not isinstance(exc, Exception):
                        rollback_errors.append(exc)
                    continue
                # A name whose restoration is unproven must not keep pointing at the rejected candidate.
                # Its recoverable prior inode/link is retained under ``backups`` for manual settlement.
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)
                rollback_errors.append(exc)
        try:
            _fsync_directory(bindir)
        except BaseException as exc:
            rollback_errors.append(exc)
        if reclaimed_shadow is not None:
            shadow, backup = reclaimed_shadow
            try:
                os.replace(backup, shadow)
                _fsync_directory(shadow.parent)
            except BaseException as exc:
                if not os.path.lexists(backup) and os.path.lexists(shadow):
                    try:
                        _fsync_directory(shadow.parent)
                    except BaseException as durability_fault:
                        rollback_errors.append(durability_fault)
                    if not isinstance(exc, Exception):
                        rollback_errors.append(exc)
                else:
                    rollback_errors.append(exc)
        if rollback_errors:
            residue = _RollbackError(
                "activation failed and last-known-good rollback did not settle",
                backups,
            )
            cancellation = (primary if not isinstance(primary, Exception) else next(
                (fault for fault in rollback_errors if not isinstance(fault, Exception)), None,
            ))
            if cancellation is not None:
                cancellation.add_note(f"installer rollback also failed: {residue}")
                raise cancellation.with_traceback(cancellation.__traceback__)
            raise residue from primary
        try:
            _discard_candidate(backups)
        except BaseException as cleanup_fault:
            if not isinstance(primary, Exception):
                primary.add_note(
                    f"installer rollback cleanup also failed: {type(cleanup_fault).__name__}: "
                    f"{cleanup_fault}"
                )
                raise primary.with_traceback(primary.__traceback__)
            if not isinstance(cleanup_fault, Exception):
                raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
            raise cleanup_fault from primary
        raise primary.with_traceback(primary.__traceback__)
    # ``current`` now names and revalidates the candidate. Backup cleanup is deliberately caller-owned so
    # install_one can cross an explicit committed boundary before any later fault or cancellation.
    return result, backups


def install_one(t: Tool, echo, dry_run: bool = False) -> bool:
    """Build, verify and receipt one complete version before an atomic current-pointer publication."""
    cmd = pinned_install(t)
    if cmd is None:
        echo(f"unsupported platform ({current_platform()}) — no {t.bin} artifact")
        return False
    if not cmd:
        echo(f"{t.bin}: manual install — {t.doc}")
        return False
    if dry_run:
        echo(f"{t.bin} @ {t.pin or t.ref or t.policy or 'installed'}")
        return True
    if t.policy == "distro":
        if verify_installed(t):
            echo(f"{t.bin}: ok (distro-managed; Quarry performed no in-place mutation)")
            return True
        echo(f"{t.bin}: distro-managed tool is absent or unhealthy — NOT modified")
        return False
    identity = t.pin or t.ref
    if not identity:
        echo(f"{t.bin}: no exact install identity — NOT activated")
        return False

    candidate = None
    root = None
    with _install_lock(t.lock_key or t.bin) as locked:
        if not locked:
            echo(f"{t.bin}: another install/update is in progress — skipped")
            return False
        try:
            root = _managed_root(t)
            versions = root / "versions"
            for directory in (root, versions):
                _private_directory(directory)
            active = _active_version(root)
            generation = os.urandom(16).hex()
            candidate = versions / generation
            candidate.mkdir(mode=0o700)
            previous_tools = _copy_active_version(active, candidate)
            _set_candidate_writable(candidate)
            environment = _installer_environment(candidate, t)
            bindir = candidate / "home" / ".local" / "bin"
            for obsolete in (bindir / t.bin, bindir / ".stage" / t.bin):
                if obsolete.is_symlink() or obsolete.exists():
                    obsolete.unlink()
            with _install_environment(environment, t):
                code, command_output = run_shell(cmd, False)
            if code != 0:
                raise _ActivationError(
                    f"{t.bin}: install command failed with exit {code}: "
                    f"{_install_output_detail(command_output)}"
                )
            try:
                executable = _candidate_executable(candidate, t)
            except _ActivationError as exc:
                raise _ActivationError(
                    f"{t.bin}: install command exited 0 but staged no binary: "
                    f"{_install_output_detail(command_output)}"
                ) from exc
            _validate_declared_payloads(candidate, t)
            cache = candidate / "cache"
            if os.path.lexists(cache):
                _discard_candidate(cache)
            _validate_retained_tools(candidate, previous_tools, t, environment)
            _freeze_candidate_payload(candidate)
            _durably_settle_candidate_payload(candidate)
            with _install_environment(environment, t):
                if not _probe_candidate(t, executable.resolve(), environment):
                    raise _ActivationError(
                        f"{t.bin}: candidate identity/capability verification failed"
                    )
            closure = _tree_rows(candidate)
            if closure != _tree_rows(candidate):
                raise _ActivationError(f"{t.bin}: candidate changed during final verification")
            executable_relative = executable.relative_to(candidate).as_posix()
            content_identity = _closure_identity(closure)
            previous_tools[t.bin] = {
                "executable": executable_relative,
                "identity": str(identity),
                "runtime": t.runtime,
                "content_identity": content_identity,
            }
            # A copied shared-lock generation has a new complete closure identity. Every retained tool record
            # must describe those exact candidate bytes, never the prior generation's aggregate.
            for record in previous_tools.values():
                record["content_identity"] = content_identity
            receipt = {
                "schema_version": _RUNTIME_RECEIPT_SCHEMA,
                "lock_key": _safe_lock_key(t.lock_key or t.bin),
                "generation": generation,
                "tools": previous_tools,
                "files": closure,
            }
            _write_runtime_receipt(candidate, receipt)
            _fsync_directory(candidate)
            _seal_candidate_root(candidate)
            _validate_runtime_receipt(
                candidate, _strict_json(candidate / _RUNTIME_RECEIPT_NAME), tool=t,
            )
            _fsync_directory(candidate)
            _fsync_directory(versions)
            relocated, rollback_backups = _activate_candidate(root, candidate, receipt, t)
            # Explicit commit boundary: from this assignment onward ``current`` names the verified candidate.
            # No cleanup, logging, or cancellation path may treat it as rejected or remove it.
            candidate = None
            try:
                _discard_candidate(rollback_backups)
            except _RollbackError as exc:
                echo(
                    f"{t.bin}: install CRITICAL (activation committed; rollback backup cleanup "
                    f"did not settle) — active candidate kept; recovery retained at {exc.recovery}"
                )
                return False
            echo(f"{t.bin}: ok ({identity})")
            if relocated is not None:
                echo(f"{t.bin}: relocated legacy PATH shadow to {relocated}")
            return True
        except _RollbackError as exc:
            echo(f"{t.bin}: install CRITICAL ({exc}) — recovery retained at {exc.recovery}")
            return False
        except (OSError, ValueError, _ActivationError) as exc:
            if root is not None and _candidate_is_current(root, candidate):
                candidate = None
                echo(
                    f"{t.bin}: install CRITICAL ({type(exc).__name__}: {exc}) — activation "
                    "committed; active candidate kept"
                )
                return False
            echo(f"{t.bin}: install FAILED ({type(exc).__name__}: {exc}) — last-known-good kept")
            if candidate is not None:
                try:
                    _discard_candidate(candidate)
                except _RollbackError as cleanup_fault:
                    echo(
                        f"{t.bin}: install CRITICAL ({cleanup_fault}) — recovery retained at "
                        f"{cleanup_fault.recovery}"
                    )
            return False
        except BaseException as primary:
            if root is not None and _candidate_is_current(root, candidate):
                candidate = None
            if candidate is not None:
                try:
                    _discard_candidate(candidate)
                except BaseException as cleanup_fault:
                    if (isinstance(primary, Exception)
                            and not isinstance(cleanup_fault, Exception)):
                        raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
                    primary.add_note(
                        f"install candidate cleanup also failed: {type(cleanup_fault).__name__}: "
                        f"{cleanup_fault}"
                    )
            raise primary.with_traceback(primary.__traceback__)


def run_shell(cmd: str, dry_run: bool) -> tuple[int, str]:
    """Run an install/update shell command. Returns (exit_code, short_output)."""
    if dry_run:
        return 0, "(dry-run)"
    try:
        environment = getattr(_install_context, "environment", None)
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800,
                           env=(dict(environment) if environment is not None else None))
        tail = "\n".join((p.stdout + p.stderr).strip().splitlines()[-4:])
        return p.returncode, tail
    except subprocess.SubprocessError as e:
        return 1, str(e)
