"""Tool registry — load tool definitions, audit installs, drive install/update/doctor.

The registry is data (data/tools.yaml); this module is the behavior around it.
"""
from __future__ import annotations

import os
import re
import shutil
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
    # a language runtime another tool needs (bun), provisioned by this same machinery but reported with
    # go/pipx/chromium, not in a phase's tool list; `phase` is still the tool that needs it
    dependency: bool = False
    # lock, one shape per runtime: go/pipx pin the module/package version (each verifies its own hashes);
    # binary pins the release tag plus per-platform `artifacts`; source pins `ref`; distro sets `policy`
    pin: str | None = None
    artifacts: dict | None = None          # {"linux/amd64": {"url": str, "sha256": <64-hex>}, ...}
    ref: str | None = None                 # exact source commit/tag (source runtime)
    policy: str | None = None              # e.g. "distro" — pinning delegated (apt)
    capability: str | None = None
    cap_codes: list | None = None          # accepted capability exit codes (default [0]); explicit per tool
    # accepted exit codes for the version probe (default [0]) — a separate axis from `cap_codes`, which says
    # only that the binary runs, not that a failed command's output carries a version
    version_codes: list | None = None
    # upstream "owner/name" for binary/source tools — the identity a future `quarry lock --refresh` queries
    # for release/commit candidates (go/pipx identities are parseable from the install string)
    repo: str | None = None
    # refresh policy, planning only — never affects verify/drift/install/runtime. State = upstream check
    # cadence; `release` = the human tag, recorded only when `pin`/`ref` is a pseudo-version or commit
    maintenance_state: str | None = None
    release: str | None = None

    @property
    def installed(self) -> bool:
        return shutil.which(self.bin) is not None

    @property
    def path(self) -> str | None:
        return shutil.which(self.bin)

    def version(self) -> str:
        """A clean version string ('v2.14.0', '2.2.4'), never the tool's banner; "" when nothing parses.
        The probe's exit code gates the parse, on `version_codes` (default {0}) and not on `cap_codes`:
        a probe that failed states no version, whatever version-shaped token its help text carries."""
        if not self.installed or not self.version_cmd:
            return ""
        rc, out = _probe(self.version_cmd)
        return _parse_version(out) if _version_ok(rc, self.version_codes) else ""


_PROBE_NOT_RUN = -1     # "not executed / timed out" — distinct from any exit code a tool could accept


def _probe(cmd: str, timeout: int = 15) -> tuple[int, str]:
    """Run a probe (shell) -> (returncode, ANSI-stripped stdout+stderr); a timeout or launch
    failure returns _PROBE_NOT_RUN, never an exit code a tool could accept."""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
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
            version_codes=t.get("version_codes"),
        ))
    return tools


def tools_by_phase(phase: str) -> list[Tool]:
    return [t for t in load_tools() if t.phase == phase]


def version_eq(a: str | None, b: str | None) -> bool:
    """Tolerant version-string compare — normalize a leading 'v' and surrounding whitespace so 'v2.14.0' and
    '2.14.0' match. Empty/None never equals anything (an unknown version is not a match)."""
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
    """The installed pipx package (version, app_paths) from `pipx list --json`, matched on the normalized
    name; app_paths are the venv-internal executables the bin symlinks point at. ('', []) if unreadable."""
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


def _read_receipt(bin_: str) -> dict:
    try:
        import json
        rp = _receipt_path(bin_)
        rec = json.loads(rp.read_text()) if rp.exists() else {}
    except (OSError, ValueError):
        return {}
    return rec if isinstance(rec, dict) else {}            # a list/scalar receipt is not usable


def _write_receipt(bin_: str, ident: str, sha: str) -> None:
    """Write the receipt {ident, sha256}: the pin or ref, and the activated binary's digest."""
    import json
    _receipt_path(bin_).write_text(json.dumps({"ident": ident, "sha256": sha}))


def installed_identity(t: "Tool") -> str:
    """The installed version by runtime-specific identity, never a CLI banner:
      go             -> the module version `go version -m` reports for the resolved binary
      pipx           -> `pipx list` metadata, tied to the resolved executable
      binary, source -> the receipt written at install time (its `ident`, with the sha256 rechecked)
      distro         -> 'distro' (not version-checked — pinning is the distro's job)
    Empty when the identity cannot be proven."""
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
    """Pin status from the already-probed identity `iv`: 'not-installed' | 'distro' | 'version-unknown' |
    'unpinned' | 'ok' | 'DRIFT'. An unknown identity is never 'ok'; a source `ref` must match exactly."""
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
    """Each managed tool's installed identity on this host against its pin/ref, with drift status —
    `quarry lock` emits it as a reviewable pin set. Probes each identity exactly once."""
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
    """The install host's platform key ('linux/amd64' | 'linux/arm64' …) that selects a binary artifact;
    Quarry targets Linux, and the arch is normalized from platform.machine()."""
    import platform as _p
    m = _p.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)
    return f"linux/{arch}"


def pinned_install(t: Tool) -> str | None:
    """The version-locked install command: go `@latest` -> `@<pin>`; pipx `install <pkg>` -> `install
    --force "<pkg>==<pin>"`; binary fills the template with this host's artifact url + sha256; source
    fills in the pinned `ref`. None when a binary tool has no artifact for this platform (uninstallable
    here — the caller reports it); the install unchanged when the tool is unpinned."""
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
    """The go-install output dir (GOBIN, else GOPATH/bin, else ~/go/bin) — the only location a shadowing
    legacy copy may be reclaimed from, never a system dir. None when it can't be resolved."""
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
    """Relocate a shadowing legacy `go install` binary to `<bin>.quarry-replaced-<ts>` — only within the
    go-install output dir. Returns the relocation path, or None when the shadow may not be touched."""
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
    """A capability probe passes only on the accepted exit codes — default exactly {0}, so an ordinary
    error, dependency failure or traceback (rc 1..125) is not laundered into success."""
    return rc in (accepted or {0})


def _version_ok(rc: int, declared=None) -> bool:
    """May a version be read out of a probe that exited `rc`? Default exactly {0} — separate from
    `cap_codes`, because a command that failed did not make a version statement."""
    return rc in (set(declared) if declared else {0})


def health(t: Tool) -> dict:
    """The single-probe health snapshot shared by `verify_installed` (install) and `doctor` (audit), so
    doctor's check means exactly what install's verify means. Keys: installed · identity · drift ·
    capability · ok. `capability` is None when the tool declares no probe; `ok` is the verify verdict."""
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
    """Is an already-installed tool healthy — identity verified (drift 'ok', or 'distro') and capability
    probe passed? `install` uses this to decide whether a present tool may be left as-is."""
    return health(t)["ok"]


def install_one(t: Tool, echo, dry_run: bool = False) -> bool:
    """The one install path shared by `quarry install` and `quarry update`; always runs the version-locked
    command, never `@latest` / `pipx upgrade`. binary/source stage to ~/.local/bin/.stage, are verified
    there, then activated atomically, so a bad build never destroys the working binary; go/pipx install in
    place, then verify runtime identity (drift = fail) and capability. Returns True on success; False on an
    unsupported platform, a manual-install tool, or any failed verification."""
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
        stage = Path.home() / ".local" / "bin" / ".stage" / t.bin
        stage.parent.mkdir(parents=True, exist_ok=True)
        if stage.exists():
            stage.unlink()
        code, out = run_shell(cmd, False)
        if code != 0 or not stage.exists():
            # report the command's own output; a guessed cause sends the operator to debug the wrong thing
            why = (f"exit {code}" if code != 0 else "exited 0 but staged no binary")
            detail = (out or "").strip()
            echo(f"{t.bin}: install FAILED ({why})"
                 + (f" — {detail}" if detail else " — the command produced no output"))
            return False
        # verify the staged binary before replacing the working one
        if t.capability or t.version_cmd:
            capcmd = (t.capability or t.version_cmd).replace(t.bin, str(stage), 1)
            if not _capability_ok(_probe(capcmd)[0], accepted):
                stage.unlink(missing_ok=True)
                echo(f"{t.bin}: CAPABILITY FAILED on staged binary — existing binary kept")
                return False
        # a working binary from the wrong release must not pass (source is covered by the receipt below)
        if t.pin and t.runtime == "binary" and t.version_cmd:
            # a second, independent probe — the capability probe's success says nothing about this one, and
            # an ungated parse would let a version-shaped token in help text stand in for the pin
            _rc, _out = _probe(t.version_cmd.replace(t.bin, str(stage), 1))
            sv = _parse_version(_out) if _version_ok(_rc, t.version_codes) else ""
            if not version_eq(sv, t.pin):
                stage.unlink(missing_ok=True)
                echo(f"{t.bin}: staged version {sv!r} != pin {t.pin} — wrong release, NOT activated")
                return False
        dest = Path.home() / ".local" / "bin" / t.bin
        os.replace(str(stage), str(dest))                    # atomic activate
        # the receipt is written before any legacy copy is touched: it always describes the live binary, and a
        # hash/receipt failure returns False with nothing yet displaced
        dest_sha = _file_sha256(dest)
        if not _SHA256_RE.fullmatch(dest_sha):
            echo(f"{t.bin}: activated but could not hash the binary for its receipt — reinstall to verify")
            return False
        try:
            _write_receipt(t.bin, t.ref or t.pin, dest_sha)
        except OSError as e:
            echo(f"{t.bin}: activated but could not write receipt ({e}) — reinstall to verify")
            return False
        # the activated binary must be the one that resolves — on PATH and not shadowed
        which = shutil.which(t.bin)
        if not which:
            echo(f"{t.bin}: activated but does NOT resolve on PATH (~/.local/bin not on PATH?)")
            return False
        if Path(which).resolve() != dest.resolve():
            # a legacy go-install copy earlier in PATH is reclaimed (go -> binary runtime migration); a shadow
            # anywhere else we must not touch — fail loud
            shadow_orig = Path(which)
            relocated = _reclaim_go_shadow(t.bin, shadow_orig)
            if relocated:
                echo(f"{t.bin}: relocated legacy go binary {which} -> {relocated} (runtime migration)")
                which = shutil.which(t.bin)
            if not which or Path(which).resolve() != dest.resolve():
                if relocated:                                # migration failed -> restore the legacy binary
                    try:
                        os.replace(str(relocated), str(shadow_orig))
                    except OSError:
                        pass
                echo(f"{t.bin}: SHADOWED — {which} resolves before the managed {dest}")
                return False
        echo(f"{t.bin}: ok ({t.pin or t.ref})")
        return True

    # go / pipx — install in place, then verify identity + capability
    code, _ = run_shell(cmd, False)
    if code != 0 or not t.installed:
        echo(f"{t.bin}: install FAILED")
        return False
    if (t.pin or t.ref) and drift(t) != "ok":             # drift or an unknown identity is a failure
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
