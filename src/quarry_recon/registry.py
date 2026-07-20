"""Tool registry — load tool definitions, audit installs, drive install/update/doctor.

No tool is "production ready" until it has a registry entry (design §2). The registry
is data (data/tools.yaml); this module is the behavior around it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# version token, not part of a longer dotted number (excludes IPs like 127.0.0.1)
_VER_RE = re.compile(r"(?<![\w.])v?\d+\.\d+(?:\.\d+)?(?![\w.])")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")             # C08 lock: a valid sha256 digest


class LockError(ValueError):
    """A tools.yaml lock field is malformed — loading fails LOUD (review-C08.1#3) rather than trusting a lock
    that only appears valid (a numeric version, a bad hash, an empty capability)."""


def _validate_lock(bin_: str, t: dict) -> None:
    """Fail loud on invalid C08 lock data — a lock that isn't trustworthy must not load silently."""
    def _bad(msg):
        raise LockError(f"{bin_}: {msg}")
    v = t.get("version")
    if v is not None and (not isinstance(v, str) or not v.strip()):
        _bad(f"version must be a non-empty string, got {v!r}")      # a numeric YAML version would crash .strip()
    for key in ("ref", "policy", "capability"):
        val = t.get(key)
        if val is not None and (not isinstance(val, str) or not val.strip()):
            _bad(f"{key} must be a non-empty string, got {val!r}")
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
    # C08 compatibility lock — STRATEGY-AWARE (review-C08.1#2), one shape per install runtime:
    #   go / pipx : `pin` = the module/package version (go verifies via the checksum DB, pip via PyPI hashes —
    #               no artifact sha needed).
    #   binary    : `pin` = the release TAG + `artifacts` = {"<os>/<arch>": {"url": .., "sha256": ..}} — a
    #               DOWNLOAD needs a per-PLATFORM hash (gitleaks ships distinct amd64/arm64 archives).
    #   source    : `ref` = the exact commit/tag built from (a version alone can't reproduce a source build).
    #   distro    : `policy: distro` (apt) — pinning is the distro's job, so no pin/artifacts here.
    # `capability` is a post-install smoke test that must succeed (stronger than "the binary exists"). The field
    # is `pin` because `version()` is already the INSTALLED-version method. All optional until C08.2 bakes them.
    pin: str | None = None
    artifacts: dict | None = None          # {"linux/amd64": {"url": str, "sha256": <64-hex>}, ...}
    ref: str | None = None                 # exact source commit/tag (source runtime)
    policy: str | None = None              # e.g. "distro" — pinning delegated (apt)
    capability: str | None = None

    @property
    def installed(self) -> bool:
        return shutil.which(self.bin) is not None

    @property
    def path(self) -> str | None:
        return shutil.which(self.bin)

    def version(self) -> str:
        """A clean version string ('v2.14.0', '2.2.4') — never the tool's ASCII banner. Extracts the first
        version-like token from the output. review-C08.1#1: returns "" (UNKNOWN) when no version token is
        found — an unparseable version is UNCAPTURABLE and must never become a trusted pin (the old 'installed'
        sentinel let version_eq('installed','installed') accept a fake pin)."""
        if not self.installed or not self.version_cmd:
            return ""
        try:
            p = subprocess.run(self.version_cmd.split(), capture_output=True,
                               text=True, timeout=15)
        except (subprocess.SubprocessError, OSError):
            return ""
        text = _ANSI_RE.sub("", p.stdout + p.stderr)
        for line in text.splitlines():          # prefer a line that names a version
            if "version" in line.lower():
                m = _VER_RE.search(line)
                if m:
                    return m.group(0)
        m = _VER_RE.search(text)
        return m.group(0) if m else ""          # no parseable version -> UNKNOWN (never a pin)


def load_tools() -> list[Tool]:
    data = yaml.safe_load(resources.files("quarry_recon.data").joinpath("tools.yaml").read_text())
    tools = []
    for t in data.get("tools", []):
        _validate_lock(t.get("bin", "?"), t)               # review-C08.1#3: fail loud on malformed lock data
        tools.append(Tool(
            bin=t["bin"], phase=t.get("phase", "?"), role=t.get("role", ""),
            install=t.get("install"), update=t.get("update"),
            version_cmd=t.get("version_cmd"), doc=t.get("doc"),
            keys=t.get("keys"), optional=bool(t.get("optional", False)),
            notes=t.get("notes"), runtime=t.get("runtime", "go"),
            deps=t.get("deps") or [], needs_chromium=bool(t.get("needs_chromium", False)),
            pin=t.get("version"), artifacts=t.get("artifacts"), ref=t.get("ref"),
            policy=t.get("policy"), capability=t.get("capability"),
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


def _drift_status(installed: bool, iv: str, pin: str | None) -> str:
    """C08 pin status from the ALREADY-PROBED installed version `iv` (probe once — review-C08.1#3):
    'not-installed' | 'version-unknown' | 'unpinned' | 'ok' | 'DRIFT'. An UNKNOWN installed version (empty) is
    UNCAPTURABLE — never 'ok' and never a pin (review-C08.1#1)."""
    if not installed:
        return "not-installed"
    if not iv:
        return "version-unknown"                            # can't determine -> can't pin
    if not pin:
        return "unpinned"
    return "ok" if version_eq(iv, pin) else "DRIFT"


def drift(t: Tool) -> str:
    return _drift_status(t.installed, t.version() if t.installed else "", t.pin)


def capture_lock() -> list[dict]:
    """C08 capture: each managed tool's INSTALLED version on THIS host (the known-good target when run on a
    validated host) vs its PINNED version in tools.yaml, with the drift status. `quarry lock` emits this as a
    reviewable pin set; doctor/install use it to flag pin drift. Probes each version EXACTLY ONCE."""
    rows = []
    for t in load_tools():
        installed = t.installed
        iv = t.version() if installed else ""               # probe ONCE, reuse for the status
        rows.append({"bin": t.bin, "installed": iv or None, "pin": t.pin,
                     "runtime": t.runtime, "optional": t.optional,
                     "drift": _drift_status(installed, iv, t.pin)})
    return rows


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
