"""Tool registry — load tool definitions, audit installs, drive install/update/doctor.

No tool is "production ready" until it has a registry entry (design §2). The registry
is data (data/tools.yaml); this module is the behavior around it.
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
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")             # C08 lock: a valid sha256 digest
_SENTINEL_PINS = {"installed", "latest", "main", "master", "head"}   # floating refs — NEVER a valid pin
_MAINTENANCE_STATES = {"active", "monitor", "frozen", "distro"}      # v0.3.9 refresh-cadence classes (planning only)


class LockError(ValueError):
    """A tools.yaml lock field is malformed — loading fails LOUD (review-C08.1#3) rather than trusting a lock
    that only appears valid (a numeric version, a bad hash, an empty capability)."""


def _validate_lock(bin_: str, t: dict) -> None:
    """Fail loud on invalid C08 lock data — a lock that isn't trustworthy must not load silently."""
    def _bad(msg):
        raise LockError(f"{bin_}: {msg}")
    v = t.get("version")
    if v is not None:
        if not isinstance(v, str) or not v.strip():
            _bad(f"version must be a non-empty string, got {v!r}")  # a numeric YAML version would crash .strip()
        if v.strip().lower() in _SENTINEL_PINS:
            _bad(f"version {v!r} is a floating sentinel (installed/latest/…) — pin an exact release")
        # review-C08.2: cross-field strategy — a BINARY download pinned to a version MUST carry per-platform
        # artifacts (a version tag alone doesn't fix the bytes; go/pipx verify their own hashes so they don't).
        if t.get("runtime") == "binary" and not t.get("artifacts"):
            _bad("a binary tool with a version pin must declare per-platform `artifacts` (url + sha256)")
        # review-C08.2r6#2: a pinned GO tool's install must yield a parseable module — else installed_identity
        # can't prove the built module and would (now, fail-closed) reject a correctly-installed binary forever.
        if t.get("runtime", "go") == "go" and not re.search(r"go install\s+(\S+?)@", t.get("install") or ""):
            _bad("a pinned go tool needs a parseable `go install <module>@…` install command")
    ref = t.get("ref")
    if ref is not None:
        if not str(ref).strip():
            _bad("source `ref` must be a non-empty commit/tag")
        if str(ref).strip().lower() in _SENTINEL_PINS:      # review-C08.2r4#6: `ref: main` is a FLOATING ref
            _bad(f"ref {ref!r} is a floating sentinel — pin an exact commit/tag")
    for _codes_key in ("cap_codes", "version_codes"):        # review-C08.2r3/r4#6 + review#20: same shape rules
        cc = t.get(_codes_key)
        if cc is not None:                                   # unique STRICT ints (not bool!) 0..255
            if (not isinstance(cc, list) or not cc or len(cc) != len(set(cc))
                    or not all(type(x) is int and 0 <= x <= 255 for x in cc)):  # bool is an int subclass
                _bad(f"{_codes_key} must be a non-empty list of unique ints (not bools) in 0..255, got {cc!r}")
    for key in ("ref", "policy", "capability", "release"):
        val = t.get(key)
        if val is not None and (not isinstance(val, str) or not val.strip()):
            _bad(f"{key} must be a non-empty string, got {val!r}")
    ms = t.get("maintenance_state")                          # v0.3.9: refresh-policy metadata (planning only)
    if ms is not None and ms not in _MAINTENANCE_STATES:
        _bad(f"maintenance_state must be one of {sorted(_MAINTENANCE_STATES)}, got {ms!r}")
    # review-r13#2/r14: 'distro' refresh state and `policy: distro` must AGREE (both or neither) — a distro-
    # managed tool's refresh IS the distro, and only such a tool is state 'distro'. Checked UNCONDITIONALLY, so
    # `policy: distro` with no maintenance_state (or vice versa) is rejected, not silently accepted.
    if (ms == "distro") != (t.get("policy") == "distro"):
        _bad("maintenance_state 'distro' and policy: distro must agree (set both or neither)")
    rel = t.get("release")                                    # review-r13#2: the human release tag, kept SEPARATE
    if rel is not None:                                       # from a pseudo-version/commit pin — it MUST differ
        if str(rel).strip().lower() in _SENTINEL_PINS:
            _bad(f"release {rel!r} is a floating sentinel — a release is an EXACT human tag")
        pinref = t.get("version") or t.get("ref")
        if not pinref:
            _bad("release requires a pin (version) or ref to differ from")
        # a plain normalized compare (NOT the runtime version_eq) — validation is a pure data check
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
    cap_codes: list | None = None          # accepted capability exit codes (default [0]); explicit per tool
    # accepted exit codes for the VERSION probe, default exactly [0] — a SEPARATE axis from `cap_codes`
    # (review#20, Lumpy). `cap_codes: [0, 1]` says "this tool's help screen exits 1 and that still proves
    # the binary runs". It does NOT say the output of a failed version command carries a trustworthy
    # version. Nothing declares this today: measured 2026-08-06, 0 of 29 installed tools with a version
    # probe exit non-zero. It exists so meeting one is a yaml line, not a reason to loosen `cap_codes`.
    version_codes: list | None = None
    # `repo` = the upstream "owner/name" for binary/source tools — the UPSTREAM IDENTITY a future automated
    # `quarry lock --refresh` reads to discover release/commit candidates via the GitHub API (go/pipx identities
    # are parseable from the install string, so they don't need it). Structured so refresh stays one-command.
    repo: str | None = None
    # v0.3.9 REFRESH-POLICY metadata (planning only — NEVER affects verify/drift/install/runtime, per
    # [[quarry-runtime-is-not-a-knob]]). `maintenance_state` tells a future `quarry lock --refresh` how often to
    # check upstream: active (fast cadence) · monitor (low cadence) · frozen (rarely/never updated) · distro
    # (delegated to the OS). `release` is the HUMAN release tag, kept SEPARATE from the reproducible `pin`/`ref`
    # — for a tool pinned to a go pseudo-version / commit (gowitness, smap, hakrawler, jsluice, gf, shosubgo,
    # massdns) the pin is NOT its release number, so refresh must compare releases without "upgrading" it to an
    # OLDER tagged build. A tool whose pin already IS its release omits it.
    maintenance_state: str | None = None
    release: str | None = None

    @property
    def installed(self) -> bool:
        return shutil.which(self.bin) is not None

    @property
    def path(self) -> str | None:
        return shutil.which(self.bin)

    def version(self) -> str:
        """A clean version string ('v2.14.0', '2.2.4') — never the tool's ASCII banner. review-C08.1#1: "" when
        no version token parses (UNCAPTURABLE — never a trusted pin).

        The EXIT CODE gates the parse (2026-08-06). A probe that FAILED prints whatever the tool prints on
        failure, and that is usually its help text — dalfox v2 answers `--version` with `Error: unknown flag`
        followed by help, and the first version-shaped token in it is the `Mozilla/5.0` in a default
        User-Agent. Quarry reported that tool as version "5.0": a confident number, scraped from an error.
        A failed probe knows NOTHING about the version, so it says nothing.

        Gated on `version_codes` (default `{0}`), NOT on `cap_codes` (review#20, Lumpy): the 14 tools that
        declare `[0, 1]` are saying a help screen exiting 1 proves the BINARY RUNS, which is a different
        claim from "this output carries a version"."""
        if not self.installed or not self.version_cmd:
            return ""
        rc, out = _probe(self.version_cmd)
        return _parse_version(out) if _version_ok(rc, self.version_codes) else ""


_PROBE_NOT_RUN = -1     # review-C08.2r3#1: a DISTINCT "not executed / timed out" state — never an accepted cap code


def _probe(cmd: str, timeout: int = 15) -> tuple[int, str]:
    """Run a version/capability probe (shell) → (returncode, ANSI-stripped stdout+stderr). review-C08.2r3#1: a
    TIMEOUT or LAUNCH FAILURE returns _PROBE_NOT_RUN (-1), NOT exit 1 — otherwise a tool that accepts `[0,1]`
    would classify a hung/failed probe as 'working'. -1 is never a valid cap_code (those are 0..255)."""
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
        _validate_lock(t.get("bin", "?"), t)               # review-C08.1#3: fail loud on malformed lock data
        tools.append(Tool(
            bin=t["bin"], phase=t.get("phase", "?"), role=t.get("role", ""),
            install=t.get("install"), update=t.get("update"),
            version_cmd=t.get("version_cmd"), doc=t.get("doc"),
            keys=t.get("keys"), optional=bool(t.get("optional", False)),
            notes=t.get("notes"), runtime=t.get("runtime", "go"),
            deps=t.get("deps") or [], needs_chromium=bool(t.get("needs_chromium", False)),
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
    """review-C08.2#3/r4#4: the Go MODULE PATH + version embedded in a built binary (`go version -m`) — the
    AUTHORITATIVE installed identity. Returns (module, version); ('', '') if unreadable. The module path proves
    the binary is the INTENDED tool (not a same-named binary from a different module)."""
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
    """The module path a go tool SHOULD be built from — parsed from its `go install <path>@ver` (the `/cmd/...`
    command suffix stripped). Used to prove the installed binary is the intended module (review-C08.2r4#4)."""
    m = re.search(r"go install\s+(\S+?)@", t.install or "")
    return re.sub(r"/cmd/.*$", "", m.group(1)) if m else ""


def _pipx_pkg(t: "Tool") -> str:
    m = re.search(r"pipx install\s+(\S+)", t.install or "")
    return m.group(1) if m else t.bin


def _norm_pkg(name: str) -> str:
    """PEP 503 name normalization — pipx stores venvs under the normalized package name (xnLinkFinder ->
    xnlinkfinder), so a case/underscore/dot difference must not miss the metadata (review-C08.2r2#3)."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _pipx_meta(pkg: str) -> tuple[str, list]:
    """review-C08.2#3/r5: the installed pipx package (version, app_paths) from `pipx list --json` — matched on
    the NORMALIZED name. `app_paths` are the venv-internal executables the PIPX_BIN symlinks point at, used to
    TIE the identity to the actual resolved binary (a shadow won't resolve to one of these). Root-shape safe
    (review-C08.2r5#4: a non-dict JSON root is ('', []), never a crash)."""
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
    return Path.home() / ".local" / "bin" / f".{bin_}.lock"      # C08 source receipt (records ref + activated sha256)


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
    return rec if isinstance(rec, dict) else {}            # review-C08.2r4#5: a list/scalar receipt is not usable


def _write_receipt(bin_: str, ident: str, sha: str) -> None:
    """C08 receipt: {ident, sha256} — `ident` is the pin (binary) or ref (source), `sha256` the ACTIVATED
    binary's digest. Proves both what was intended AND the exact live bytes."""
    import json
    _receipt_path(bin_).write_text(json.dumps({"ident": ident, "sha256": sha}))


def installed_identity(t: "Tool") -> str:
    """review-C08.2#3: the installed version by RUNTIME-SPECIFIC identity (never a fragile CLI banner):
      go     -> `go version -m` module version   · pipx -> pipx list metadata
      binary -> version_cmd (release binaries report a clean version)
      source -> a RECEIPT file written at install time (massdns exposes no version)
      distro -> 'distro' (not version-checked — pinning is the distro's job)."""
    if not t.installed:
        return ""
    if t.policy == "distro":
        return "distro"
    # review-C08.2r4#4: identity is of the executable that RESOLVES on PATH — a tool that doesn't resolve (or a
    # shadow) can't be the proven one. (binary/source shadowing is enforced at activation in install_one.)
    which = shutil.which(t.bin)
    if t.runtime in ("go", "pipx") and not which:
        return ""
    if t.runtime == "go":
        mod, ver = _go_mod_and_version(which)               # the RESOLVED binary, not just t.path
        exp = _expected_go_module(t)
        # review-C08.2r5#3/r6#2: EXACT module. An UNPARSEABLE expected module (exp == "") is fail-CLOSED —
        # an unknown target must never accept whatever module the binary happens to embed.
        if not mod or not exp or mod != exp:
            return ""
        return ver
    if t.runtime == "pipx":
        # review-C08.2r5#1/r6#1: TIE the version to the RESOLVED executable — an out-of-pipx shadow (e.g.
        # /usr/local/bin/arjun earlier on PATH) must not borrow the pipx env's version. An EMPTY app_paths list
        # proves nothing -> fail-closed (require a non-empty list AND membership).
        ver, app_paths = _pipx_meta(_pipx_pkg(t))
        if not ver:
            return ""
        if not app_paths or Path(which).resolve() not in {Path(a).resolve() for a in app_paths}:
            return ""                                       # resolved binary isn't the pipx-installed one
        return ver
    if t.runtime in ("binary", "source"):
        # review-C08.2r3#2/r5#2: a RECEIPT proves the exact activated binary (its sha256) for BINARY tools too —
        # a pre-C08 (unverified) binary has no receipt -> unknown identity -> reinstall (so the checksum-verified
        # download actually runs). A replaced binary's sha no longer matches -> drift.
        rec = _read_receipt(t.bin)
        ident, sha = rec.get("ident"), rec.get("sha256")
        if not ident or not sha or _file_sha256(which or t.path) != sha:
            return ""
        return str(ident)
    return t.version()


def _drift_status(t: "Tool", installed: bool, iv: str) -> str:
    """C08 pin status from the ALREADY-PROBED runtime identity `iv` (probe once — review-C08.1#3):
    'not-installed' | 'distro' | 'version-unknown' | 'unpinned' | 'ok' | 'DRIFT'. An UNKNOWN identity is
    UNCAPTURABLE — never 'ok' and never a pin. A source `ref` matches EXACTLY (a commit is not version-like);
    versions compare tolerantly."""
    if not installed:
        return "not-installed"
    if t.policy == "distro":
        return "distro"                                     # distro-managed — pinning delegated, not drift-checked
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
    """C08 capture: each managed tool's INSTALLED identity on THIS host (runtime-specific — review-C08.2#3) vs
    its PIN/ref, with the drift status. `quarry lock` emits this as a reviewable pin set; doctor/install use it
    to flag drift. Probes each identity EXACTLY ONCE."""
    rows = []
    for t in load_tools():
        installed = t.installed
        iv = installed_identity(t) if installed else ""     # runtime-specific, probe ONCE
        rows.append({"bin": t.bin, "installed": iv or None, "pin": t.pin or t.ref,
                     "runtime": t.runtime, "optional": t.optional,
                     "drift": _drift_status(t, installed, iv),
                     # v0.3.9 refresh-policy metadata (planning only) — `release` is the human tag when it differs
                     # from a pseudo-version/commit pin, so a future `lock --refresh` compares the right numbers.
                     "maintenance": t.maintenance_state, "release": t.release or t.pin or t.ref})
    return rows


def current_platform() -> str:
    """The install host's platform key ('linux/amd64' | 'linux/arm64' …) used to select a binary artifact.
    Quarry targets Linux; the arch is normalized from platform.machine()."""
    import platform as _p
    m = _p.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)
    return f"linux/{arch}"


def pinned_install(t: Tool) -> str | None:
    """C08.2: the version-LOCKED install command for a tool. go: `@latest`->`@<pin>`; pipx: `pipx install
    <pkg>`->`pipx install <pkg>==<pin>`; binary: fill the install template with THIS host's artifact url+sha256
    (a checksum-verified download); source: fill in the pinned `ref`. Returns None when a binary tool has no
    artifact for this platform (uninstallable here — the caller reports it), and the install UNCHANGED when a
    tool is unpinned. A sentinel pin never reaches here (load rejects it)."""
    cmd = t.install
    if not cmd:
        return cmd
    if t.runtime == "go" and t.pin:
        return cmd.replace("@latest", "@" + t.pin)
    if t.runtime == "pipx" and t.pin:
        # review-C08.2r2#1: `pipx install pkg==ver` LEAVES an existing env unchanged — the pin (incl. a
        # downgrade) only reliably applies with --force (a clean reinstall at the exact version).
        return re.sub(r"pipx install\s+(\S+).*",
                      lambda m: f'pipx install --force "{m.group(1)}=={t.pin}"', cmd, count=1)
    if t.runtime == "binary" and t.artifacts:
        art = t.artifacts.get(current_platform())
        if not art:
            return None                                     # no artifact for this platform -> can't install here
        return cmd.format(url=art["url"], sha256=art["sha256"], bin=t.bin)
    if t.runtime == "source" and t.ref:
        return cmd.format(ref=t.ref, bin=t.bin)
    return cmd


def _go_bin_dir() -> "Path | None":
    """The go-install OUTPUT dir (`GOBIN`, else `GOPATH/bin`, else ~/go/bin) — the ONLY location a go→binary
    runtime migration is allowed to reclaim a shadowing legacy copy from (Quarry itself put it there when the
    tool was a `go install` tool). Never a system dir. Returns None when it can't be resolved / doesn't exist."""
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
    """review-C08.2r7 (dalfox v2 go → v3 binary): a legacy `go install` binary at ~/go/bin can sit EARLIER in
    PATH than the newly-activated managed binary and shadow it — so the upgrade would silently keep running the
    OLD tool. RECLAIM it, but ONLY when it lives in the go-install output dir (a copy Quarry owns): relocate it as
    rollback EVIDENCE (`<bin>.quarry-replaced-<ts>`), never delete, never touch a path outside that dir. Returns
    the relocation path on success, else None (caller then fails loud — a shadow we may not touch)."""
    gb = _go_bin_dir()
    try:
        if not gb or shadow.resolve().parent != gb.resolve():
            return None                                     # shadow isn't the go-install dir -> hands off
        bak = shadow.with_name(f"{bin_}.quarry-replaced-{int(time.time())}")
        os.replace(str(shadow), str(bak))                   # rename within the dir — relocate, not delete
        return bak
    except OSError:
        return None


def _capability_ok(rc: int, accepted=None) -> bool:
    """review-C08.2r2#2: a capability probe passes ONLY on the ACCEPTED exit codes — default exactly {0}, so an
    ordinary error / dependency failure / invalid command / traceback (rc 1..125) is NOT laundered into success.
    A tool whose probe legitimately exits non-zero declares its codes explicitly via `cap_codes`."""
    return rc in (accepted or {0})


def _version_ok(rc: int, declared=None) -> bool:
    """May a version be READ out of a probe that exited `rc`? Default exactly {0}.

    review#20 (Lumpy): reusing `cap_codes` here gave that field two meanings. Capability asks "does this
    binary run at all" — a help screen exiting 1 answers yes. Version asks "is this output a version
    statement", and a command that failed did not make one. Separate question, separate codes."""
    return rc in (set(declared) if declared else {0})


def health(t: Tool) -> dict:
    """The SINGLE-probe health snapshot shared by `verify_installed` (install) and `doctor` (audit) — so
    doctor's ✓ means EXACTLY what install's verify means (identity drift 'ok'/'distro' AND capability pass),
    never merely 'present on PATH'. Probes the runtime identity ONCE and reuses it for both the verdict and the
    displayed version. `capability` is None when the tool declares no probe (nothing to fail); `ok` is the
    verify verdict. Keys: installed · identity · drift · capability · ok."""
    if not t.installed:
        return {"installed": False, "identity": "", "drift": "not-installed", "capability": None, "ok": False}
    iv = installed_identity(t)                               # probe ONCE, reuse for drift + display
    d = _drift_status(t, True, iv)
    cap = None
    probe = t.capability or t.version_cmd
    if probe:
        cap = _capability_ok(_probe(probe)[0], set(t.cap_codes) if t.cap_codes else None)
    return {"installed": True, "identity": iv, "drift": d, "capability": cap,
            "ok": d in ("ok", "distro") and cap is not False}


def verify_installed(t: Tool) -> bool:
    """review-C08.2r4#1: is an ALREADY-installed tool HEALTHY? Its identity must verify (drift 'ok', or 'distro'
    for a distro-managed tool) AND its capability probe pass. `install` uses this to decide whether a present
    tool may be left as-is — a failed prior update that left a wrong binary no longer reads as healthy."""
    return health(t)["ok"]


def install_one(t: Tool, echo, dry_run: bool = False) -> bool:
    """review-C08.2: the ONE install path shared by `quarry install` and `quarry update`. ALWAYS runs the
    version-LOCKED command (never @latest / pipx upgrade). binary/source stage to ~/.local/bin/.stage, are
    capability-verified there, then ATOMICALLY activated — a bad build never destroys the working binary
    (review#5). go/pipx install in place, then verify runtime identity (DRIFT = fail, review#4) + capability
    (review#2). An unsupported platform returns False, never a crash (review#6). Returns True on success."""
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
            # SAY WHAT HAPPENED. review#45 (Lumpy, from a real install): the command's own output was
            # discarded and the message guessed "(checksum or build)" for every failure — so
            # `jxscout-ast`, whose script exits with "needs bun (the analyzer fails under node)", was
            # reported as a checksum or build problem. The operator then debugs the wrong thing.
            #
            # The two states are also distinct: a command that FAILED, and one that returned 0 while
            # staging nothing. Both are failures; only one of them is the script's fault.
            why = (f"exit {code}" if code != 0 else "exited 0 but staged no binary")
            detail = (out or "").strip()
            echo(f"{t.bin}: install FAILED ({why})"
                 + (f" — {detail}" if detail else " — the command produced no output"))
            return False
        # verify the STAGED binary BEFORE replacing the working one (review#5)
        if t.capability or t.version_cmd:
            capcmd = (t.capability or t.version_cmd).replace(t.bin, str(stage), 1)
            if not _capability_ok(_probe(capcmd)[0], accepted):         # review#2: strict exit code
                stage.unlink(missing_ok=True)
                echo(f"{t.bin}: CAPABILITY FAILED on staged binary — existing binary kept")
                return False
        # review-C08.2r2#4: a WORKING binary from the WRONG release must not pass — parse the staged binary's
        # version and require it to match the pin (binary tools; source uses the receipt below).
        if t.pin and t.runtime == "binary" and t.version_cmd:
            # review#20 (Lumpy): this is a SECOND, INDEPENDENT invocation — the capability probe succeeding
            # says nothing about whether THIS one did, and for the 5 tools with a distinct `capability` it
            # is not even the same command. An ungated parse here recreates the laundering defect at
            # install time: a failed version command prints help, and a version-shaped token in that help
            # can coincide with the pin, activating a binary whose version command does not work.
            _rc, _out = _probe(t.version_cmd.replace(t.bin, str(stage), 1))
            sv = _parse_version(_out) if _version_ok(_rc, t.version_codes) else ""
            if not version_eq(sv, t.pin):
                stage.unlink(missing_ok=True)
                echo(f"{t.bin}: staged version {sv!r} != pin {t.pin} — wrong release, NOT activated")
                return False
        dest = Path.home() / ".local" / "bin" / t.bin
        os.replace(str(stage), str(dest))                    # atomic activate
        # review-C08.2r4#2/r5#2/r6#3: record the receipt for the NOW-ACTIVE binary (sha256) FIRST — before any
        # legacy copy is touched. So (a) the receipt always describes the live binary, a pre-C08 receipt-less
        # binary is reinstalled next run; and (b, review-r8#3) a hash/receipt FAILURE returns False while the
        # legacy binary is still UNtouched — the migration is transactional, it hasn't displaced anything yet.
        dest_sha = _file_sha256(dest)
        if not _SHA256_RE.fullmatch(dest_sha):
            echo(f"{t.bin}: activated but could not hash the binary for its receipt — reinstall to verify")
            return False
        try:
            _write_receipt(t.bin, t.ref or t.pin, dest_sha)
        except OSError as e:
            echo(f"{t.bin}: activated but could not write receipt ({e}) — reinstall to verify")
            return False
        # review-C08.2r3#2/r4#4: the ACTIVATED binary must be the one that RESOLVES — on PATH AND not shadowed.
        which = shutil.which(t.bin)
        if not which:
            echo(f"{t.bin}: activated but does NOT resolve on PATH (~/.local/bin not on PATH?)")
            return False
        if Path(which).resolve() != dest.resolve():
            # review-C08.2r7: a copy earlier in PATH shadows the managed binary. If it's a legacy go-install
            # binary (a go→binary runtime migration, e.g. dalfox v2→v3), reclaim it as rollback evidence so the
            # managed v3 resolves; a shadow anywhere ELSE (system dir) we must NOT touch — fail loud.
            shadow_orig = Path(which)
            relocated = _reclaim_go_shadow(t.bin, shadow_orig)
            if relocated:
                echo(f"{t.bin}: relocated legacy go binary {which} -> {relocated} (runtime migration)")
                which = shutil.which(t.bin)
            if not which or Path(which).resolve() != dest.resolve():
                if relocated:                                # review-r8#3: migration didn't take -> RESTORE the
                    try:                                     # legacy binary so the host isn't left with neither
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
    if (t.pin or t.ref) and drift(t) != "ok":             # review-r2#3: a locked tool MUST verify 'ok' (a DRIFT
        echo(f"{t.bin}: identity NOT VERIFIED ({drift(t)}) "     # OR an unknown identity is a failure, not 'ok')
             f"installed={installed_identity(t)!r} != pin {t.pin or t.ref!r}")
        return False
    probe = t.capability or t.version_cmd
    if probe and not _capability_ok(_probe(probe)[0], accepted):   # review#2: strict smoke test
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
