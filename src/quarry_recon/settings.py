"""Machine-scoped runtime settings — the non-secret counterpart to secrets.yaml.

Store: `~/.config/quarry/config.yaml`. Holds knobs that are NOT credentials and NOT per-engagement —
local performance / concurrency and advanced local tool paths. Two stores, two axes:

  secrets.yaml  = credentials (tokens / keys / webhooks).
  target.yaml   = the ENGAGEMENT (scope, RATELIMIT = "pressure on the TARGET").
  config.yaml   = the MACHINE ("how many local lanes does a tool use?" = CONCURRENCY) + local paths.

(This module is `settings` to avoid colliding with `config.py`, which parses the target profile.)
Everything is optional: a missing file or unset key falls back to a safe default. `config.yaml` is
created once by bootstrap and never overwritten (same rule as secrets.yaml).
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

import yaml

PATH = Path.home() / ".config" / "quarry" / "config.yaml"
_cache: dict | None = None
#: RUN-scoped knob overrides set by an explicit operator FLAG. Config is machine policy; a flag is this
#: run's instruction, and it wins over the file for this process only. Values go through the same strict
#: readers, so a flag can never introduce a value the file could not hold (step 4.3, `--unbound`).
_overrides: dict = {}

PROFILES = ("safe", "balanced", "aggressive", "auto")


def load() -> dict:
    global _cache
    if _cache is None:
        try:
            _cache = (yaml.safe_load(PATH.read_text()) or {}) if PATH.exists() else {}
        except (yaml.YAMLError, OSError):
            _cache = {}
    return _cache


def override(key: str, value) -> None:
    """Set a run-scoped override for one knob. Explicit, per flag, never inferred."""
    _overrides[key] = value


def clear_overrides() -> None:
    """Drop every run-scoped override (a fresh process, or a test)."""
    _overrides.clear()


@contextlib.contextmanager
def overrides(values: dict):
    """Apply flag overrides for ONE run, and restore whatever was there before.

    `override()` alone is process-global and never restored, which is wrong the moment two runs share an
    interpreter — a `--settle` supervisor drives child runs in one process, and an unbound child would
    leave its bounds lifted for the next one. Snapshot in, restore in `finally`, so a run's instruction
    cannot outlive the run (flag-axis step 2)."""
    before = dict(_overrides)
    _overrides.update(values)
    try:
        yield
    finally:
        _overrides.clear()
        _overrides.update(before)


def source_of(key: str) -> str:
    """Where a value for `key` was WRITTEN: a run `flag`, the machine `config`, else `default`.

    Presence is not acceptance — a value the strict parser rejects still leaves the key present here. Ask
    `strict_int_with_source()` for the ATTRIBUTION of an effective value."""
    if key in _overrides:
        return "flag"
    return "config" if key in performance() else "default"


def performance() -> dict:
    p = load().get("PERFORMANCE")
    return p if isinstance(p, dict) else {}


def profile() -> str:
    """The concurrency PROFILE: safe | balanced | aggressive | auto (default). `auto` = derive worker
    counts from CPU cores at run time (H2); the others are fixed tiers. Unknown value → `auto`."""
    prof = str(performance().get("PROFILE") or "auto").strip().lower()
    return prof if prof in PROFILES else "auto"


def web_port_prefilter() -> bool:
    """v0.3.5: SYN web-port prefilter before the bulk httpx (naabu over host IPs × the HTTP port set →
    httpx only on OPEN host:ports, bbot-style). Default ON. `false` restores direct-httpx over ALL
    configured ports (no SYN prefilter) — but the private/reserved-only-host SKIP still applies (that's a
    safety rail, not part of the prefilter). Separate from MODES.PORTSCAN (infra scan)."""
    v = performance().get("WEB_PORT_PREFILTER")
    if v is None:
        return True
    return str(v).strip().lower() not in ("false", "no", "0", "off")


def strict_int(key: str, *, default: int, maximum: int) -> int:
    """A COVERAGE/BUDGET knob from PERFORMANCE, parsed strictly: an exact int (never a bool) or a clean
    int-string in 0..maximum. Anything else — bool, float, negative, oversized, whitespace, garbage —
    falls back to `default` rather than inventing a policy from a typo.

    `0` is a MEANINGFUL value for these knobs (the caller decides what it means: unbounded budget, full
    depth, …), which is why this is separate from `concurrency()` — that one clamps to >= 1 and would turn
    an intentional 0 into 1. Shared because the same parser is needed by every knob that decides how much
    of the eligible input gets processed (SUBFINDER_MAX_TIME, NUCLEI_MAX_HOST_ERROR, the fetch budgets),
    and three hand-rolled copies would drift."""
    return strict_int_with_source(key, default=default, maximum=maximum)[0]


def strict_int_with_source(key: str, *, default: int, maximum: int) -> tuple[int, str, str | None]:
    """`(value, source, rejected)` — the value, WHO it came from, and what was thrown away getting there.

    Attribution has to come out of the SAME parse as the value. Asking "is the key present?" separately
    reported `source: config` for a run whose configured value the parser had refused, so the policy
    evidence named an author for a number it did not choose (flag-axis step 3 review). A rejected value is
    attributed to the DEFAULT and the offending input is kept, so the report can say what was ignored."""
    written = source_of(key)
    if written == "default":
        return default, "default", None
    raw = _overrides[key] if key in _overrides else performance().get(key)
    value = None
    if isinstance(raw, bool):
        value = None                                  # a bool is not an int here, ever
    elif isinstance(raw, int):
        value = raw if 0 <= raw <= maximum else None
    elif isinstance(raw, str) and raw.strip().isdigit():
        v = int(raw.strip())
        value = v if 0 <= v <= maximum else None
    if value is None:
        return default, "default", repr(raw)          # written, refused, and SAID so
    return value, written, None


def raw(key: str, default=None):
    """The configured value EXACTLY as written, or `default` when unset.

    review-B1.6b13#1: `concurrency()` exists for worker counts, where `max(1, ...)` and a silent fallback
    are right — a zero worker pool is meaningless. They are wrong for a SPENDING control, where `0` means
    "no ceiling", a negative is a typo, and a malformed value must not become a permissive default. A
    cost guard needs the value as the operator wrote it so its own parser can refuse it."""
    v = performance().get(key)
    return default if v in (None, "") else v


def concurrency(key: str, default: int) -> int:
    """An explicit per-tool concurrency override from PERFORMANCE (e.g. `NUCLEI_CONCURRENCY`,
    `HTTPX_THREADS`), else `default`. This is the explicit-override floor; the auto/core-scaling
    layer (H2) sits on top. A blank/invalid value falls back to `default`."""
    v = performance().get(key)
    if v in (None, ""):
        return default
    try:
        return max(1, int(v))
    except (TypeError, ValueError):
        return default


# ── H2: concurrency scaled by CPU cores × profile ────────────────────────────────────────────
# Workers = CPU cores × a per-tool factor × the profile multiplier, clamped. This is CONCURRENCY
# only (local lanes); it never touches RATE (target.yaml RATELIMIT), which is applied separately —
# pushing workers must stay within the rate budget. reconftw scales threads by cores the same way;
# we cap + profile-gate it. Tools with no factor (dalfox — rate-sensitive) are override-only.
_OVERRIDE_KEY = {"nuclei": "NUCLEI_CONCURRENCY", "httpx": "HTTPX_THREADS",
                 "ffuf": "FFUF_THREADS", "dalfox": "DALFOX_WORKERS",
                 "katana": "KATANA_CONCURRENCY", "arjun": "ARJUN_THREADS"}
_CORE_FACTOR = {"nuclei": 10, "httpx": 12, "ffuf": 12, "katana": 6, "arjun": 6}   # workers per core;
#   interim bump from 6/8/10 — eyeballed per-tool RAM is modest (all <1.5 GB), so there's headroom.
#   PRECISE factors wait on per-tool CPU/RAM telemetry + a bigger-target run (the range under-stresses
#   cores). Higher nuclei -c also finishes faster → eases the timeout on multi-core boxes.
_PROFILE_MULT = {"safe": 0.5, "balanced": 1.0, "auto": 1.0, "aggressive": 1.75}
_CAP = {"nuclei": 100, "httpx": 300, "ffuf": 300, "katana": 50, "arjun": 40}
_FLOOR = 4
# Network-I/O-bound tools: their concurrency tracks network round-trips, not CPU cores. Core-scaling
# ALONE starves them on small-core boxes — a 4-core VPS got httpx -t 48, and a 567-host × 94-port probe
# timed out at 1800s. Give these a core-INDEPENDENT base (profile-scaled), and take the max with the
# core-scaled value so a big box can still go higher. Initial estimates (well within each tool's async
# limits, conservative); the next big-target run's per-tool telemetry (H3, now flushed per-phase) refines.
_IO_BASE = {"httpx": 150, "ffuf": 120, "katana": 25, "arjun": 20}   # katana/arjun are network-bound too;
# the hard-coded lows (katana -c 4, arjun -t 5) left a multi-core VPS idle. I/O-scaled now, config-tunable.


def workers(tool: str, default: int) -> int:
    """Resolve a tool's local concurrency, in priority order:
      1. explicit PERFORMANCE override (e.g. `NUCLEI_CONCURRENCY`) — always wins.
      2. auto/core-scaled: `cpu_cores × per-tool factor × profile multiplier`, clamped [floor, cap].
      3. the tool's base `default` — for a tool with no scaling factor (dalfox is override-only,
         since its worker count interacts with the rate budget)."""
    key = _OVERRIDE_KEY.get(tool)
    if key:
        ov = performance().get(key)
        if ov not in (None, ""):
            try:
                return max(1, int(ov))
            except (TypeError, ValueError):
                pass
    factor = _CORE_FACTOR.get(tool)
    if factor is None:
        return default
    cores = os.cpu_count() or 2
    prof = profile()
    mult = _PROFILE_MULT.get(prof, 1.0)
    scaled = round(cores * factor * mult)
    io = _IO_BASE.get(tool)
    if io is not None:                      # I/O-bound: a low core count must not cap network concurrency
        scaled = max(scaled, round(io * mult))
    scaled = min(scaled, _CAP.get(tool, 200))
    # `safe` = the user opted to throttle → may drop below the tool's baseline (floored at _FLOOR).
    # auto/balanced/aggressive NEVER go below the proven `default` — scaling only ADDS lanes on bigger
    # boxes, so a small VPS keeps the old behavior and `auto` never surprise-slows an existing setup.
    return int(max(_FLOOR, scaled) if prof == "safe" else max(default, scaled))


def openintel() -> dict:
    """Advanced local openintel-subs paths (`{binary, db}`) — a PATH pair, not a credential, so its
    home is config.yaml. Back-compat: if config.yaml doesn't carry it, fall back to the legacy
    `openintel:` block in secrets.yaml (its temporary parking spot). Returns {} unless configured."""
    o = load().get("openintel")
    if isinstance(o, dict) and (o.get("binary") or o.get("db")):
        return o
    from . import secrets                                   # legacy home (pre-config.yaml installs)
    return secrets.openintel()


def reset_cache() -> None:
    global _cache
    _cache = None
