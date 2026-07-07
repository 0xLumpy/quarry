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

from pathlib import Path

import yaml

PATH = Path.home() / ".config" / "quarry" / "config.yaml"
_cache: dict | None = None

PROFILES = ("safe", "balanced", "aggressive", "auto")


def load() -> dict:
    global _cache
    if _cache is None:
        try:
            _cache = (yaml.safe_load(PATH.read_text()) or {}) if PATH.exists() else {}
        except (yaml.YAMLError, OSError):
            _cache = {}
    return _cache


def performance() -> dict:
    p = load().get("PERFORMANCE")
    return p if isinstance(p, dict) else {}


def profile() -> str:
    """The concurrency PROFILE: safe | balanced | aggressive | auto (default). `auto` = derive worker
    counts from CPU cores at run time (H2); the others are fixed tiers. Unknown value → `auto`."""
    prof = str(performance().get("PROFILE") or "auto").strip().lower()
    return prof if prof in PROFILES else "auto"


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
