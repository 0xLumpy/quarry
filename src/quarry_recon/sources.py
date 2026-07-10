"""Source registry — the control-plane single source of truth (v0.3 stabilization, step 1).

Loads `data/sources.yaml` and exposes lookup + validation. Keyed by SOURCE_ID (`phase.source`), NOT tool,
so one tool can back several sources with different policy (crawl.waymore_urls vs crawl.waymore_responses).

Complements `registry.py` (the TOOL-install registry over tools.yaml): that governs *what to install*;
this governs *how a source runs* — tier, class, default, failure policy, log policy — the control that is
currently SCATTERED across runner.py / settings.py / phase code / comments, now in ONE declarative place.
It is the substrate for `run_contract()` (step 2), `quarry plan` (step 3), and the danger-tool conversion.

STEP 1 is declarative ONLY — no phase imports this yet, so there is NO behavior change. The registry can be
validated and queried, but nothing routes through it until the wrapper + conversion land.
"""
from __future__ import annotations

from importlib import resources

import yaml

TIERS = {"core", "optional", "heavy", "experimental"}
CLASSES = {"passive", "active", "deep", "attack"}
DEFAULTS = {"on", "off", "key"}
# the contract fields a fully-specified source declares (values are spec strings until the conversion
# wires them to real execution):
CONTRACT_FIELDS = ("tool", "phase", "tier", "class", "default", "input", "output",
                   "workers", "rate", "timeout", "failure", "fallback", "parser", "log")
_REQUIRED = ("tool", "phase", "tier", "class", "default")   # minimum for a valid registry entry

_cache: dict | None = None
# YAML 1.1 parses bare on/off/yes/no as booleans, so `default: on` → True. Normalize back to the string
# vocabulary so the registry (and anyone hand-editing the yaml without quotes) stays consistent.
_BOOL_DEFAULT = {True: "on", False: "off"}


def _load() -> dict:
    global _cache
    if _cache is None:
        # explicit utf-8: the registry carries UTF-8 symbols (arrows/× in reasons), and Windows
        # defaults read_text to the locale codepage → UnicodeDecodeError before anything renders.
        raw = yaml.safe_load(
            resources.files("quarry_recon.data").joinpath("sources.yaml").read_text(encoding="utf-8"))
        srcs = (raw or {}).get("sources", {}) if isinstance(raw, dict) else {}
        for s in srcs.values():
            if isinstance(s, dict) and isinstance(s.get("default"), bool):
                s["default"] = _BOOL_DEFAULT[s["default"]]
        _cache = srcs
    return _cache


def all_sources() -> dict:
    """{source_id: contract-dict} for every registered source."""
    return dict(_load())


def get(source_id: str) -> dict | None:
    """The contract for one source_id, or None."""
    s = _load().get(source_id)
    return dict(s) if isinstance(s, dict) else None


def by_tier(tier: str) -> list[str]:
    return sorted(sid for sid, s in _load().items() if isinstance(s, dict) and s.get("tier") == tier)


def by_class(cls: str) -> list[str]:
    return sorted(sid for sid, s in _load().items() if isinstance(s, dict) and s.get("class") == cls)


def by_phase(phase: str) -> list[str]:
    return sorted(sid for sid, s in _load().items() if isinstance(s, dict) and s.get("phase") == phase)


def default_state(source_id: str) -> str:
    """'on' | 'off' | 'key' — the registry's default enablement (unknown source → 'off')."""
    return (get(source_id) or {}).get("default", "off")


def validate() -> list[str]:
    """Structural validation of the registry. Returns a list of problems (empty = valid).
    No behavior — safe to run anywhere (doctor, verify, CI)."""
    errs: list[str] = []
    for sid, s in _load().items():
        if not isinstance(s, dict):
            errs.append(f"{sid}: entry is not a mapping")
            continue
        if "." not in sid:
            errs.append(f"{sid}: source_id must be 'phase.source'")
        missing = [k for k in _REQUIRED if k not in s]
        if missing:
            errs.append(f"{sid}: missing required {missing}")
        if s.get("tier") not in TIERS:
            errs.append(f"{sid}: bad tier {s.get('tier')!r} (want {sorted(TIERS)})")
        if s.get("class") not in CLASSES:
            errs.append(f"{sid}: bad class {s.get('class')!r} (want {sorted(CLASSES)})")
        if s.get("default") not in DEFAULTS:
            errs.append(f"{sid}: bad default {s.get('default')!r} (want {sorted(DEFAULTS)})")
        if isinstance(s.get("phase"), str) and "." in sid and not sid.startswith(s["phase"] + "."):
            errs.append(f"{sid}: phase {s['phase']!r} does not match source_id prefix")
    return errs
