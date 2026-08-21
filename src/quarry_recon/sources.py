"""Source registry — the control-plane source of truth over `data/sources.yaml`.

Keyed by source_id (`phase.source`), not tool, so one tool can back several sources with different
policy (crawl.waymore_urls vs crawl.waymore_responses).  Planned phase sources remain separate from
auxiliary acquisition/control contracts, so expanding the latter cannot silently expand a phase plan.
Exposes lookup + validation. Complements
`registry.py` (the tool-install registry): that governs what to install, this governs how a source
runs — tier, class, default, failure policy, log policy.
"""
from __future__ import annotations

from importlib import resources

import yaml

TIERS = {"core", "optional", "heavy", "experimental"}
CLASSES = {"passive", "active", "deep", "attack"}
DEFAULTS = {"on", "off", "key"}
# contract fields a fully-specified source declares
CONTRACT_FIELDS = ("tool", "phase", "tier", "class", "default", "input", "output",
                   "workers", "rate", "timeout", "failure", "fallback", "parser", "log")
FULL_CONTRACT_FIELDS = CONTRACT_FIELDS + ("ownership", "transport")
_REQUIRED = ("tool", "phase", "tier", "class", "default")   # minimum for a valid registry entry
OWNERSHIP_KINDS = {"quarry_provider", "external_tool", "target_facing", "local", "operator_control"}
TRANSPORT_FIELDS = ("kind", "authority", "profile")

_cache: tuple[dict, dict] | None = None
_semantic_errors: tuple[str, ...] = ()
# YAML 1.1 parses bare on/off as booleans; normalize back to the string vocabulary.
_BOOL_DEFAULT = {True: "on", False: "off"}


def _load() -> tuple[dict, dict]:
    """Return `(planned, auxiliary)` contracts decorated with canonical semantics."""
    global _cache, _semantic_errors
    if _cache is None:
        # explicit utf-8: the registry carries non-ASCII symbols; Windows would decode as locale codepage.
        raw = yaml.safe_load(
            resources.files("quarry_recon.data").joinpath("sources.yaml").read_text(encoding="utf-8"))
        raw = raw if isinstance(raw, dict) else {}
        planned = raw.get("sources", {}) if isinstance(raw.get("sources", {}), dict) else {}
        auxiliary = (raw.get("auxiliary_sources", {})
                     if isinstance(raw.get("auxiliary_sources", {}), dict) else {})
        semantics = raw.get("semantics", {}) if isinstance(raw.get("semantics", {}), dict) else {}

        ownership: dict[str, str] = {}
        semantic_errors: list[str] = []
        for kind, source_ids in (semantics.get("ownership", {}) or {}).items():
            for source_id in source_ids or ():
                source_id = str(source_id)
                if source_id not in planned:
                    semantic_errors.append(f"ownership names unknown planned source {source_id}")
                if source_id in ownership:
                    semantic_errors.append(f"ownership names {source_id} more than once")
                ownership[source_id] = str(kind)
        provider_control_values = [str(source_id) for source_id in (semantics.get("provider_control", []) or [])]
        provider_control = set(provider_control_values)
        for source_id in provider_control:
            if source_id not in planned and source_id not in auxiliary:
                semantic_errors.append(f"provider_control names unknown source {source_id}")
        if len(provider_control) != len(provider_control_values):
            semantic_errors.append("provider_control names a source more than once")
        transport: dict[str, dict] = {}
        for spec in semantics.get("transport", []) or []:
            if not isinstance(spec, dict):
                continue
            value = {field: spec.get(field) for field in TRANSPORT_FIELDS}
            for source_id in spec.get("sources", []) or []:
                source_id = str(source_id)
                if source_id not in planned:
                    semantic_errors.append(f"transport names unknown planned source {source_id}")
                if source_id in transport:
                    semantic_errors.append(f"transport names {source_id} more than once")
                transport[source_id] = value
        for source_id in planned:
            if source_id not in ownership:
                semantic_errors.append(f"planned source {source_id} has no ownership contract")
            if source_id not in transport:
                semantic_errors.append(f"planned source {source_id} has no transport contract")

        def decorate(entries: dict, *, planned_entry: bool) -> dict:
            result: dict = {}
            for source_id, entry in entries.items():
                if not isinstance(entry, dict):
                    result[source_id] = entry
                    continue
                value = dict(entry)
                if isinstance(value.get("default"), bool):
                    value["default"] = _BOOL_DEFAULT[value["default"]]
                if planned_entry:
                    value["ownership"] = ownership.get(source_id)
                    value["transport"] = dict(transport.get(source_id, {}))
                    if source_id in provider_control:
                        value["provider_control"] = True
                result[source_id] = value
            return result

        _cache = (decorate(planned, planned_entry=True), decorate(auxiliary, planned_entry=False))
        _semantic_errors = tuple(semantic_errors)
    return _cache


def all_sources() -> dict:
    """Planned `{source_id: contract}` entries; stable input for phase planners."""
    return {source_id: dict(contract) for source_id, contract in _load()[0].items()}


def auxiliary_sources() -> dict:
    """Non-planned acquisition/control `{source_id: contract}` entries."""
    return {source_id: dict(contract) for source_id, contract in _load()[1].items()}


def all_contracts() -> dict:
    """Every canonical source contract, including non-planned auxiliary identities."""
    planned, auxiliary = _load()
    return {source_id: dict(contract) for source_id, contract in {**planned, **auxiliary}.items()}


# Explicit name for callers which must include the non-planned control plane.
all_source_contracts = all_contracts


def get(source_id: str) -> dict | None:
    """The planned phase contract for one source_id, or None.

    Kept phase-only for compatibility: this is the lookup consumed by planning
    and normal `run_contract` admission.  Control-plane callers use `get_any`.
    """
    s = _load()[0].get(source_id)
    return dict(s) if isinstance(s, dict) else None


def get_any(source_id: str) -> dict | None:
    """The canonical planned or auxiliary contract for `source_id`, or None."""
    planned, auxiliary = _load()
    s = planned.get(source_id, auxiliary.get(source_id))
    return dict(s) if isinstance(s, dict) else None


def by_tier(tier: str, *, include_auxiliary: bool = False) -> list[str]:
    """Source IDs in `tier`; phase-planned contracts only unless explicitly requested."""
    entries = all_contracts() if include_auxiliary else all_sources()
    return sorted(sid for sid, s in entries.items() if isinstance(s, dict) and s.get("tier") == tier)


def by_class(cls: str, *, include_auxiliary: bool = False) -> list[str]:
    """Source IDs in `cls`; phase-planned contracts only unless explicitly requested."""
    entries = all_contracts() if include_auxiliary else all_sources()
    return sorted(sid for sid, s in entries.items() if isinstance(s, dict) and s.get("class") == cls)


def by_phase(phase: str) -> list[str]:
    return sorted(sid for sid, s in all_sources().items() if isinstance(s, dict) and s.get("phase") == phase)


def by_ownership(kind: str, *, include_auxiliary: bool = True) -> list[str]:
    """Canonical IDs owned by `kind`; planners may opt out of auxiliary entries."""
    entries = all_contracts() if include_auxiliary else all_sources()
    return sorted(source_id for source_id, spec in entries.items()
                  if isinstance(spec, dict) and spec.get("ownership") == kind)


def provider_control_sources() -> tuple[str, ...]:
    """Lanes governed by campaign acquisition closure, derived from the registry."""
    return tuple(sorted(source_id for source_id, spec in all_contracts().items()
                        if isinstance(spec, dict) and spec.get("provider_control") is True))


def default_state(source_id: str) -> str:
    """'on' | 'off' | 'key' — the registry's default enablement (unknown source → 'off')."""
    return (get(source_id) or {}).get("default", "off")


def validate() -> list[str]:
    """Structural validation of the registry; returns a list of problems (empty = valid). No
    behavior, safe to run anywhere (doctor, verify, CI)."""
    errs: list[str] = []
    planned, auxiliary = _load()
    errs.extend(_semantic_errors)
    overlap = set(planned) & set(auxiliary)
    if overlap:
        errs.append(f"source ids occur in planned and auxiliary sections: {sorted(overlap)}")
    for sid, s in {**planned, **auxiliary}.items():
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
        if s.get("ownership") not in OWNERSHIP_KINDS:
            errs.append(f"{sid}: bad ownership {s.get('ownership')!r} (want {sorted(OWNERSHIP_KINDS)})")
        door = s.get("transport")
        if not isinstance(door, dict) or any(not isinstance(door.get(field), str) or not door[field]
                                             for field in TRANSPORT_FIELDS):
            errs.append(f"{sid}: transport must declare {list(TRANSPORT_FIELDS)}")
        missing_contract = [field for field in FULL_CONTRACT_FIELDS if field not in s]
        if missing_contract:
            errs.append(f"{sid}: missing full contract fields {missing_contract}")
        if sid in planned and isinstance(s.get("phase"), str) and "." in sid and not sid.startswith(s["phase"] + "."):
            errs.append(f"{sid}: phase {s['phase']!r} does not match source_id prefix")
    return errs
