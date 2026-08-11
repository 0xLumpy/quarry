"""Typed state records shared by the verdict, campaign, finalisation and exit-code paths; construction
validates the declared invariants and to_dict/from_dict round-trip the serialized shape exactly."""
from __future__ import annotations

import types
import typing
from dataclasses import dataclass, field, fields

from .remainder import TERMINAL_CAUSES, Remainder  # authoritative; re-exported as the one contract surface

SCHEMA_VERSION = 1
SUPPORTED_SCHEMA = frozenset({1})


class ContractError(ValueError):
    """A record violates its declared invariant."""


def _exact_int(name: str, v, *, allow_none=False) -> int:
    if v is None and allow_none:
        return 0
    if type(v) is not int or v < 0:      # `type is int` rejects bool; excludes floats/strings/negatives
        raise ContractError(f"{name} must be an exact non-negative int, got {v!r}")
    return v


def _check_schema_version(sv, key: str = "schema_version") -> None:
    if type(sv) is not int or sv not in SUPPORTED_SCHEMA:      # `type is int` rejects bool (True == 1)
        raise ContractError(f"unsupported {key} {sv!r} (this reader supports {sorted(SUPPORTED_SCHEMA)})")


def _present_int(container: dict, key: str) -> int:
    """A non-negative int if the key is present (rejecting None/bool/float/str/neg), else the 0 default."""
    return _exact_int(key, container[key]) if key in container else 0


def _present_dict(container: dict, key: str) -> dict:
    """The value if the key is present and a dict, else {} — an explicit None/list/scalar is rejected."""
    if key not in container:
        return {}
    v = container[key]
    if not isinstance(v, dict):
        raise ContractError(f"{key} must be an object, got {v!r}")
    return v


def _check_counters(prefix: str, d: dict) -> tuple[int, int, int]:
    return tuple(_present_int(d, n) for n in ("eligible", "tested", "omitted"))  # each exact or 0


def _to_dict(obj, *, drop_none=True) -> dict:
    return {f.name: getattr(obj, f.name) for f in fields(obj)
            if not (drop_none and getattr(obj, f.name) is None)}


def _from_dict(cls, d: dict):
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in (d or {}).items() if k in known})


# ── Fault ─────────────────────────────────────────────────────────────────────────────────────────
# `diagnostic` = a best-effort/secondary artifact failed (e.g. persisting stderr); it does NOT challenge the
# completeness of the recon evidence, so it never demotes a clean terminal.
_FAULT_NONBLOCKING = frozenset({"optional_tool_failed", "diagnostic"})
FAULT_KINDS = ("phase_exception", "machinery", "publication", "optional_tool_failed", "required_tool_missing",
               "diagnostic")


@dataclass
class Fault:
    kind: str
    where: str | None = None
    detail: str | None = None
    challenges_completeness: bool | None = None

    def __post_init__(self):
        if self.kind not in FAULT_KINDS:
            raise ContractError(f"unknown fault kind {self.kind!r}")
        derived = self.kind not in _FAULT_NONBLOCKING
        if self.challenges_completeness is None:
            self.challenges_completeness = derived
        elif type(self.challenges_completeness) is not bool or self.challenges_completeness != derived:
            raise ContractError(f"fault {self.kind!r} must have challenges_completeness={derived}")

    def to_dict(self) -> dict:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Fault":
        return _from_dict(cls, d)


# ── Coverage: the aggregated per-(source, measure) rollup the manifest carries (store.py) ─────────
COVERAGE_SOFT = ("sample", "provider")
COVERAGE_GAP = ("cap", "timeout", "tool_omission", "ownership", "unknown")


@dataclass
class Coverage:
    source_id: str
    measure: str
    eligible: int = 0
    tested: int = 0
    omitted: int = 0
    reason: str | None = None
    valid: bool = True
    by_kind: dict = field(default_factory=dict)
    units: list = field(default_factory=list)
    unknown: list = field(default_factory=list)

    _KINDS = frozenset(COVERAGE_SOFT + COVERAGE_GAP)

    def __post_init__(self):
        if type(self.valid) is not bool:
            raise ContractError(f"coverage.valid must be a bool, got {self.valid!r}")
        self.eligible = _exact_int("eligible", self.eligible)     # explicit null is rejected; absent already defaults
        self.tested = _exact_int("tested", self.tested)
        self.omitted = _exact_int("omitted", self.omitted)
        bk = {}
        for kind, c in self.by_kind.items():        # every nested kind + counter is checked exactly
            if kind not in self._KINDS:
                raise ContractError(f"unknown coverage kind {kind!r}")
            if not isinstance(c, dict):
                raise ContractError(f"by_kind.{kind} must be an object, got {c!r}")
            bk[kind] = list(_check_counters(f"by_kind.{kind}", c))
        u_by_kind: dict = {}
        for u in self.units:
            if not isinstance(u, dict):
                raise ContractError(f"units entry must be an object, got {u!r}")
            if u.get("kind") not in self._KINDS:
                raise ContractError(f"unknown coverage kind {u.get('kind')!r} in units")
            agg = u_by_kind.setdefault(u["kind"], [0, 0, 0])
            u_by_kind[u["kind"]] = [a + b for a, b in zip(agg, _check_counters(f"unit {u.get('unit')}", u))]
        for u in self.unknown:
            if not isinstance(u, dict):
                raise ContractError(f"unknown entry must be an object, got {u!r}")
            if u.get("kind") is not None and u["kind"] not in self._KINDS:
                raise ContractError(f"unknown coverage kind {u['kind']!r} in unknown")
        if self.valid:      # a VALID aggregate reconciles — headline, and by_kind vs units PER KIND
            headline = [self.eligible, self.tested, self.omitted]
            if self.tested + self.omitted != self.eligible:
                raise ContractError(f"valid coverage headline inconsistent: {headline}")
            if bool(bk) != bool(u_by_kind):     # attribution is two-sided or absent, never one-sided
                raise ContractError("valid coverage attribution needs both by_kind and units, or neither")
            if bk:
                bk_sum = [sum(t[i] for t in bk.values()) for i in range(3)]
                u_sum = [sum(t[i] for t in u_by_kind.values()) for i in range(3)]
                if bk_sum != headline or u_sum != headline:
                    raise ContractError(f"valid coverage attribution {bk_sum}/{u_sum} != headline {headline}")
                for kind in set(bk) | set(u_by_kind):
                    if bk.get(kind, [0, 0, 0]) != u_by_kind.get(kind, [0, 0, 0]):
                        raise ContractError(f"valid coverage kind {kind!r}: by_kind {bk.get(kind)} "
                                            f"!= units {u_by_kind.get(kind)}")

    def is_soft(self) -> bool:
        # only the kinds that actually omitted decide softness (a zero-omission gap kind does not count).
        omitting = [k for k, c in self.by_kind.items() if int((c or {}).get("omitted") or 0) > 0]
        return bool(omitting) and not self.unknown and all(k in COVERAGE_SOFT for k in omitting)

    def challenges_completeness(self) -> bool:
        # invalid/unmeasurable gates; else only an omitted gap-class kind does (no breakdown -> gates).
        if not self.valid or self.unknown:
            return True
        if self.omitted <= 0:
            return False
        if self.by_kind:
            return any(k in COVERAGE_GAP and int(c.get("omitted") or 0) > 0 for k, c in self.by_kind.items())
        return True

    def to_dict(self) -> dict:
        return _to_dict(self, drop_none=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Coverage":
        return _from_dict(cls, d)


# ── Gap ─────────────────────────────────────────────────────────────────────────────────────────
GAP_KINDS = COVERAGE_GAP + ("mixed", "required_tool_missing")


@dataclass
class Gap:
    source_id: str
    kind: str                       # required — a machine gap needs an actionable cause
    measure: str | None = None
    unit: str | None = None
    eligible: int | None = None
    tested: int | None = None
    omitted: int | None = None
    reason: str | None = None
    challenges_completeness: bool = True

    def __post_init__(self):
        if self.challenges_completeness is not True:
            raise ContractError("a Gap always challenges completeness")
        if self.kind not in GAP_KINDS:
            raise ContractError(f"unknown gap kind {self.kind!r}")
        for n in ("eligible", "tested", "omitted"):
            v = getattr(self, n)
            if v is not None:
                _exact_int(n, v)

    def to_dict(self) -> dict:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Gap":
        return _from_dict(cls, d)

    @classmethod
    def for_coverage(cls, cov: Coverage) -> list["Gap"]:
        """One Gap per gating kind (deterministic), plus an `unknown` gap for an invalid/unmeasurable
        aggregate — never a single insertion-order-dependent label for a mixed rollup."""
        if not cov.challenges_completeness():
            return []
        gaps = []
        for kind in sorted(k for k in cov.by_kind if k in COVERAGE_GAP):
            c = cov.by_kind[kind]
            if int(c.get("omitted") or 0) <= 0:      # a gap-class kind that omitted nothing is not a gap
                continue
            gaps.append(cls(source_id=cov.source_id, kind=kind, measure=cov.measure,
                            eligible=c.get("eligible"), tested=c.get("tested"), omitted=c.get("omitted"),
                            reason=cov.reason))
        if not cov.valid or cov.unknown:
            gaps.append(cls(source_id=cov.source_id, kind="unknown", measure=cov.measure, reason=cov.reason))
        if not gaps:        # challenges with no captured gap-class kind -> an explicit mixed label, never guessed
            gaps.append(cls(source_id=cov.source_id, kind="mixed", measure=cov.measure, reason=cov.reason))
        return gaps

    @classmethod
    def missing_tool(cls, tool: str, why: str | None = None) -> "Gap":
        return cls(source_id=tool, kind="required_tool_missing", reason=why)


# ── Remainder: authoritative (re-exported); reconstruct exactly, then validate ────────────────────
def parse_remainder(record: dict) -> Remainder:
    """Rebuild the authoritative Remainder from its `as_record` shape: absent counters default, but an
    explicitly supplied None/bool/str/float/negative is rejected — then the class validates the rest."""
    r = dict(record or {})
    retriable = _present_dict(r, "retriable")            # explicit None/[]/scalar is rejected, not coerced to {}
    raw_terminal = _present_dict(r, "terminal")
    terminal = {c: _exact_int(f"terminal.{c}", v) for c, v in raw_terminal.items()}   # keep 0s; reject bad values
    rem = Remainder(lane=r["lane"], unit=r["unit"], measure=r["measure"], model=r["model"],
                    now=_present_int(retriable, "now"), cooldown=_present_int(retriable, "cooldown"),
                    terminal=terminal, detail=_present_dict(r, "detail"))
    rem.validate()
    return rem


# ── WorkUnit: resume identity; the fingerprint is computed and verified on read ────────────────────
@dataclass
class WorkUnit:
    source_id: str
    inputs: object = None
    config: object = None
    file_digests: dict = field(default_factory=dict)
    adapter_schema_version: int = 1                    # the source ADAPTER's parser version; feeds the id
    record_schema_version: int = SCHEMA_VERSION        # this state record's contract version

    def __post_init__(self):
        _check_schema_version(self.record_schema_version, "record_schema_version")   # even direct construction
        if type(self.adapter_schema_version) is not int or self.adapter_schema_version < 0:
            raise ContractError(f"adapter_schema_version must be a non-negative int, got "
                                f"{self.adapter_schema_version!r}")

    def fingerprint(self) -> str:
        from . import events
        return events.work_unit(self.source_id, inputs=self.inputs, config=self.config,
                                file_digests=self.file_digests, schema_version=self.adapter_schema_version)

    def to_dict(self) -> dict:
        d = _to_dict(self, drop_none=False)
        d["fingerprint"] = self.fingerprint()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "WorkUnit":
        _check_schema_version((d or {}).get("record_schema_version", 1), "record_schema_version")
        wu = _from_dict(cls, d)
        if "fingerprint" not in (d or {}):
            raise ContractError("WorkUnit record has no fingerprint to verify")
        if d["fingerprint"] != wu.fingerprint():
            raise ContractError("WorkUnit fingerprint does not match its inputs — evidence was modified")
        return wu


# ── PolicyDecision ─────────────────────────────────────────────────────────────────────────────
POLICY_KINDS = ("off_scope_redirect", "self_withheld", "private_opt_out", "scope_exclusion", "oos", "other")


@dataclass
class PolicyDecision:
    kind: str
    subject: str
    rule: str | None = None
    reason: str | None = None
    source: str | None = None

    def __post_init__(self):
        if self.kind not in POLICY_KINDS:
            raise ContractError(f"unknown policy-decision kind {self.kind!r}")

    def to_dict(self) -> dict:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyDecision":
        return _from_dict(cls, d)


# ── RunState ──────────────────────────────────────────────────────────────────────────────────
RUN_STATES = ("created", "running", "finalizing", "finished", "finalization_failed")
#: a persisted lifecycle record that exists but cannot be read. Not a state a run may be IN and not a
#: legal transition source or target, so every advance from it fails closed.
STATE_UNKNOWN = "unknown"
#: `finished -> finalizing` is the deliberate reopen: re-finalising a finished run (`quarry report`)
#: must be able to record that the regeneration failed, and the manifest is only ever rewritten while
#: `finalizing`, so a run resting in `finished` still carries an immutable manifest.
_RUN_TRANSITIONS = {
    "created": {"running"}, "running": {"finalizing"},
    "finalizing": {"finished", "finalization_failed"},
    "finalization_failed": {"finalizing"}, "finished": {"finalizing"},
}


def run_transition_ok(src: str, dst: str) -> bool:
    return dst in _RUN_TRANSITIONS.get(src, set())


@dataclass
class RunState:
    state: str = "created"

    def __post_init__(self):
        if self.state not in RUN_STATES:
            raise ContractError(f"unknown run state {self.state!r}")

    def can_transition(self, dst: str) -> bool:
        return run_transition_ok(self.state, dst)

    def to_dict(self) -> dict:
        return _to_dict(self, drop_none=False)

    @classmethod
    def from_dict(cls, d: dict) -> "RunState":
        return _from_dict(cls, d)


# ── CommandResult: the machine result behind the exit contract (QR39-011) ─────────────────────────
OUTCOMES = ("invalid", "refused", "failed", "completed")
COVERAGE_STATES = ("clean", "intentionally_bounded", "gapped")
EXIT_CODES = (0, 2, 3, 4, 5, 6, 130)
EXIT_CLEAN, EXIT_INVALID, EXIT_BOUNDED, EXIT_GAPPED, EXIT_MACHINERY, EXIT_REFUSED, EXIT_INTERRUPTED = EXIT_CODES


def compute_exit(outcome: str, coverage: str, *, interrupted: bool = False,
                 machinery_after_start: bool = False) -> int:
    """The exit code, by the contract's deterministic precedence."""
    if outcome not in OUTCOMES:
        raise ContractError(f"unknown outcome {outcome!r}")
    if coverage not in COVERAGE_STATES:
        raise ContractError(f"unknown coverage state {coverage!r}")
    if type(interrupted) is not bool or type(machinery_after_start) is not bool:
        raise ContractError("interrupted/machinery_after_start must be bools")
    if interrupted:
        return EXIT_INTERRUPTED
    if machinery_after_start or outcome == "failed":
        return EXIT_MACHINERY
    if outcome == "invalid":
        return EXIT_INVALID
    if outcome == "refused":
        return EXIT_REFUSED
    if coverage == "gapped":
        return EXIT_GAPPED
    if coverage == "intentionally_bounded":
        return EXIT_BOUNDED
    return EXIT_CLEAN


@dataclass
class CommandResult:
    command: str
    outcome: str = "completed"
    coverage: str = "clean"
    run_id: str | None = None
    campaign_id: str | None = None
    faults: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    remediation: str | None = None
    interrupted: bool = False
    machinery_after_start: bool = False
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        if self.outcome not in OUTCOMES:
            raise ContractError(f"unknown outcome {self.outcome!r}")
        if self.coverage not in COVERAGE_STATES:
            raise ContractError(f"unknown coverage state {self.coverage!r}")
        _check_schema_version(self.schema_version)               # even a direct construction is version-gated
        for name in ("interrupted", "machinery_after_start"):     # a truthy string would flip the exit code
            if type(getattr(self, name)) is not bool:
                raise ContractError(f"CommandResult.{name} must be a bool, got {getattr(self, name)!r}")
        if not all(isinstance(f, Fault) for f in self.faults):
            raise ContractError("CommandResult.faults must contain only Fault records")
        if not all(isinstance(g, Gap) for g in self.gaps):
            raise ContractError("CommandResult.gaps must contain only Gap records")
        # the summary must not contradict the records it carries (a non-challenging optional fault may stay clean)
        if self.gaps and self.coverage != "gapped":
            raise ContractError("a result carrying gaps must have coverage='gapped'")
        if any(f.challenges_completeness for f in self.faults) and self.outcome != "failed":
            raise ContractError("a completeness-challenging fault requires outcome='failed'")

    @property
    def exit_code(self) -> int:
        return compute_exit(self.outcome, self.coverage, interrupted=self.interrupted,
                            machinery_after_start=self.machinery_after_start)

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "command": self.command,
                "run_id": self.run_id, "campaign_id": self.campaign_id,
                "outcome": self.outcome, "coverage": self.coverage,
                "faults": [f.to_dict() for f in self.faults], "gaps": [g.to_dict() for g in self.gaps],
                "interrupted": self.interrupted, "machinery_after_start": self.machinery_after_start,
                "exit_code": self.exit_code, "remediation": self.remediation}

    @classmethod
    def from_dict(cls, d: dict) -> "CommandResult":
        _check_schema_version((d or {}).get("schema_version", 1))
        d = dict(d or {})
        if "exit_code" not in d:      # the derived field is required on read — a v1 record must carry it
            raise ContractError("persisted CommandResult is missing its exit_code")
        d["faults"] = [Fault.from_dict(f) if isinstance(f, dict) else f for f in d.get("faults", [])]
        d["gaps"] = [Gap.from_dict(g) if isinstance(g, dict) else g for g in d.get("gaps", [])]
        stored = d.pop("exit_code")
        if type(stored) is not int:      # `type is int` rejects a False/True stored as exit 0/1
            raise ContractError(f"persisted exit_code must be an int, got {stored!r}")
        cr = _from_dict(cls, d)
        if stored != cr.exit_code:
            raise ContractError(f"persisted exit_code {stored} contradicts the result ({cr.exit_code})")
        return cr


# ── JSON Schema: one resolvable document, generated to match to_dict, drift-guarded by the tests ──
_JSON_TYPES = {int: "integer", str: "string", bool: "boolean", float: "number", dict: "object", list: "array"}
_RECORDS = (Fault, Coverage, Gap, WorkUnit, PolicyDecision, RunState, CommandResult)

#: computed keys `to_dict` emits that are not dataclass fields, and per-field constraints.
_EXTRA_PROPS = {
    "WorkUnit": {"fingerprint": {"type": "string"}},
    "CommandResult": {"exit_code": {"type": "integer", "enum": list(EXIT_CODES)}},
}
_REQUIRED_EXTRA = {"WorkUnit": ["fingerprint"], "CommandResult": ["exit_code"]}
_COUNTER = {"type": "integer", "minimum": 0}
_COV_KINDS = list(COVERAGE_SOFT + COVERAGE_GAP)
_CONSTRAINTS = {
    "Fault": {"kind": {"enum": list(FAULT_KINDS)}},
    "Coverage": {"eligible": {"minimum": 0}, "tested": {"minimum": 0}, "omitted": {"minimum": 0},
                 "by_kind": {"propertyNames": {"enum": _COV_KINDS},
                             "additionalProperties": {"type": "object", "additionalProperties": _COUNTER}},
                 "units": {"items": {"type": "object", "properties": {
                     "unit": {"type": "string"}, "kind": {"enum": _COV_KINDS},
                     "eligible": _COUNTER, "tested": _COUNTER, "omitted": _COUNTER}}},
                 "unknown": {"items": {"type": "object", "properties": {
                     "unit": {"type": "string"}, "kind": {"enum": _COV_KINDS}}}}},
    "Gap": {"kind": {"enum": list(GAP_KINDS)}, "challenges_completeness": {"const": True}},
    "WorkUnit": {"record_schema_version": {"enum": sorted(SUPPORTED_SCHEMA)}},
    "PolicyDecision": {"kind": {"enum": list(POLICY_KINDS)}},
    "RunState": {"state": {"enum": list(RUN_STATES)}},
    "CommandResult": {"outcome": {"enum": list(OUTCOMES)}, "coverage": {"enum": list(COVERAGE_STATES)},
                      "schema_version": {"enum": sorted(SUPPORTED_SCHEMA)},
                      "faults": {"items": {"$ref": "#/$defs/Fault"}},
                      "gaps": {"items": {"$ref": "#/$defs/Gap"}}},
}
#: the Remainder serialized (`as_record`) shape — a nested doc, hand-declared since the class is external.
_REMAINDER_DEF = {
    "type": "object",
    "properties": {"lane": {"type": "string"}, "unit": {"type": "string"}, "measure": {"type": "string"},
                   "model": {"type": "string", "enum": ["project_progress", "rerun_same_work"]},
                   "retriable": {"type": "object",
                                 "properties": {"now": {"type": "integer", "minimum": 0},
                                                "cooldown": {"type": "integer", "minimum": 0}}},
                   "terminal": {"type": "object", "propertyNames": {"enum": list(TERMINAL_CAUSES)},
                                "additionalProperties": {"type": "integer", "minimum": 0}},
                   "detail": {"type": "object"}},
    "required": ["lane", "unit", "measure", "model"],
}


def _json_type(hint):
    origin = typing.get_origin(hint)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in typing.get_args(hint) if a is not type(None)]
        base = _json_type(args[0]) if args else None
        if base is None:
            return None
        return base if isinstance(base, list) else [base, "null"]
    return _JSON_TYPES.get(hint)          # None => arbitrary JSON (e.g. WorkUnit.inputs/config): no type constraint


def _record_def(cls) -> dict:
    """A JSON Schema for one record, matching what `to_dict` serializes."""
    hints = typing.get_type_hints(cls)
    constraints = _CONSTRAINTS.get(cls.__name__, {})
    props = {}
    for f in fields(cls):
        jt = _json_type(hints.get(f.name, str))
        p = {"type": jt} if jt is not None else {}      # no type => arbitrary JSON allowed
        p.update(constraints.get(f.name, {}))
        props[f.name] = p
    props.update(_EXTRA_PROPS.get(cls.__name__, {}))
    required = [f.name for f in fields(cls) if _is_required(f)] + _REQUIRED_EXTRA.get(cls.__name__, [])
    return {"type": "object", "properties": props, "required": required}


def _is_required(f) -> bool:
    import dataclasses
    return f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING


def all_schemas() -> dict:
    """One resolvable schema document: every record under `$defs`, so `#/$defs/*` refs resolve."""
    defs = {c.__name__: _record_def(c) for c in _RECORDS}
    defs["Remainder"] = _REMAINDER_DEF
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "x-schema-version": SCHEMA_VERSION,
            "$defs": defs}


_TYPE_CHECK = {"integer": lambda v: type(v) is int, "string": lambda v: isinstance(v, str),
               "boolean": lambda v: type(v) is bool, "number": lambda v: isinstance(v, (int, float)),
               "object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
               "null": lambda v: v is None}


def _check_value(schema: dict, v, path: str, defs: dict) -> None:
    ref = schema.get("$ref")
    if ref:
        _check_object(defs[ref.rsplit("/", 1)[-1]], v, path, defs)
        return
    t = schema.get("type")
    types_ = t if isinstance(t, list) else ([t] if t else [])
    if types_ and not any(_TYPE_CHECK[x](v) for x in types_):
        raise ContractError(f"{path}: {v!r} is not {t}")
    if "enum" in schema and v not in schema["enum"]:
        raise ContractError(f"{path}: {v!r} not in enum")
    if "const" in schema and v != schema["const"]:
        raise ContractError(f"{path}: {v!r} != const {schema['const']!r}")
    if "minimum" in schema and isinstance(v, (int, float)) and v < schema["minimum"]:
        raise ContractError(f"{path}: {v} < minimum {schema['minimum']}")
    if schema.get("type") == "array" and "items" in schema and isinstance(v, list):
        for i, item in enumerate(v):
            _check_value(schema["items"], item, f"{path}[{i}]", defs)
    if schema.get("type") == "object" and isinstance(v, dict) and \
            ("properties" in schema or "additionalProperties" in schema):
        _check_object(schema, v, path, defs)          # recurse nested objects incl. additionalProperties maps


def _check_object(schema: dict, obj: dict, path: str, defs: dict) -> None:
    if not isinstance(obj, dict):
        raise ContractError(f"{path}: expected object, got {type(obj).__name__}")
    for req in schema.get("required", []):
        if req not in obj:
            raise ContractError(f"{path}: missing required {req!r}")
    props = schema.get("properties", {})
    addl = schema.get("additionalProperties")
    names = schema.get("propertyNames") or {}
    for k, v in obj.items():
        if "enum" in names and k not in names["enum"]:
            raise ContractError(f"{path}: property name {k!r} not in {names['enum']}")
        if k in props:
            _check_value(props[k], v, f"{path}.{k}", defs)
        elif isinstance(addl, dict):
            _check_value(addl, v, f"{path}.{k}", defs)


def validate_serialized(name: str, data: dict) -> None:
    """Validate a serialized record against its `$def` in the one schema document. Raises ContractError."""
    doc = all_schemas()
    if name not in doc["$defs"]:
        raise ContractError(f"no schema for {name!r}")
    _check_object(doc["$defs"][name], data, name, doc["$defs"])
