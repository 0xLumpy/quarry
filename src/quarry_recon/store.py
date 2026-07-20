"""Asset store + run manifest — structured JSONL is the source of truth (design §5).

Layout (per-project; project dir derived from the target.yaml location):
    <project>/recon/<run_id>/manifest.json
    <project>/recon/<run_id>/raw/<phase>/<tool>/...
    <project>/recon/<run_id>/normalized/<entity>.jsonl
    <project>/recon/<run_id>/exports/
    <project>/recon/<run_id>/reports/
    <project>/recon/state/current -> latest run (symlink)
    <project>/recon/state/history/<run_id>.json

Every normalized entity keeps provenance back to the raw evidence that produced it.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import idna as _idna                                        # IDNA2008/UTS-46 host canonicalization (C09a)
from pathlib import Path

# PRIORITY thresholds (NOT a gate): any cap/timeout with omitted>0 is already a gap — truth is not a
# fraction. These only label a gap `major` vs `minor` for operator triage: omitted >= 10% OR >= 100 absolute
# is `major` (a big-fraction small set AND a small-fraction huge set both count). Boundaries are inclusive.
COVERAGE_GAP_FRACTION = 0.10
COVERAGE_GAP_ABSOLUTE = 100


def _coverage_gates(frac: float, omitted: int) -> bool:
    """Priority label: True == `major` (material under-coverage), False == `minor`. Does NOT decide gating —
    a cap/timeout with omitted>0 is always a gap regardless of this."""
    return frac >= COVERAGE_GAP_FRACTION or omitted >= COVERAGE_GAP_ABSOLUTE


ENTITY_KEYS = {
    "subdomain": "host",
    "resolved": "host",
    "dns_record": "id",
    "live": "url",
    "url": "url",
    "js_url": "url",
    "endpoint": "value",
    "parameter": "value",
    "secret": "id",
    "ip": "ip",
    "certificate": "id",
    "port": "id",
    "finding": "id",
    "screenshot": "url",
    "tech": "id",
    "review": "id",
    "wildcard_zone": "value",   # A1: cert-derived *.X.apex brute-zones (persisted vertical→enrich for A1d)
    "web_port": "id",           # v0.3.5: open web port per host:ip (naabu SYN prefilter) — host→ip→port edge
    "oob_interaction": "id",    # OOB.1: imported out-of-band callbacks (interactsh); raw in raw/oob/,
                                # uncorrelated by default until Quarry owns the token namespace (Phase 2)
}

# ── C09a identity contract — canonical dedup key per entity type ──────────────────────────────────────
# The OLD key was `str(value).strip().lower()` for EVERY entity, which collapsed case-DISTINCT offensive
# surface (e.g. `/API` and `/api`, a case-sensitive endpoint/parameter/fingerprint). The contract below
# lowercases ONLY the case-INSENSITIVE components (DNS names; a URL's scheme+host) and PRESERVES everything
# case-sensitive (path, query, parameter names, composite ids, secret/cert fingerprints). Same function is
# used to WRITE and to RELOAD keys so dedup is stable across a reopened run.
_HOST_KEYED = {"subdomain", "resolved"}                     # key = DNS name (case-insensitive)
_URL_KEYED = {"live", "url", "js_url", "screenshot"}        # key = URL (scheme+host insensitive; path/query NOT)
_IP_KEYED = {"ip"}                                          # key = IP literal (normalize; case-insensitive)
# every other entity is id/value-keyed → case is PRESERVED (path/param/fingerprint/composite id carry case)


def _canon_host(h: str) -> str:
    """DNS-name canonicalization: lower, strip trailing dot, IDNA2008/UTS-46 non-transitional (so `faß.de`
    and `xn--fa-hia.de` share one key). Best-effort — a non-domain host (IP literal, wildcard, odd label)
    that IDNA can't encode falls back to the lowered/dot-stripped form rather than raising."""
    h = h.strip().lower().rstrip(".")
    if not h:
        return h
    try:
        return _idna.encode(h, uts46=True, transitional=False).decode("ascii")
    except Exception:
        return h


def _canon_url(u: str) -> str:
    """Canonicalize a URL's scheme + HOSTNAME only (lower + IDNA + trailing-dot strip); PRESERVE path,
    query, fragment, AND userinfo (a credential-bearing lead) exactly, so `/API` != `/api` and
    `Admin:SeCrEt@h` != `admin:secret@h`. Unparseable URL (e.g. `http://[::1`) -> preserved verbatim."""
    from urllib.parse import urlsplit, urlunsplit
    u = u.strip()
    try:
        s = urlsplit(u)
        host = s.hostname                                  # may raise ValueError on a malformed authority
        port = s.port                                       # review#9: .port ALSO raises ValueError (e.g. :99999, :abc)
    except ValueError:
        return u                                            # unparseable -> preserve (never crash Run.add)
    if not s.scheme and not s.netloc:
        return u                                            # not a URL shape — preserve verbatim
    canon_host = _canon_host(host or "")
    if ":" in canon_host:                                   # IPv6 literal -> re-bracket for a valid netloc
        canon_host = f"[{canon_host}]"
    netloc = canon_host
    if port is not None:
        netloc += f":{port}"
    if s.username is not None:                              # userinfo PRESERVED verbatim (case-sensitive creds)
        userinfo = s.username + (f":{s.password}" if s.password is not None else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((s.scheme.lower(), netloc, s.path, s.query, s.fragment))


def _canon_ip(ip: str) -> str:
    import ipaddress
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))                # compressed canonical form (IPv6 case-insensitive)
    except ValueError:
        return ip.lower()


def _all_refs(record: dict) -> list:
    """Every raw-evidence reference on a record — the scalar `raw_ref` folded into the `raw_refs` list."""
    refs = list(record.get("raw_refs") or [])
    rr = record.get("raw_ref")
    if rr and rr not in refs:
        refs.append(rr)
    return refs


def _subsumed(base: dict, incoming: dict) -> bool:
    """True when `incoming` carries NOTHING the merged `base` doesn't already hold exactly — a pure
    duplicate. A new list element, a previously-empty field now filled, OR a CONFLICTING scalar (a different
    non-empty value) all make it False → the observation is novel and must be logged (never discarded)."""
    _a = base.get("_alt")                                   # review#9: alternates we've ALREADY logged per field
    alt = _a if isinstance(_a, dict) else {}                # review#8: tolerate a corrupt/crafted non-dict _alt
    for k, v in incoming.items():
        if k in ("first_seen", "last_seen", "_alt") or v in (None, "", [], {}):
            continue
        cur = base.get(k)
        if isinstance(v, list):
            curl = cur if isinstance(cur, list) else ([cur] if cur not in (None, "") else [])
            if any(x not in curl for x in v):
                return False
        elif cur in (None, "", [], {}):
            return False                                    # fills a previously-empty field — novel
        else:
            _seen = alt.get(k)                              # review#4: a corrupt non-list entry (e.g. int) -> []
            if cur != v and v not in (_seen if isinstance(_seen, list) else []):
                return False                                # a CONFLICT we have NOT logged before — novel
        # else: cur==v (dup) OR a conflict whose value is already in the log (_alt) → nothing new
    return True


def _merge_record(base: dict, incoming: dict) -> dict:
    """C09b provenance merge: union list-valued evidence, fill previously-empty enrichment fields, and
    NEVER overwrite a non-empty scalar (a conflicting value stays in the immutable observation log). Symmetric
    provenance: `sources`, `raw_refs`, tags, IPs, and any list field are unioned order-preserving."""
    merged = dict(base)
    _a = base.get("_alt")                                   # review#9: per-field conflicting alternates already logged
    alt = dict(_a) if isinstance(_a, dict) else {}          # review#8: tolerate a corrupt/crafted non-dict _alt
    for k, v in incoming.items():
        if k in ("raw_ref", "raw_refs", "first_seen", "last_seen", "_alt"):
            continue                                        # refs handled below; timestamps below; _alt is internal
        cur = merged.get(k)
        if isinstance(cur, list) or isinstance(v, list):    # union lists (either side), order-preserving
            out = list(cur) if isinstance(cur, list) else ([cur] if cur not in (None, "") else [])
            for x in (v if isinstance(v, list) else [v]):
                if x not in out:
                    out.append(x)
            merged[k] = out
        elif cur in (None, "", [], {}):
            merged[k] = v                                   # fill a previously-empty enrichment field
        elif cur != v:                                      # a CONFLICT: KEEP first value (first non-empty wins),
            seen = alt.get(k)                               # but REMEMBER the alternate so a repeat is subsumed
            if not isinstance(seen, list):                  # review#4: normalize a corrupt/non-list entry
                seen = []
            if v not in seen:                               # (else an unchanged conflict re-appends forever)
                alt[k] = seen + [v]
        # else: cur==v → nothing to do
    if alt:
        merged["_alt"] = alt                                # conflicting values, preserved in the merged view too
    refs = _all_refs(base)
    for x in _all_refs(incoming):
        if x not in refs:
            refs.append(x)
    if refs:
        merged["raw_refs"] = refs
        merged["raw_ref"] = refs[0]                         # back-compat scalar = first evidence
    # keep the EARLIEST first_seen across observations
    fs = [t for t in (base.get("first_seen"), incoming.get("first_seen")) if t]
    if fs:
        merged["first_seen"] = min(fs)
    # review#8: keep the LATEST last_seen across observations — persisted (stamped on each appended obs), so a
    # reopened run recovers it from the log instead of losing an in-memory-only value.
    ls = [t for t in (base.get("last_seen"), incoming.get("last_seen")) if t]
    if ls:
        merged["last_seen"] = max(ls)
    return merged


def canonical_key(entity: str, record: dict) -> str:
    """The dedup identity for a normalized entity — case-correct per the contract above. Empty when the
    record is not an object or the key field is absent/blank (the record is then not addable)."""
    if not isinstance(record, dict):
        return ""                                           # a non-object JSONL row (null/[]/scalar) is not an entity
    raw = str(record.get(ENTITY_KEYS.get(entity, "value"), "")).strip()
    if not raw:
        return ""
    if entity in _HOST_KEYED:
        return _canon_host(raw)
    if entity in _URL_KEYED:
        return _canon_url(raw)
    if entity in _IP_KEYED:
        return _canon_ip(raw)
    return raw                                              # id/value: case-PRESERVING (strip only)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_started(path: Path):
    """The recorded `started` timestamp from a run.json / manifest.json, or None if absent/unreadable —
    so open() can recover the real start without fabricating one."""
    try:
        v = json.loads(path.read_text())
        return v.get("started") if isinstance(v, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _atomic_write(path: Path, text: str) -> None:
    """Write via a same-directory temp + os.replace so a reader never sees a half-written file and a
    crash mid-write leaves the previous version intact (C10a)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


@dataclass
class ToolRunRecord:
    phase: str
    tool: str
    status: str
    exit_code: int | None
    duration: float
    stdout_lines: int
    note: str
    cmd: str
    stderr_tail: str = ""
    cpu_s: float = 0.0                 # per-tool child CPU seconds (H3 telemetry)
    peak_rss_mb: float = 0.0           # per-tool peak RSS (MB) of the process tree (H3 telemetry)


class Run:
    """One reconnaissance run inside a project: owns its tree, manifest, and entity store.

    Lives at <project_dir>/recon/<run_id>/ — the project dir is derived from the target.yaml
    location, so a run's output co-locates with its profile (campaign/project model).
    """

    def __init__(self, project_dir: Path, target: str, run_id: str | None = None, *, load_started: bool = False):
        self.project_dir = Path(project_dir)
        self.target = target
        self.run_id = run_id or self._mint_run_id()
        self.dir = self.project_dir / "recon" / self.run_id
        self.raw = self.dir / "raw"
        self.normalized = self.dir / "normalized"
        self.exports = self.dir / "exports"
        self.reports = self.dir / "reports"
        for d in (self.raw, self.normalized, self.exports, self.reports):
            d.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.dir / "manifest.json"
        self.meta_path = self.dir / "run.json"            # IMMUTABLE creation record (started/run_id/target)
        self._tool_runs: list[ToolRunRecord] = []
        self._counts_cache: dict[str, int] = {}
        self._records: dict[str, dict] = {}   # entity -> {canonical_key: MERGED record} (C09b; instance-local)
        # C10a/review#7: OPENING an existing run must NOT fabricate a fresh start time (a ghost). It reads
        # `started` from the IMMUTABLE run.json written at CREATE — which survives a crash even when the final
        # manifest was never written (the exact resume situation). Manifest is only a fallback; a fresh
        # CREATE stamps now and persists run.json so a later open() can never invent a start.
        if load_started:
            self.started = _read_started(self.meta_path) or _read_started(self.manifest_path) or _utc()
        else:
            self.started = _utc()
            if not self.meta_path.exists():
                _atomic_write(self.meta_path, json.dumps(
                    {"run_id": self.run_id, "target": target, "started": self.started}))
        self.notes: list[str] = []

    # ── C10a lifecycle ──
    @staticmethod
    def _mint_run_id() -> str:
        """Collision-resistant run id: sortable UTC timestamp + 8-hex random suffix. Second-precision alone
        collided (two runs in the same second reused one directory); the 4-byte suffix (4.3B space) makes a
        same-second clash negligible, and Run.create() claims the dir atomically to eliminate even that."""
        return time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()

    @classmethod
    def create(cls, project_dir, target) -> "Run":
        """Start a NEW run — mint a unique id and CLAIM its directory atomically (mkdir exist_ok=False),
        retrying on the astronomically-unlikely clash. `started` = now."""
        project_dir = Path(project_dir)
        for _ in range(16):
            rid = cls._mint_run_id()
            try:
                (project_dir / "recon" / rid).mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                continue
            return cls(project_dir, target, run_id=rid)
        raise RuntimeError("could not mint a unique run id after 16 attempts")

    @classmethod
    def open(cls, project_dir, target, run_id) -> "Run":
        """Attach to an EXISTING run — must already exist (never fabricate a ghost dir / start time).
        Reads the recorded `started` from run.json (manifest fallback).

        review#5: VALIDATE the recorded start BEFORE the constructor mutates the tree (it creates raw/…
        subdirs). A run with neither a readable run.json NOR a readable manifest is corrupt — raise instead of
        silently inventing a fresh `started` (a ghost) and half-materializing a directory for it."""
        d = Path(project_dir) / "recon" / run_id
        if not d.is_dir():
            raise FileNotFoundError(f"run {run_id!r} not found under {d.parent}")
        if _read_started(d / "run.json") is None and _read_started(d / "manifest.json") is None:
            raise ValueError(f"run {run_id!r} has no readable run.json/manifest — refusing to fabricate a start")
        return cls(project_dir, target, run_id=run_id, load_started=True)

    # ── raw evidence ──
    def raw_path(self, phase: str, tool: str, name: str) -> Path:
        p = self.raw / phase / tool
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    # ── tool run accounting ──
    def record(self, phase: str, result) -> None:
        # Redact any secret values out of the recorded command/note/stderr before they ever
        # hit the manifest (e.g. shosubgo's `-s <shodan-key>` arg). Single choke point.
        from . import secrets
        self._tool_runs.append(ToolRunRecord(
            phase=phase, tool=result.tool, status=str(result.status.value),
            exit_code=result.exit_code, duration=round(result.duration, 2),
            stdout_lines=result.stdout_lines, note=secrets.redact(result.note),
            cmd=secrets.redact(" ".join(result.cmd)), stderr_tail=secrets.redact(result.stderr_tail),
            cpu_s=getattr(result, "cpu_s", 0.0), peak_rss_mb=getattr(result, "peak_rss_mb", 0.0),
        ))

    def tool_runs(self, phase: str | None = None) -> list[ToolRunRecord]:
        if phase is None:
            return list(self._tool_runs)
        return [r for r in self._tool_runs if r.phase == phase]

    # ── normalized entities (JSONL, append, dedup on natural key) ──
    def _entity_file(self, entity: str) -> Path:
        return self.normalized / f"{entity}.jsonl"

    def add(self, entity: str, record: dict) -> bool:
        """Record an observation of a normalized entity. Returns True iff its natural key is NEW (so the
        `sum(add(...))`/`if add(...)` counting semantics across phases are unchanged).

        C09a: identity is case-CORRECT (canonical_key) — `/API` != `/api`.
        C09b: provenance is MERGED, never discarded. A repeat observation of an existing key is UNIONed into
        the merged view (sources / raw_refs / tags / IPs / list evidence unioned; previously-empty
        enrichment filled; a conflicting non-empty scalar keeps the first value, and every observation is
        still appended to the immutable JSONL log, so nothing is lost). Only a VALUE-ADDING observation is
        appended (a pure duplicate that changes nothing is a no-op), which bounds file growth.

        review#3: consequently `last_seen` means the time of the last observation that ADDED something (new
        evidence / a conflicting value) — NOT the last time the entity was seen at all. A pure-duplicate
        re-sighting is deliberately not appended (growth-bounding), so it does not advance `last_seen`. This
        narrower "last value-changing observation" semantic is intentional; `first_seen` is exact."""
        key = canonical_key(entity, record)
        if not key:
            return False
        records = self._records_for(entity)
        # review#8: `_alt` is RESERVED internal merge metadata — strip it from caller/source input so external
        # data can never inject a value that later crashes or corrupts the conflict tracking.
        record = {k: v for k, v in dict(record).items() if k != "_alt"}
        now = _utc()
        record.setdefault("first_seen", now)
        record["last_seen"] = now       # review#8: on the APPENDED obs -> durable; review#3: = last VALUE-ADDING obs
        if key not in records:
            records[key] = record
            self._append_obs(entity, record)
            return True
        if not _subsumed(records[key], record):             # novel: new evidence OR a conflicting value
            self._append_obs(entity, record)                # keep the raw observation in the immutable log
            records[key] = _merge_record(records[key], record)   # folds max(last_seen) durably
        return False                                        # not a NEW entity (counting semantics preserved)

    def _append_obs(self, entity: str, record: dict) -> None:
        with self._entity_file(entity).open("a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _records_for(self, entity: str) -> dict:
        """Lazily materialize the MERGED view {key: record} for an entity by folding its append-only JSONL
        observation log (so a reopened run recovers the same merged state). Dict-safe + skips keyless rows."""
        if entity not in self._records:
            merged: dict[str, dict] = {}
            f = self._entity_file(entity)
            if f.exists():
                for line in f.read_text().splitlines():
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    k = canonical_key(entity, rec)
                    if not k:
                        continue
                    merged[k] = _merge_record(merged[k], rec) if k in merged else rec
            self._records[entity] = merged
        return self._records[entity]

    def _seen_keys(self, entity: str) -> set:
        return set(self._records_for(entity))

    def read(self, entity: str) -> list[dict]:
        """The MERGED entities (one per canonical key, provenance unioned) — not the raw observation lines."""
        return list(self._records_for(entity).values())

    def count(self, entity: str) -> int:
        return len(self._records_for(entity))

    def values(self, entity: str) -> list[str]:
        key_field = ENTITY_KEYS.get(entity, "value")
        return [str(r.get(key_field, "")) for r in self.read(entity) if r.get(key_field)]

    # ── manifest ──
    def _run_summary(self) -> dict:
        """Per-run reliability rollup for the manifest: tool status counts + the 'what failed' list + a
        run VERDICT and a GAPS list. A degraded run must NEVER read as a clean success — `tools_failed`
        only counts hard FAILED, so partial/blocked/timed_out sources were invisible in the headline.
        `gaps` names every such source with its `output_lines` (stdout line count — NOT proof of evidence;
        a -o tool preserves an artifact with zero stdout), and `verdict` is `complete_with_gaps` whenever
        any source failed OR degraded OR a phase raised OR a required tool was missing.
        `note`/`stderr_tail` were already redacted by record(); phase_exceptions are redacted here so no
        free-text bypasses the manifest secret choke point."""
        from . import events, secrets
        _DEGRADED = ("partial", "blocked", "timed_out")
        _MISSING = ("not on path", "not installed", "not found")   # skip reason == the tool is absent
        # a REQUIRED (non-optional) tool skipped because it is MISSING is a coverage gap; an optional /
        # setup-disabled / passive skip is intentional and fine. (output_lines is stdout only — NOT
        # proof of evidence; a -o tool preserves an artifact with zero stdout — hence the honest name.)
        try:
            from .registry import load_tools
            _required = {t.bin for t in load_tools() if not t.optional}
        except Exception:
            _required = set()
        status_counts: dict[str, int] = {}
        failures = []
        gaps = []
        for r in self._tool_runs:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            why = r.note or r.stderr_tail or f"exit {r.exit_code}"
            if r.status == "failed":
                failures.append({"phase": r.phase, "tool": r.tool, "why": why})
            elif r.status in _DEGRADED:
                gaps.append({"phase": r.phase, "tool": r.tool, "status": r.status,
                             "why": why, "output_lines": r.stdout_lines})
            elif (r.status == "skipped" and r.tool in _required
                  and any(m in why.lower() for m in _MISSING)):
                gaps.append({"phase": r.phase, "tool": r.tool, "status": "missing",
                             "why": why, "output_lines": 0})       # required tool absent -> coverage gap
        # review-r3#1/r4#6: in-process provider terminals (run_provider) never hit _tool_runs — fold them here
        # so a FAILED/PARTIAL provider feeds the verdict AND every provider terminal (incl. clean) increments
        # tool_status (a `tools_failed` count without a matching status count is a lie). Keyed by
        # (source_id, work_unit), latest per current generation.
        for term in self._read_provider_terminals():
            sid = term.get("source_id", "?")
            st = term.get("status")
            status_counts[st] = status_counts.get(st, 0) + 1     # providers count toward tool_status too
            if st not in ("failed", "partial", "incomplete"):
                continue
            why = term.get("reason") or term.get("error_class") or st
            entry = {"phase": sid.split(".", 1)[0], "tool": sid, "why": why}
            if term.get("error_class"):
                entry["error_class"] = term["error_class"]
            if st == "failed":
                failures.append(entry)
            else:                                                 # partial / incomplete (crash) -> a coverage gap
                gaps.append({**entry, "status": st, "output_lines": 0})
        phase_exceptions = [secrets.redact(n) for n in self.notes if "EXCEPTION" in n]
        # ── coverage counters: reconcile event-level input omissions into the verdict ──────────────
        # A cap/timeout SITE records tool-level success yet may truncate eligible input; its coverage_partial
        # event carries eligible/tested/omitted/kind/unit. TRUTH policy (not a threshold): dropping eligible
        # methodology means the run is NOT clean —
        #   · a CAP or TIMEOUT with omitted>0 is a GAP (complete_with_gaps), regardless of fraction;
        #   · an operator-selected SAMPLE with omitted>0 is a soft LIMIT (complete_with_limits, not a gap);
        #   · an INCONSISTENT triple is coverage:unknown (a gap — never fabricated completion).
        # The 10%/100 rule is retained ONLY as a `priority` label (major/minor) for triage, NOT to gate.
        # by_kind is kept so a mixed source is reported honestly (sample counts stay sample, timeouts gate).
        coverage = self._read_coverage()
        coverage_limits = []
        for cov in coverage:
            sid = cov["source_id"]
            base = {"phase": sid.split(".", 1)[0], "tool": sid, "measure": cov["measure"], "why": cov["reason"]}
            if not cov["valid"]:
                gaps.append({**base, "status": "coverage:unknown", "output_lines": cov["tested"],
                             "eligible": cov["eligible"], "omitted": cov["omitted"]})
                continue
            for kind, c in cov["by_kind"].items():
                if c["omitted"] <= 0:
                    continue                                          # fully covered this run — no gap/limit
                frac = round(c["omitted"] / c["eligible"], 3) if c["eligible"] else 0.0
                entry = {**base, "status": f"coverage:{kind}", "output_lines": c["tested"],
                         "eligible": c["eligible"], "omitted": c["omitted"], "omitted_fraction": frac,
                         "priority": "major" if _coverage_gates(frac, c["omitted"]) else "minor"}
                if kind == events.COVERAGE_SAMPLE:
                    coverage_limits.append(entry)                     # operator-chosen subset -> soft limit
                else:
                    gaps.append(entry)                                # cap/timeout with omitted>0 -> gap
        verdict = ("complete_with_gaps" if (failures or gaps or phase_exceptions)
                   else "complete_with_limits" if coverage_limits else "complete")
        return {"verdict": verdict, "tool_status": status_counts, "tools_failed": len(failures),
                "failures": failures, "gaps": gaps, "phase_exceptions": phase_exceptions,
                "coverage": coverage, "coverage_limits": coverage_limits}

    def _read_coverage(self) -> list[dict]:
        """Aggregate STRUCTURED coverage_partial events (those carrying eligible/tested/omitted) from
        events.jsonl into a per-source_id rollup, rerun/resume-safe:
          1. keep only the LATEST record per (source_id, unit) — a repeated phase re-emits the SAME unit
             every run (including with omitted=0 when it no longer caps), so latest-per-unit lets an
             uncapped rerun CLEAR a prior cap. Summing raw appends would double-count and never clear.
          2. aggregate surviving units per source_id, keeping a `by_kind` breakdown so a mixed source
             reports honestly (sample counts stay sample; timeout counts gate) — no relabeling.
          3. counters are coerced defensively; a unit with a non-numeric / inconsistent triple flags the
             source ``valid=False`` and its garbage numbers are NOT summed (verdict treats it as unknown,
             and manifest generation can never crash on a bad value).
        Legacy per-item events (no structured counters) are ignored — already covered by degraded tool_runs.
        Best-effort: a missing/garbled log yields []."""
        from . import events

        def _int(x):
            try:
                return int(x)
            except (TypeError, ValueError):
                return None

        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        # Process the log IN LINE ORDER (append order = happened order): a coverage_reset for a source DROPS
        # that source's accumulated units; the lines after it are the new generation. No timestamp math, so a
        # unit sharing the reset's millisecond can't survive, and a vanished unit is cleared by its reset.
        live: dict[str, dict] = {}                                 # source_id -> {unit: latest rec} (current gen)
        try:
            for line in ev.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                et = rec.get("event")
                sid = rec.get("source_id", "?")
                if et == events.COVERAGE_RESET:
                    live.pop(sid, None)                            # new generation: prior units gone
                elif et == events.COVERAGE_PARTIAL and rec.get("eligible") is not None:
                    live.setdefault(sid, {})[rec.get("unit", sid)] = rec   # latest per unit, this generation
        except Exception:
            pass
        # aggregate per (source_id, MEASURE) — files and params (different measures) are NEVER summed; each
        # rollup has one homogeneous denominator. by_kind is kept so a mixed source reports each kind honestly,
        # and per-unit summaries are retained so a multi-unit rollup keeps HONEST attribution (not just the
        # first unit's reason).
        agg: dict[tuple, dict] = {}
        for sid, units in live.items():
            for rec in units.values():
                measure = rec.get("measure") or "items"
                kind = rec.get("kind") or events.COVERAGE_TIMEOUT
                elig, tst, omt = _int(rec.get("eligible")), _int(rec.get("tested")), _int(rec.get("omitted"))
                a = agg.setdefault((sid, measure),
                                   {"source_id": sid, "measure": measure, "eligible": 0, "tested": 0,
                                    "omitted": 0, "reason": None, "valid": True, "by_kind": {}, "units": []})
                unit_valid = (rec.get("coverage_valid") is not False and None not in (elig, tst, omt)
                              and elig >= 0 and tst >= 0 and omt >= 0 and tst + omt == elig)
                if not unit_valid:
                    a["valid"] = False                            # do NOT sum garbage -> no += on a str
                    continue
                a["eligible"] += elig; a["tested"] += tst; a["omitted"] += omt
                a["units"].append({"unit": rec.get("unit", sid), "eligible": elig, "tested": tst,
                                   "omitted": omt, "kind": kind, "reason": rec.get("reason")})
                bk = a["by_kind"].setdefault(kind, {"eligible": 0, "tested": 0, "omitted": 0})
                bk["eligible"] += elig; bk["tested"] += tst; bk["omitted"] += omt
        for a in agg.values():                                    # honest aggregate reason (attribution kept in `units`)
            limited = [u for u in a["units"] if u["omitted"] > 0]
            if len(limited) == 1:
                a["reason"] = limited[0]["reason"]
            elif len(limited) > 1:
                a["reason"] = f"{len(limited)} unit(s) limited; {a['omitted']} {a['measure']} omitted"
            elif a["units"]:
                a["reason"] = a["units"][0]["reason"]             # fully covered — carry a representative note
        return list(agg.values())

    def _read_provider_terminals(self) -> list[dict]:
        """review-r3#1/r4#6: fold IN-PROCESS provider terminals (run_provider, marked provider=True) into the
        verdict — they never hit _tool_runs, so a FAILED/PARTIAL provider would otherwise leave the run looking
        complete, and clean providers would be invisible to the status counts. Returns ALL current-generation
        terminals (the caller counts every status and gates on failed/partial). GENERATION (review-r4#3): a
        terminal marked reset_generation supersedes this source's PRIOR terminals (all work_units) — processed in
        LINE ORDER so a resume/config-change clears stale failures, keeping the LATEST per (source_id, work_unit)
        within the current generation. The `provider` flag prevents double-counting a subprocess lane."""
        from . import events
        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        latest: dict[tuple, dict] = {}
        try:
            for line in ev.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                et = rec.get("event")
                if not rec.get("provider") or et not in (events.TOOL_START, events.TOOL_FINISH):
                    continue
                sid = rec.get("source_id", "?")
                key = (sid, rec.get("work_unit"))
                if et == events.TOOL_START:
                    if rec.get("reset_generation"):               # review-r5#1: reset persisted BEFORE execution
                        for k in [k for k in latest if k[0] == sid]:   # new generation: drop this source's prior units
                            del latest[k]
                    # record the START as INCOMPLETE — replaced when the matching terminal arrives; a start with
                    # NO terminal (crash mid-provider) stays incomplete and gates the verdict.
                    latest[key] = {"source_id": sid, "work_unit": rec.get("work_unit"),
                                   "status": "incomplete", "reason": "provider started but never finished (crash?)"}
                else:                                             # TOOL_FINISH — terminal supersedes the start
                    latest[key] = rec
        except Exception:
            return []
        return list(latest.values())

    def write_manifest(self, profile_summary: dict, phases_run: list[str],
                       metrics: dict | None = None) -> None:
        from . import secrets
        manifest = {
            "run_id": self.run_id,
            "target": self.target,
            "started": self.started,
            "finished": _utc(),
            "profile": profile_summary,
            "phases_run": phases_run,
            "tool_runs": [asdict(r) for r in self._tool_runs],
            "entity_counts": {e: self.count(e) for e in ENTITY_KEYS
                              if self._entity_file(e).exists()},
            "notes": [secrets.redact(n) for n in self.notes],
            "summary": self._run_summary(),
        }
        if metrics:                                 # pointer + headline totals for the telemetry artifact
            manifest["metrics"] = metrics
        # C11: if any event-sink write FAILED this session, events.jsonl is incomplete — record that fact so
        # a coverage/verdict folded from it is not read as clean truth (the run itself never crashed on it).
        from . import events as _events
        od = _events.observability_degraded()
        if od:
            manifest["observability_degraded"] = od
        _events.persist_degraded()                  # review#6: survive to the next resume (accumulates)
        # C10a: atomic write (temp + os.replace) so a crash mid-write never leaves a truncated manifest.
        _atomic_write(self.manifest_path, json.dumps(manifest, indent=2))
        # update state pointers (per-project, under recon/)
        state = self.project_dir / "recon" / "state"
        (state / "history").mkdir(parents=True, exist_ok=True)
        _atomic_write(state / "history" / f"{self.run_id}.json",
                      json.dumps({"run_id": self.run_id, "target": self.target,
                                  "finished": manifest["finished"],
                                  "entity_counts": manifest["entity_counts"]}, indent=2))
        # `current` pointer: swap ATOMICALLY (temp symlink + os.replace) so a concurrent reader never sees
        # it briefly missing between unlink and re-create.
        cur = state / "current"
        try:
            tmp = state / f".current.{os.getpid()}.tmp"
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
            os.symlink(self.dir.resolve(), tmp)
            os.replace(tmp, cur)
        except OSError:
            _atomic_write(state / "current.txt", str(self.dir.resolve()))

    @staticmethod
    def latest(project_dir: Path) -> "Run | None":
        runs_dir = Path(project_dir) / "recon"
        if not runs_dir.exists():
            return None
        candidates = sorted([d for d in runs_dir.iterdir()
                             if d.is_dir() and d.name != "state"])
        if not candidates:
            return None
        d = candidates[-1]
        # review#5: recover target from run.json when there is no manifest (a CRASHED run has run.json but no
        # final manifest) — else `latest()` mislabels a resumable run as target "unknown".
        target = "unknown"
        for meta in (d / "manifest.json", d / "run.json"):   # manifest first (richer), run.json fallback
            if meta.exists():
                try:
                    t = json.loads(meta.read_text()).get("target")
                except (OSError, json.JSONDecodeError):
                    continue
                if t:
                    target = t
                    break
        return Run.open(project_dir, target, d.name)        # C10a: OPEN (load started), never fabricate
