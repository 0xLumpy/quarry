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
from pathlib import Path

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


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    def __init__(self, project_dir: Path, target: str, run_id: str | None = None):
        self.project_dir = Path(project_dir)
        self.target = target
        self.run_id = run_id or time.strftime("%Y%m%d-%H%M%S")
        self.dir = self.project_dir / "recon" / self.run_id
        self.raw = self.dir / "raw"
        self.normalized = self.dir / "normalized"
        self.exports = self.dir / "exports"
        self.reports = self.dir / "reports"
        for d in (self.raw, self.normalized, self.exports, self.reports):
            d.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.dir / "manifest.json"
        self._tool_runs: list[ToolRunRecord] = []
        self._counts_cache: dict[str, int] = {}
        self._seen: dict[str, set] = {}   # entity -> seen keys (instance-local; no cross-run bleed)
        self.started = _utc()
        self.notes: list[str] = []

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
        """Append a normalized entity if its natural key is new. Returns True if added."""
        key_field = ENTITY_KEYS.get(entity, "value")
        key = str(record.get(key_field, "")).strip().lower()
        if not key:
            return False
        existing = self._seen_keys(entity)
        if key in existing:
            return False
        record.setdefault("first_seen", _utc())
        with self._entity_file(entity).open("a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        existing.add(key)
        self._counts_cache[entity] = self._counts_cache.get(entity, 0) + 1
        return True

    def _seen_keys(self, entity: str) -> set:
        if entity not in self._seen:
            keys = set()
            f = self._entity_file(entity)
            if f.exists():
                key_field = ENTITY_KEYS.get(entity, "value")
                for line in f.read_text().splitlines():
                    try:
                        keys.add(str(json.loads(line).get(key_field, "")).strip().lower())
                    except json.JSONDecodeError:
                        continue
            self._seen[entity] = keys
        return self._seen[entity]

    def read(self, entity: str) -> list[dict]:
        f = self._entity_file(entity)
        if not f.exists():
            return []
        out = []
        for line in f.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def count(self, entity: str) -> int:
        return len(self._seen_keys(entity))

    def values(self, entity: str) -> list[str]:
        key_field = ENTITY_KEYS.get(entity, "value")
        return [str(r.get(key_field, "")) for r in self.read(entity) if r.get(key_field)]

    # ── manifest ──
    def _run_summary(self) -> dict:
        """Per-run reliability rollup for the manifest: tool status counts + the 'what failed' list + a
        run VERDICT and a GAPS list. A degraded run must NEVER read as a clean success — `tools_failed`
        only counts hard FAILED, so partial/blocked/timed_out sources were invisible in the headline.
        `gaps` names every such source with its preserved-evidence line count (a blocked chunk still kept
        real output), and `verdict` is `complete_with_gaps` whenever any source failed OR degraded.
        `note`/`stderr_tail` were already redacted by record(); phase_exceptions are redacted here so no
        free-text bypasses the manifest secret choke point."""
        from . import secrets
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
        phase_exceptions = [secrets.redact(n) for n in self.notes if "EXCEPTION" in n]
        verdict = ("complete_with_gaps" if (failures or gaps or phase_exceptions) else "complete")
        return {"verdict": verdict, "tool_status": status_counts, "tools_failed": len(failures),
                "failures": failures, "gaps": gaps, "phase_exceptions": phase_exceptions}

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
        self.manifest_path.write_text(json.dumps(manifest, indent=2))
        # update state pointers (per-project, under recon/)
        state = self.project_dir / "recon" / "state"
        (state / "history").mkdir(parents=True, exist_ok=True)
        (state / "history" / f"{self.run_id}.json").write_text(
            json.dumps({"run_id": self.run_id, "target": self.target,
                        "finished": manifest["finished"],
                        "entity_counts": manifest["entity_counts"]}, indent=2))
        cur = state / "current"
        try:
            if cur.is_symlink() or cur.exists():
                cur.unlink()
            os.symlink(self.dir.resolve(), cur)
        except OSError:
            (state / "current.txt").write_text(str(self.dir.resolve()))

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
        manifest = d / "manifest.json"
        target = "unknown"
        if manifest.exists():
            try:
                target = json.loads(manifest.read_text()).get("target", "unknown")
            except json.JSONDecodeError:
                pass
        return Run(project_dir, target, run_id=d.name)
