"""Lightweight runtime telemetry → `<run_id>/metrics/summary.json`.

Per-phase wall + child-CPU + inventory-at-phase, per-tool wall/status (from the manifest's tool
records), and the run's long poles, via `time.perf_counter` + `resource.getrusage(RUSAGE_CHILDREN)`.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

try:
    import resource

    def rusage() -> tuple[float, int]:
        """(cumulative child CPU seconds, peak child RSS). RSS is a monotonic high-water mark, so
        only the final value is meaningful. `ru_maxrss` is KB on Linux (assumed) / bytes on macOS."""
        ru = resource.getrusage(resource.RUSAGE_CHILDREN)
        return ru.ru_utime + ru.ru_stime, ru.ru_maxrss
except ImportError:                                # non-unix — telemetry degrades, never breaks
    def rusage() -> tuple[float, int]:
        return 0.0, 0


def build(run, phases: list[dict], run_wall: float, run_cpu: float, peak_rss_mb: float) -> dict:
    tools = [{"phase": r.phase, "tool": r.tool, "status": r.status,
              "wall_s": round(r.duration, 2), "out_lines": r.stdout_lines,
              # -1.0 means unmeasured (ran concurrently — getrusage delta unattributable); render null, not 0
              "cpu_s": (None if getattr(r, "cpu_s", 0.0) < 0 else getattr(r, "cpu_s", 0.0)),
              "peak_rss_mb": getattr(r, "peak_rss_mb", 0.0)}
             for r in run.tool_runs()]
    long_tools = sorted(tools, key=lambda t: t["wall_s"], reverse=True)[:5]
    long_phases = sorted(phases, key=lambda p: p.get("wall_s", 0), reverse=True)[:3]
    # per-tool RAM ranking — concurrency-budgeting data (tool_RAM × workers ≤ box RAM)
    heavy_rss = sorted((t for t in tools if t["peak_rss_mb"]),
                       key=lambda t: t["peak_rss_mb"], reverse=True)[:5]
    return {
        "run_id": run.run_id, "target": run.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {"wall_s": round(run_wall, 2), "child_cpu_s": round(run_cpu, 2),
                   "peak_rss_mb": round(peak_rss_mb, 1), "tool_runs": len(tools)},
        "phases": phases,
        "tools": tools,
        "long_poles": {
            "tools": [{"tool": t["tool"], "wall_s": t["wall_s"]} for t in long_tools],
            "phases": [{"phase": p["phase"], "wall_s": p.get("wall_s", 0)} for p in long_phases],
            "rss": [{"tool": t["tool"], "peak_rss_mb": t["peak_rss_mb"]} for t in heavy_rss],
        },
    }


def write(run, phases, run_wall, run_cpu, peak_rss_mb) -> dict:
    from .state import ContractError
    from .store import MutationScope
    state = run.state
    if state == "finished":
        raise ContractError(
            f"run {run.run_id} is finished — reopen it (`finalizing`) before rewriting metrics",
        )
    if state in {"created", "running"}:
        scope = MutationScope.BASE_EVIDENCE
    elif state in {"finalizing", "finalization_failed"}:
        scope = MutationScope.FINALIZATION_METADATA
    else:
        raise ContractError(f"metrics are unavailable in run state {state!r}")
    d = build(run, phases, run_wall, run_cpu, peak_rss_mb)
    run._replace_artifact(
        scope, ("metrics", "summary.json"), json.dumps(d, indent=2).encode("utf-8"),
    )
    return d
