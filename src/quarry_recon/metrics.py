"""Lightweight runtime telemetry → `<run_id>/metrics/summary.json`.

Data beats vibes: per-phase wall + child-CPU + inventory-at-phase (target size at that moment),
per-tool wall/status (from the manifest's tool records), and the run's long poles. No new deps —
`time.perf_counter` + `resource.getrusage(RUSAGE_CHILDREN)`. Groundwork for later concurrency
tuning (which tool is the bottleneck at what target size).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

try:
    import resource

    def rusage() -> tuple[float, int]:
        """(cumulative child CPU seconds, peak child RSS). Deltas give per-phase CPU; RSS is a
        monotonic high-water mark, so only the final value is meaningful (run-level peak).
        NOTE: `ru_maxrss` unit is platform-specific — KB on Linux (Quarry's target), bytes on macOS;
        the caller's `/1024` assumes Linux."""
        ru = resource.getrusage(resource.RUSAGE_CHILDREN)
        return ru.ru_utime + ru.ru_stime, ru.ru_maxrss
except ImportError:                                # non-unix — telemetry degrades, never breaks
    def rusage() -> tuple[float, int]:
        return 0.0, 0


def build(run, phases: list[dict], run_wall: float, run_cpu: float, peak_rss_mb: float) -> dict:
    tools = [{"phase": r.phase, "tool": r.tool, "status": r.status,
              "wall_s": round(r.duration, 2), "out_lines": r.stdout_lines,
              "cpu_s": getattr(r, "cpu_s", 0.0), "peak_rss_mb": getattr(r, "peak_rss_mb", 0.0)}
             for r in run.tool_runs()]
    long_tools = sorted(tools, key=lambda t: t["wall_s"], reverse=True)[:5]
    long_phases = sorted(phases, key=lambda p: p.get("wall_s", 0), reverse=True)[:3]
    # per-tool RAM ranking — the H3 data for concurrency budgeting (tool_RAM × workers ≤ box RAM)
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
    d = build(run, phases, run_wall, run_cpu, peak_rss_mb)
    out = run.dir / "metrics"
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(d, indent=2))
    return d
