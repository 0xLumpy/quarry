"""Read-only rendering views for the control plane — two renderers, no execution and no scheduling.

- ``plan_lines()`` — a static dry-run: folds the registry (`sources`) plus machine settings into a
  per-phase account of what would run. It never calls the runner.
- ``status_lines()`` — folds ``events.jsonl`` into current/last-known per-source state.

One line per source. Imports neither ``runner`` nor ``contract``.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import settings, sources

# Canonical pipeline order for grouping; unknown phases sort last (stable).
_PHASE_ORDER = ("horizontal", "vertical", "dns", "origin", "probe",
                "enrich", "crawl", "params", "content")


def _phase_rank(p: str) -> int:
    return _PHASE_ORDER.index(p) if p in _PHASE_ORDER else len(_PHASE_ORDER)


def plan_lines(nuclei_plan: dict | None = None) -> list[str]:
    """Static dry-run: what would run, derived from the registry plus machine settings. No execution.
    ``workers`` prefers the source's contract value, else the machine-scaled ``settings.workers``;
    ``rate`` (per-target RoE) and ``timeout`` come from the contract when declared."""
    srcs = sources.all_sources()
    run = off = key = pend = ret = dbt = 0
    lines = ["quarry plan — static (registry + machine settings; nothing is executed)"]
    phases = sorted({s.get("phase", "?") for s in srcs.values()}, key=_phase_rank)
    for ph in phases:
        ids = sorted(sid for sid, s in srcs.items() if s.get("phase") == ph)
        if not ids:
            continue
        lines.append("")
        lines.append(f"[{ph}]")
        for sid in ids:
            s = srcs[sid]
            d = s.get("default", "off")
            pending = s.get("pending")
            retired = s.get("retired")
            if retired:
                ret += 1; mark = "⊘"      # retired: no code routes through it
                note = f"  (retired: {retired})"
            elif pending:
                pend += 1; mark = "◔"     # declared but not wired yet
                note = f"  (pending: {pending})"
            elif d == "on":
                run += 1; mark = "▶"      # will run
                note = ""
            elif d == "key":
                key += 1; mark = "◆"      # needs key
                note = f"  ({s['reason']})" if s.get("reason") else ""
            else:
                off += 1; mark = "·"      # off
                note = f"  ({s['reason']})" if s.get("reason") else ""
            tool = s.get("tool", "?")
            w = s.get("workers") or settings.workers(tool, 0) or "-"
            rate = s.get("rate", "-")
            to = s.get("timeout", "-")
            longpole = "  ⏳bounded" if s.get("bounded") == "planned" and not (pending or retired) else ""
            debt = s.get("debt")
            if debt:
                dbt += 1
                note = f"{note}  ⚠debt: {debt}"
            name = sid.split(".", 1)[-1]
            lines.append(f"  {mark} {name:<22} {s.get('tier','?'):<12} {s.get('class','?'):<8} "
                         f"w={str(w):<4} rate={str(rate):<5} to={str(to):<6}{longpole}{note}")
    lines.append("")
    dbt_txt = f" · {dbt} control-debt" if dbt else ""
    lines.append(f"summary: {run} will run · {pend} pending (not wired) · {ret} retired · {off} off · "
                 f"{key} need key{dbt_txt}   (default-on includes bounded long-poles; off = setup/lane/intent)")
    if nuclei_plan is not None:
        lines.extend(["", "[accepted Nuclei / OOB policy]"])
        modes = nuclei_plan["modes"]
        lines.append(
            f"  snapshot={nuclei_plan['snapshot']} · corpus-trust={nuclei_plan['corpus_trust']} · "
            f"oob={modes['oob_backend']} · private-target-block="
            f"{str(modes['block_private_targets']).lower()}"
        )
        for owner in nuclei_plan["owners"]:
            selected = owner["selected_count"]
            selected_text = "snapshot-required" if selected is None else str(selected)
            counts = owner["semantic_counts"]
            semantic_text = ("snapshot-required" if counts is None else
                             ",".join(f"{name}={counts[name]}" for name in sorted(counts)))
            lines.append(
                f"  {owner['owner']}: oob-enabled={str(owner.get('oob_enabled', owner['oob_backend'] != 'off')).lower()} "
                f"· oob={owner['oob_backend']} · selected={selected_text} · "
                f"semantic={semantic_text}"
            )
            for label in ("potentially_state_changing", "unknown"):
                refs = owner[label]
                if refs:
                    lines.append(
                        f"    {label}: "
                        + ", ".join(f"{row['id']}@{row['path']}" for row in refs)
                    )
        for channel in nuclei_plan["channels"]:
            channel_enabled = channel.get("enabled", channel["oob_backend"] not in {"off"})
            lines.append(
                f"  {channel['owner']}: oob-enabled={str(channel_enabled).lower()} "
                f"· oob={channel['oob_backend']}"
            )
    return lines


# event-only states (no terminal status carried) → a human state for the status surface. Coverage events
# are absent by design: coverage is telemetry, and its truth is the manifest's summary.coverage/verdict.
_HUMAN = {"tool_start": "running", "tool_progress": "running",
          "tool_blocked": "blocked", "artifact_written": "running", "tool_finish": "done"}


def _fold_events(path: Path) -> dict:
    """Collapse the append-only event log to the latest known state per source_id. Later events win;
    terminal status, ledger produced/consumed, blocked/partial reasons and progress carry forward."""
    state: dict[str, dict] = {}
    # explicit utf-8: Windows would else read UTF-8 payloads in the codepage.
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        sid = e.get("source_id")
        if not sid:
            continue
        if e.get("event") in ("coverage_partial", "coverage_reset"):
            continue                       # telemetry, never a lifecycle status
        st = state.setdefault(sid, {})
        if e.get("event") == "ledger":     # carries produced/consumed, but is not a lifecycle terminal
            for k in ("produced", "consumed"):
                if e.get(k) is not None:
                    st[k] = e[k]
            continue                       # last_event unset, so tool_finish stays the terminal
        st["last_event"] = e.get("event", st.get("last_event"))
        if e.get("ts") is not None:
            st["ts"] = e["ts"]
        for k in ("status", "duration", "reason", "produced", "consumed", "exit_code", "rss",
                  "current_index", "input_total", "chunk_index", "chunk_total"):
            if e.get(k) is not None:
                st[k] = e[k]
    return state


def status_lines(events_path) -> list[str]:
    """Render current/last-known per-source state from events.jsonl. Degrades gracefully when the
    file is absent (no run yet / wrapper not wired to phases until step 4)."""
    p = Path(events_path)
    if not p.exists():
        return [f"no events recorded yet ({p}).",
                "  the run_contract wrapper is not wired to phases until step 4 — nothing has emitted "
                "events yet."]
    state = _fold_events(p)
    if not state:
        return [f"events file present but empty ({p})."]
    lines = [f"quarry status — {p}", ""]
    for sid in sorted(state):
        st = state[sid]
        # a terminal status wins; otherwise the raw event name maps to a human state.
        status = st.get("status") or _HUMAN.get(st.get("last_event"), st.get("last_event") or "?")
        # a chunked source reports both chunk and input counts: show both (`chunk 4/10 · 150/491 complete`).
        prog = ""
        if st.get("chunk_total") is not None:
            prog = f"chunk {st.get('chunk_index', '?')}/{st['chunk_total']}"
            if st.get("input_total") is not None:
                prog += f" · {st.get('current_index', '?')}/{st['input_total']} complete"
        elif st.get("input_total") is not None:
            prog = f"{st.get('current_index', '?')}/{st['input_total']}"
        dur = st.get("duration")
        detail = prog or (f"{dur}s" if dur is not None else "-")
        parts = [f"{k}={st[k]}" for k in ("produced", "consumed") if st.get(k) is not None]
        pc = ("  " + " ".join(parts)) if parts else ""
        reason = f"  — {st['reason']}" if st.get("reason") else ""
        lines.append(f"  {sid:<28} {status:<10} {detail:<12}{pc}{reason}")
    return lines
