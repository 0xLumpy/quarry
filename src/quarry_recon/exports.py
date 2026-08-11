"""Export layer — disposable flat-file views over the structured store (design §9).

These exist purely for compatibility with existing manual habits (grep, Burp import).
The JSONL store remains the source of truth; exports can be regenerated anytime.
"""
from __future__ import annotations

from . import privfs


def _write(run, name: str, lines) -> int:
    p = run.exports / name
    items = sorted(set(x for x in lines if x))
    privfs.write_private(p, "\n".join(items) + ("\n" if items else ""))
    return len(items)


def write_delta(run) -> None:
    """delta.md — per-source contribution + new-since-previous-run (comm -23 style)."""
    subs = run.read("subdomain")
    # per-source contribution (first-writer-wins => sole-source approximates 'new from X')
    by_src: dict[str, int] = {}
    for s in subs:
        for src in s.get("sources", ["?"]):
            by_src[src] = by_src.get(src, 0) + 1

    out = [f"# {run.target} — Delta  (run {run.run_id})\n", "## Subdomain source contribution"]
    for src, n in sorted(by_src.items(), key=lambda kv: -kv[1]):
        out.append(f"- {src}: {n}")

    # diff against this run's immediate chronological predecessor (none if this run isn't located)
    from .store import Run
    ordered = Run.list_runs(run.project_dir)
    names = [d.name for d in ordered]
    prev_dir = None
    if run.run_id in names:
        i = names.index(run.run_id)
        prev_dir = ordered[i - 1] if i > 0 else None
    if prev_dir:
        prev_subs_file = prev_dir / "exports" / "subdomains.txt"
        if prev_subs_file.exists():
            prev_set = set(prev_subs_file.read_text().split())
            cur_set = set(run.values("subdomain"))
            new = sorted(cur_set - prev_set)
            gone = sorted(prev_set - cur_set)
            out.append(f"\n## vs previous run ({prev_dir.name})")
            out.append(f"- new subdomains: {len(new)}")
            out.append(f"- disappeared: {len(gone)}")
            for h in new[:50]:
                out.append(f"  + {h}")
    privfs.write_private(run.reports / "delta.md", "\n".join(out) + "\n")


def write_all(run) -> dict[str, int]:
    counts = {}
    counts["subdomains.txt"] = _write(run, "subdomains.txt", run.values("subdomain"))
    counts["resolved.txt"] = _write(run, "resolved.txt", run.values("resolved"))
    counts["live.txt"] = _write(run, "live.txt", run.values("live"))
    counts["urls.txt"] = _write(run, "urls.txt", run.values("url"))
    counts["js_urls.txt"] = _write(run, "js_urls.txt", run.values("js_url"))
    counts["endpoints.txt"] = _write(run, "endpoints.txt", run.values("endpoint"))
    counts["parameters.txt"] = _write(run, "parameters.txt", run.values("parameter"))

    # secrets.jsonl — copy through as-is (structured)
    secrets = run.read("secret")
    if secrets:
        import json
        # full discovered secret values — written 0600, never a group/other-readable export
        privfs.write_private(run.exports / "secrets.jsonl",
                             "\n".join(json.dumps(s, ensure_ascii=False) for s in secrets) + "\n")
        counts["secrets.jsonl"] = len(secrets)
    return counts
