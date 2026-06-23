"""Export layer — disposable flat-file views over the structured store (design §9).

These exist purely for compatibility with existing manual habits (grep, Burp import).
The JSONL store remains the source of truth; exports can be regenerated anytime.
"""
from __future__ import annotations


def _write(run, name: str, lines) -> int:
    p = run.exports / name
    items = sorted(set(x for x in lines if x))
    p.write_text("\n".join(items) + ("\n" if items else ""))
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

    # new-since-previous-run: diff against the most recent *other* run in the project
    import json
    from pathlib import Path
    runs_dir = Path(run.project_dir) / "recon"
    prev = sorted([d for d in runs_dir.iterdir()
                   if d.is_dir() and d.name not in (run.run_id, "state")])
    if prev:
        prev_subs_file = prev[-1] / "exports" / "subdomains.txt"
        if prev_subs_file.exists():
            prev_set = set(prev_subs_file.read_text().split())
            cur_set = set(run.values("subdomain"))
            new = sorted(cur_set - prev_set)
            gone = sorted(prev_set - cur_set)
            out.append(f"\n## vs previous run ({prev[-1].name})")
            out.append(f"- new subdomains: {len(new)}")
            out.append(f"- disappeared: {len(gone)}")
            for h in new[:50]:
                out.append(f"  + {h}")
    (run.reports / "delta.md").write_text("\n".join(out) + "\n")


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
        (run.exports / "secrets.jsonl").write_text(
            "\n".join(json.dumps(s, ensure_ascii=False) for s in secrets) + "\n")
        counts["secrets.jsonl"] = len(secrets)
    return counts
