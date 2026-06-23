"""Triage engine — analyst-facing prioritization with stated rationale (design §8).

Turns the structured store into ranked review queues. The vuln-class param lists and
interest buckets follow the day-2 heat-mapping methodology so the automation mirrors
the manual workflow.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .normalize import host_of_url

# Common vuln-class param lists (XSS/IDOR/SSRF/SQLi).
VULN_PARAMS = {
    "xss": ["q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords",
            "year", "view", "email", "type", "name", "p", "month", "image", "url",
            "terms", "categoryid", "key", "login"],
    "idor": ["id", "user", "account", "number", "order", "no", "doc", "key", "email",
             "group", "profile", "edit"],
    "ssrf": ["dest", "redirect", "uri", "path", "continue", "url", "window", "next",
             "data", "reference", "site", "html", "val", "validate", "domain",
             "callback", "return", "page", "feed", "host", "port", "to", "out",
             "view", "dir", "show", "navigation", "open"],
    "sqli": ["id", "select", "report", "role", "update", "query", "user", "name",
             "sort", "where", "search", "params", "process", "row", "view", "table",
             "from", "sel", "results", "sleep", "fetch", "order", "keyword", "column",
             "field", "delete", "string", "number", "filter"],
}

INTEREST = {
    "auth":  re.compile(r"/(login|logon|signin|auth|saml|oauth|sso|register|password|token)(/|\?|$)", re.I),
    "api":   re.compile(r"/(api|rest|graphql|gql|v[0-9]+|swagger|openapi|actuator)(/|\?|$)", re.I),
    "admin": re.compile(r"/(admin|manage|console|dashboard|internal|debug|staging|private)(/|\?|$)", re.I),
    "files": re.compile(r"/(upload|file|export|download|import|attachment|document|backup)(/|\?|$)", re.I),
}


def _params_of(url: str) -> list[str]:
    q = url.split("?", 1)[1] if "?" in url else ""
    out = []
    for kv in q.split("&"):
        if "=" in kv:
            out.append(kv.split("=", 1)[0].lower())
    return out


def build(run, scope) -> str:
    live = run.read("live")
    urls = run.values("url")
    subs = run.count("subdomain")
    resolved = run.count("resolved")
    secrets = run.read("secret")

    # origin (non-CDN) hosts = juicier (no WAF)
    origins = [l for l in live if not l.get("cdn")]
    # interest buckets over url corpus
    buckets = {k: sorted({u for u in urls if rx.search(u)}) for k, rx in INTEREST.items()}
    # vuln-class param classification
    vuln_urls = {k: [] for k in VULN_PARAMS}
    for u in urls:
        ps = _params_of(u)
        if not ps:
            continue
        for cls, names in VULN_PARAMS.items():
            if any(p in names for p in ps):
                vuln_urls[cls].append(u)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = []
    A = out.append
    A(f"# {run.target} — Recon HOTLIST")
    A(f"_run {run.run_id} · {ts}_\n")
    A("## Inventory")
    A(f"- subdomains: {subs}  resolved: {resolved}  live: {len(live)}  urls: {len(urls)}")
    A(f"- origin (non-CDN) live hosts: {len(origins)}  secrets: {len(secrets)}\n")

    findings = run.read("finding")
    if findings:
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        findings.sort(key=lambda f: sev_rank.get(f.get("severity", "unknown"), 5))
        A(f"## Scanner candidates ({len(findings)}) — UNCONFIRMED, manual validation required")
        for f in findings[:30]:
            A(f"- [{f.get('severity')}] {f.get('template')} @ {f.get('matched')}  (src: {','.join(f.get('sources', []))})")
        A("")

    if origins:
        A("## Likely-origin hosts (no CDN → no WAF, test first)")
        for l in origins[:40]:
            A(f"- {l['url']}  [{l.get('status_code')}] {l.get('title') or ''} "
              f"{','.join(l.get('tech') or [])}")
        A("")

    for name, label in [("auth", "Auth / SSO / register"),
                        ("api", "API / GraphQL / versioned"),
                        ("admin", "Admin / internal / debug"),
                        ("files", "Upload / file / export")]:
        items = buckets[name]
        if items:
            A(f"## {label}  ({len(items)})")
            for u in items[:25]:
                A(f"- {u}")
            A("")

    for cls in ("idor", "ssrf", "sqli", "xss"):
        items = sorted(set(vuln_urls[cls]))
        if items:
            A(f"## {cls.upper()} candidate params  ({len(items)}) — common-vuln params present")
            for u in items[:20]:
                A(f"- {u}")
            A("")

    if secrets:
        A(f"## Secret candidates ({len(secrets)}) — review before any validation")
        for s in secrets[:25]:
            verified = " VERIFIED" if s.get("verified") else ""
            A(f"- [{s.get('kind')}{verified}] {str(s.get('data'))[:100]}  (src: {','.join(s.get('sources', []))})")
        A("")

    # gf / sourcemap candidates (review entities)
    reviews = run.read("review")
    by_klass: dict[str, list[str]] = {}
    for r in reviews:
        by_klass.setdefault(r.get("klass", "other"), []).append(r.get("value", ""))
    if reviews:
        A(f"## Candidate queues ({len(reviews)}) — gf buckets / source maps")
        for klass in sorted(by_klass):
            items = sorted(set(by_klass[klass]))
            label = "fetch .map -> unminified source" if klass == "sourcemap" else "gf match"
            A(f"### {klass.upper()}  ({len(items)}) — {label}")
            for v in items[:15]:
                A(f"- {v}")
            A("")

    A("## Review order")
    A("1. secrets — exports/secrets.jsonl")
    A("2. origin hosts above (no WAF)")
    A("3. auth + api + admin buckets")
    A("4. IDOR/SSRF/SQLi/XSS param candidates")
    A("5. screenshots (gowitness) for visual anomalies")
    A("\n> Every item traces to normalized/*.jsonl with provenance. Nothing here is a")
    A("> confirmed finding — these are ranked manual-validation queues.")
    return "\n".join(out) + "\n"
