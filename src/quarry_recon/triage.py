"""Triage engine — analyst-facing prioritization with stated rationale (design §8).

Turns the structured store into ranked review queues. The vuln-class param lists and
interest buckets follow the day-2 heat-mapping methodology so the automation mirrors
the manual workflow.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from . import secrets
from .normalize import host_of_url

DIGEST_SCHEMA = "1.0"
# Canonical queue keys — ALWAYS present in the contract (empty list if nothing landed) so
# consumers can rely on a stable shape.
CANONICAL_QUEUES = ["origin", "auth", "api", "admin", "files", "xss", "idor", "ssrf", "sqli",
                    "redirect", "lfi", "rce", "ssti", "sourcemap", "takeover", "secrets", "scanner",
                    # evidence-probe surfaces (additive, same as the placeholder pattern):
                    "graphql", "actuator", "websocket", "api-base",
                    # DNS-record context (notable records only — a/cname excluded as noise):
                    "dns"]

# Notable DNS record types to surface (mail/provider/cert/network context); plain a/aaaa/cname/soa
# are excluded — a/cname already live in resolved/review, aaaa/soa are low signal for a queue.
NOTABLE_DNS_TYPES = ("mx", "ns", "txt", "caa", "asn", "cdn")


_DNS_PREVIEW_MAX = 200      # TXT (DKIM keys/SPF chains/verification blobs) can be long → preview only


def _dns_preview(value: str) -> str:
    """Cap a DNS value for the digest/HOTLIST display — the full value stays in
    normalized/dns_record.jsonl (raw_ref)."""
    return value if len(value) <= _DNS_PREVIEW_MAX else value[:_DNS_PREVIEW_MAX] + "…"


# TXT intelligence — map a needle in the TXT value to the org's provider/vendor (SPF includes +
# domain-verification tokens). OSINT pivots: which SaaS/mail/cloud a target actually uses.
_TXT_PROVIDERS = [
    ("_spf.google.com", "google-workspace"), ("google-site-verification", "google"),
    ("spf.protection.outlook.com", "microsoft-365"), ("ms=", "microsoft"),
    ("amazonses.com", "amazon-ses"), ("_amazonses", "amazon-ses"),
    ("sendgrid.net", "sendgrid"), ("mailgun.org", "mailgun"), ("spf.mandrillapp.com", "mailchimp"),
    ("_spf.salesforce.com", "salesforce"), ("zoho.com", "zoho"), ("pardot", "pardot"),
    ("facebook-domain-verification", "facebook"), ("atlassian-domain-verification", "atlassian"),
    ("stripe-verification", "stripe"), ("adobe-idp-site-verification", "adobe"),
    ("docusign", "docusign"), ("apple-domain-verification", "apple"),
    ("cisco-ci-domain-verification", "cisco"), ("citrix-verification-code", "citrix"),
]


def _txt_intel(value: str) -> list[str]:
    """Structured OSINT tags from a TXT record: mail-auth (spf/dmarc + policy), dkim, verification,
    and provider/vendor pivots (from SPF includes + verification tokens)."""
    v = value.lower()
    tags: list[str] = []
    if v.startswith("v=spf"):
        tags.append("spf")
    if v.startswith("v=dmarc"):
        tags.append("dmarc")
        m = re.search(r"\bp=(none|quarantine|reject)\b", v)
        if m:
            tags.append(f"dmarc-policy:{m.group(1)}")
    if "domainkey" in v or "dkim" in v:
        tags.append("dkim")
    if "site-verification" in v or "verification=" in v or "-verification" in v:
        tags.append("verification")
    for needle, prov in _TXT_PROVIDERS:
        if needle in v:
            tags.append(f"provider:{prov}")
    return list(dict.fromkeys(tags))               # dedup, keep order
# Reserved keys — present from M2.1 so the schema is stable, filled by tag-only classifiers
# in M2.2 (api-doc/oauth-jwt/cloud/mobile).
PLACEHOLDER_QUEUES = ["api-doc", "oauth-jwt", "cloud", "mobile"]

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

# M2.2 tag-only classifiers — simple regex over the existing URL corpus. TAG only: no parsing,
# no fetching, no enumeration, no analysis (those are later, separate items).
API_DOC_RX = re.compile(r"(/swagger|/openapi|/api-docs|/graphql\b|/gql\b|swagger\.json|"
                        r"openapi\.(?:json|ya?ml)|\.well-known/openapi)", re.I)
OAUTH_RX = re.compile(r"(/oauth2?\b|/authorize\b|/token\b|/connect/token\b|"
                      r"\.well-known/openid-configuration)", re.I)
OAUTH_PARAMS = {"code", "state", "id_token", "access_token", "redirect_uri",
                "response_type", "client_id", "scope", "nonce"}

# Query-param names whose VALUES are sensitive — the digest keeps the param name + URL
# structure but masks the value (full evidence stays in normalized/url.jsonl via raw_ref).
SENSITIVE_PARAMS = {"access_token", "id_token", "code", "state", "redirect_uri",
                    "client_secret", "token", "jwt", "assertion", "refresh_token"}


def _sanitize_url(u: str) -> str:
    if "?" not in u:
        return u
    base, qs = u.split("?", 1)
    out = []
    for kv in qs.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            if v and k.lower() in SENSITIVE_PARAMS:
                v = "***"
            out.append(f"{k}={v}")
        else:
            out.append(kv)
    return base + "?" + "&".join(out)
CLOUD_RX = re.compile(r"([a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com|s3\.amazonaws\.com/|"
                      r"storage\.googleapis\.com/|[a-z0-9-]+\.blob\.core\.windows\.net|"
                      r"[a-z0-9-]+\.r2\.cloudflarestorage\.com|gcr\.io/|[a-z0-9-]+\.azurecr\.io)", re.I)
MOBILE_RX = re.compile(r"(\.apk\b|\.ipa\b|play\.google\.com/store|apps\.apple\.com)", re.I)


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
            loc = f"  @ {s.get('file')}" if s.get("file") else ""
            A(f"- [{s.get('kind')}{verified}] {s.get('preview', '')}{loc}  (src: {','.join(s.get('sources', []))})")
        A("")

    dns_recs = [d for d in run.read("dns_record") if d.get("type") in NOTABLE_DNS_TYPES]
    if dns_recs:
        A(f"## DNS context ({len(dns_recs)} notable records — MX/NS/TXT/CAA/ASN/CDN)")
        by_t: dict[str, list] = {}
        for d in dns_recs:
            by_t.setdefault(d["type"], []).append(d)
        for t in NOTABLE_DNS_TYPES:
            items = by_t.get(t)
            if items:
                A(f"### {t.upper()}  ({len(items)})")
                for d in items[:12]:
                    A(f"- {d.get('host')} → {_dns_preview(str(d.get('value', '')))}")
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


# ── M2.1: structured digest contract (digest.json schema 1.0) ───────────────────────────
# Built from the SAME existing data as the markdown HOTLIST. Every queue item carries
# provenance (sources + raw_ref + why + confidence); values are redacted (secret previews
# only, plus a defensive redact() of our own configured keys). The new queue types are
# present as empty placeholder keys (filled by tag-only classifiers in M2.2).

def _item(type_: str, value, why: str, confidence: str, sources, raw_ref: str, tags,
          location: str | None = None) -> dict:
    val = _sanitize_url(secrets.redact(value)) if isinstance(value, str) else value
    # hash the SANITIZED value: keeps raw tokens out of the id AND dedups the same endpoint
    # that differs only by a one-time code/state.
    iid = f"{type_}:{hashlib.sha1(str(val).encode('utf-8', 'replace')).hexdigest()[:10]}"
    item = {"id": iid, "type": type_, "value": val, "why": why,
            "confidence": confidence, "sources": list(sources or []),
            "raw_ref": raw_ref, "tags": [t for t in (tags or []) if t]}
    if location:                          # evidence hint (e.g. the JS file a secret was in) —
        item["location"] = location       # distinct from raw_ref (the immutable normalized store)
    return item


def collect(run, scope) -> dict:
    """Structured digest model (inventory + clusters + queues) from existing entities only."""
    live = run.read("live")
    url_rows = run.read("url")                       # full entities → keep real provenance
    secrets_e = run.read("secret")
    findings = run.read("finding")
    reviews = run.read("review")

    queues: dict[str, list] = {q: [] for q in CANONICAL_QUEUES + PLACEHOLDER_QUEUES}
    def add(q, item):
        queues.setdefault(q, []).append(item)

    for l in live:                                  # origin (non-CDN) live hosts
        if not l.get("cdn"):
            tags = ["origin", "no-waf"] + ([str(l["status_code"])] if l.get("status_code") else [])
            add("origin", _item("origin", l["url"], "origin host (no CDN → likely no WAF)",
                                "high", l.get("sources"), "normalized/live.jsonl", tags))

    for row in url_rows:                             # interest buckets + vuln-class params
        u = row.get("url", "")
        if not u:
            continue
        src = row.get("sources")
        for k, rx in INTEREST.items():
            if rx.search(u):
                add(k, _item(k, u, f"{k} surface (path keyword)", "medium",
                             src, "normalized/url.jsonl", [k]))
        ps = _params_of(u)
        if ps:
            for cls, names in VULN_PARAMS.items():
                if any(p in names for p in ps):
                    add(cls, _item(cls, u, f"{cls} candidate param present", "low",
                                   src, "normalized/url.jsonl", [cls, "param"]))
        # M2.2 tag-only classifiers (no parse/fetch/enum)
        if API_DOC_RX.search(u):
            add("api-doc", _item("api-doc", u, "API spec/doc endpoint (tag only — not parsed)",
                                 "medium", src, "normalized/url.jsonl", ["api-doc"]))
        if OAUTH_RX.search(u) or (ps and set(ps) & OAUTH_PARAMS):
            add("oauth-jwt", _item("oauth-jwt", u,
                "OAuth/OIDC/JWT auth-flow endpoint (tag only — never test)", "medium",
                src, "normalized/url.jsonl", ["oauth-jwt", "auth"]))
        if CLOUD_RX.search(u):
            add("cloud", _item("cloud", u, "cloud-asset reference (tag only — no enumeration)",
                               "low", src, "normalized/url.jsonl", ["cloud"]))
        if MOBILE_RX.search(u):
            add("mobile", _item("mobile", u, "mobile app reference (tag only)", "low",
                                src, "normalized/url.jsonl", ["mobile"]))

    # deep-mine kinds FIRST → a richer review (e.g. graphql introspection-ENABLED) for the same URL
    # then wins on the id-dedup below (dedup keeps the last-added item).
    for ep in run.read("endpoint"):
        kind = ep.get("kind")
        if kind in ("graphql", "websocket", "api-base"):
            add(kind, _item(kind, ep.get("value"), f"{kind} endpoint (deep-mine)", "medium",
                ep.get("sources"), "normalized/endpoint.jsonl", [kind, "deep-mine"]))

    for r in reviews:                               # gf classes + sourcemap + takeover
        klass = r.get("klass", "other")
        if klass == "cname" and r.get("takeover_candidate"):
            add("takeover", _item("takeover", r.get("value"),
                "dangling CNAME → subdomain-takeover candidate", "medium",
                r.get("sources"), "normalized/review.jsonl", ["takeover"]))
        elif klass == "sourcemap":
            add("sourcemap", _item("sourcemap", r.get("value"),
                "sourcemap → fetch .map to unminify", "medium",
                r.get("sources"), "normalized/review.jsonl", ["sourcemap"]))
        elif klass in ("xss", "idor", "ssrf", "sqli", "redirect", "lfi", "rce", "ssti"):
            add(klass, _item(klass, r.get("value"), f"gf {klass} match", "low",
                r.get("sources"), "normalized/review.jsonl", [klass, "gf"]))
        elif klass == "graphql":                        # introspection probe result
            enabled = "ENABLED" in (r.get("note") or "")
            add("graphql", _item("graphql", r.get("value"), r.get("note") or "graphql endpoint",
                "high" if enabled else "low", r.get("sources"), "normalized/review.jsonl",
                ["graphql"] + (["introspection-enabled"] if enabled else [])))
        elif klass == "actuator":                       # actuator interrogation result
            note = r.get("note") or ""
            hot = r.get("priority") == "high" or "EXPOSED" in note
            add("actuator", _item("actuator", r.get("value"), note or "actuator endpoint",
                "high" if hot else "low", r.get("sources"), "normalized/review.jsonl",
                ["actuator"] + (["exposed"] if hot else ["benign"])))

    for d in run.read("dns_record"):                # notable DNS context (mail/provider/cert/network)
        t = d.get("type")
        if t not in NOTABLE_DNS_TYPES:
            continue
        val = str(d.get("value", ""))
        tags = ["dns", t] + (_txt_intel(val) if t == "txt" else [])   # tag from the FULL value
        add("dns", _item("dns", f"{d.get('host')} · {t}={_dns_preview(val)}", f"{t} record (DNS context)",
            "low", d.get("sources"), "normalized/dns_record.jsonl", tags))

    for s in secrets_e:                             # secrets (redacted — preview only)
        # preview is the redacted form; fall back to masking a legacy `data` field (pre-redaction
        # runs) so the value is never blank AND never raw.
        preview = s.get("preview") or secrets.mask(s.get("data", ""))
        add("secrets", _item("secret", preview,
            f"{s.get('kind')} secret candidate", "high" if s.get("verified") else "medium",
            s.get("sources"), "normalized/secret.jsonl",
            ["secret", s.get("kind", "")], location=s.get("file")))

    sev_conf = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
    for f in findings:                              # scanner candidates (UNCONFIRMED)
        sev = f.get("severity", "unknown")
        add("scanner", _item("finding", f.get("matched") or f.get("id"),
            f"{f.get('template')} [{sev}] — UNCONFIRMED", sev_conf.get(sev, "low"),
            f.get("sources"), "normalized/finding.jsonl", ["scanner", sev]))

    for q in queues:                                # dedup by item id (keys already canonical)
        queues[q] = list({it["id"]: it for it in queues[q]}.values())

    by_apex: dict[str, set] = {}                     # simple apex clusters from live
    for l in live:
        h = host_of_url(l["url"])
        apex = ".".join(h.split(".")[-2:]) if h and "." in h else (h or "?")
        by_apex.setdefault(apex, set()).add(l["url"])
    clusters = [{"key": apex, "type": "apex", "members": sorted(m), "signal_strength": "medium"}
                for apex, m in sorted(by_apex.items())]

    inventory = {"subdomains": run.count("subdomain"), "resolved": run.count("resolved"),
                 "live": len(live), "urls": len(url_rows), "secrets": len(secrets_e),
                 "findings": len(findings),
                 "takeover_candidates": sum(1 for r in reviews
                     if r.get("klass") == "cname" and r.get("takeover_candidate"))}
    return {"inventory": inventory, "clusters": clusters, "queues": queues}


def digest_json(run, scope) -> dict:
    """The versioned, redacted recon↔attack contract (digest.json schema 1.0)."""
    return {"digest_schema": DIGEST_SCHEMA, "target": run.target, "run_id": run.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **collect(run, scope)}
