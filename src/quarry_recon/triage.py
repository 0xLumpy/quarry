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


def _corroboration_now(run) -> dict:
    """`{path: [sources]}` as the store stands NOW.

    An observation's own `corroborated_by` is a snapshot from the moment its artifact was normalised, and
    later lanes keep publishing. Recomputing here means the report ranks on what the run actually knows,
    without rewriting evidence that was true when it was written.
    """
    from . import ast_obs, store
    out: dict = {}
    for entity in ("url", "js_url", "endpoint"):
        for rec in run.read(entity):
            if not isinstance(rec, dict):
                continue
            key = ast_obs.path_key(str(rec.get(store.ENTITY_KEYS.get(entity, "value"), "")))
            if not key:
                continue
            names = out.setdefault(key, [])
            for s in (rec.get("sources") or []):
                if isinstance(s, str) and s not in names:
                    names.append(s)
    return {k: sorted(v) for k, v in out.items()}
# Canonical queue keys — ALWAYS present in the contract (empty list if nothing landed) so
# consumers can rely on a stable shape.
CANONICAL_QUEUES = ["origin", "auth", "api", "admin", "files", "xss", "idor", "ssrf", "sqli",
                    "redirect", "lfi", "rce", "ssti", "sourcemap", "takeover", "secrets", "scanner",
                    # evidence-probe surfaces (additive, same as the placeholder pattern):
                    "graphql", "actuator", "websocket", "api-base",
                    # out-of-band callbacks imported from interactsh (OOB.3; uncorrelated in Phase 1):
                    "oob",
                    # path-like strings an AST pass read out of JS bundles: EVIDENCE with a ranking,
                    # never a queue of things to fetch (`ast_obs.priority_view`):
                    "path_observations",
                    # chain MATERIAL, deliberately separate from every queue above: those rank things to
                    # VERIFY, this remembers primitives that are not findings on their own (`gadgets.py`):
                    "gadgets",
                    # DNS-record context (notable records only — a/cname excluded as noise):
                    "dns",
                    # name-based virtual hosts served by an origin IP (may not resolve in DNS):
                    "vhost",
                    # framework debug/admin endpoints reachable (tech-conditional probe):
                    "debug",
                    # serialized-object / token format fingerprints (deser attack surface):
                    "deser",
                    # framework CVE/primitive reference for fingerprinted tech (attack-layer handoff):
                    "tech-intel"]

_FW_CVE: dict | None = None


#: what each review class actually IS, so the report never implies we probed something we observed.
_REVIEW_LABELS = {
    "sourcemap": "fetch .map -> unminified source",
    "related-host": "PASSIVE off-scope evidence — observed, never actively expanded",
    "dns-owner-name": "PASSIVE DNS owner evidence (not a hostname) — never actively expanded",
}


def _framework_cve() -> dict:
    """Load + cache the framework → CVE/primitive REFERENCE map (data/framework-cve.yaml). Best-effort:
    missing/malformed yields {} (no tech-intel annotations). Recon fires nothing from this — it is
    pure context for the attack/AI layer."""
    global _FW_CVE
    if _FW_CVE is None:
        import yaml
        from pathlib import Path
        p = Path(__file__).resolve().parent / "data" / "framework-cve.yaml"
        try:
            _FW_CVE = yaml.safe_load(p.read_text()) or {}
        except Exception:
            _FW_CVE = {}
    return _FW_CVE

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
        # rua/ruf report-address domains = org/vendor pivots (a shared rua across domains implies
        # the same org — a lightweight slice of reverse-DMARC; the full reverse index is deferred).
        for rm in re.finditer(r"(?:rua|ruf)=([^;]+)", v):
            for addr in rm.group(1).split(","):
                dom = addr.strip().replace("mailto:", "").split("@")[-1].strip().rstrip(".")
                if dom and "." in dom:
                    tags.append(f"rua:{dom}")
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
        _conf = sum(1 for f in findings if f.get("confirmed"))
        _hdr = (f"## Scanner findings — {_conf} confirmed · {len(findings) - _conf} candidate (UNCONFIRMED, "
                f"manual validation required)" if _conf else
                f"## Scanner candidates ({len(findings)}) — UNCONFIRMED, manual validation required")
        A(_hdr)
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

    oob_rows = run.read("oob_interaction")
    if oob_rows:
        by_proto: dict[str, int] = {}
        for o in oob_rows:
            by_proto[o.get("protocol", "?")] = by_proto.get(o.get("protocol", "?"), 0) + 1
        proto = ", ".join(f"{k}:{v}" for k, v in sorted(by_proto.items()))
        ncorr = sum(1 for o in oob_rows if o.get("correlation") == "correlated")
        A(f"## OOB interactions ({len(oob_rows)}) — {ncorr} correlated, {len(oob_rows) - ncorr} uncorrelated  [{proto}]")
        A("> correlated = a Quarry-issued callback named its source/param; uncorrelated = imported/stray evidence (no attribution)")
        for o in oob_rows[:25]:
            if o.get("correlation") == "correlated":
                A(f"- [{o.get('protocol')}] CORRELATED {o.get('payload_class')} <- {o.get('source_tool')} "
                  f"(param {o.get('param')} on {o.get('target_url')})")
            else:
                dom = o.get("interaction_domain") or o.get("correlation_id") or o.get("id")
                A(f"- [{o.get('protocol')}] {dom}  from {o.get('remote_address', '?')}  (uncorrelated)")
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
        # review-B1.5br4#3: the class headings became truthful while this one still said every queue was
        # a gf bucket or a source map. Some of them are evidence Quarry OBSERVED and will not act on.
        A(f"## Review queues ({len(reviews)}) — candidates and passive evidence")
        for klass in sorted(by_klass):
            items = sorted(set(by_klass[klass]))
            # every non-sourcemap class was labelled "gf match", which is wrong for anything that did
            # not come from a gf bucket — and actively misleading for PASSIVE evidence, which an operator
            # must not read as something Quarry probed.
            label = _REVIEW_LABELS.get(klass, "gf match")
            A(f"### {klass.upper()}  ({len(items)}) — {label}")
            for v in items[:15]:
                A(f"- {v}")
            if len(items) > 15:
                # B1.5b: a DISPLAY may be bounded; the stored evidence never is. Say so, or a reader
                # takes the preview for the whole queue — which is how a cap hides in plain sight.
                A(f"- … {len(items) - 15} more — full list in normalized/review.jsonl")
            A("")

    gadgets = [g for g in run.read("gadget_candidate") if isinstance(g, dict)]
    if gadgets:
        A(f"## Gadgets ({len(gadgets)}) — chain material, NOT findings")
        A("> Primitives that prove nothing on their own: malformed redirects, auth-flow redirect "
          "parameters, cross-host hops. Keep them for step two of a chain — never report one as an "
          "impact. Nothing here was probed; every row is evidence another lane already collected.\n")
        by_klass: dict[str, list] = {}
        for g in gadgets:
            by_klass.setdefault(g.get("klass") or "other", []).append(g)
        for klass in sorted(by_klass):
            rows = by_klass[klass]
            A(f"### {klass.upper()}  ({len(rows)})")
            for g in rows[:10]:
                chains = ", ".join(g.get("chain_potential") or []) or "unclassified"
                A(f"- {g.get('value')} — {g.get('observed_behavior')}  ·  chains: {chains}")
            if len(rows) > 10:
                A(f"- … {len(rows) - 10} more — full list in normalized/gadget_candidate.jsonl")
            A("")

    obs = [o for o in run.read("path_observation") if isinstance(o, dict)]
    if obs:
        from . import ast_obs
        top = ast_obs.priority_view(obs, _corroboration_now(run))
        A(f"## Path observations ({len(obs)}) — evidence, {len(top)} prioritised")
        A("> Path-like strings an AST pass read out of JS bundles. NOT endpoints and NOT findings: "
          "nothing here was requested, and no lane fetches one because it appeared. The prioritised "
          "subset is plausible + api-shaped and excludes assets, other origins, dev-server calls, MIME "
          "values, package specifiers and tz entries — a ranking over evidence, never a promotion.\n")
        fresh = _corroboration_now(run)
        for o in top[:15]:
            seen = sum(s.get("n", 0) for s in (o.get("sightings") or []) if isinstance(s, dict))
            who = ", ".join(ast_obs.corroborators(o, fresh)) or "ast only"
            A(f"- {o.get('id')}  ·  x{seen}  ·  {who}")
        if len(top) > 15:
            # a DISPLAY may be bounded; the stored evidence never is
            A(f"- … {len(top) - 15} more prioritised — full list in normalized/path_observation.jsonl")
        if len(obs) > len(top):
            A(f"- ({len(obs) - len(top)} further observation(s) kept as evidence, not prioritised)")
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
        else:                                        # CDN/WAF-fronted host — tag it as such (A2)
            cn = l.get("cdn_name") or "cdn"
            add("origin", _item("origin", l["url"], f"CDN/WAF-fronted host ({cn}) — origin hidden",
                                "low", l.get("sources"), "normalized/live.jsonl",
                                [t for t in ("cdn-fronted", cn, "waf") if t]))

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
        elif klass == "cloud":                          # enumerated cloud bucket (verify-ownership)
            add("cloud", _item("cloud", r.get("value"), r.get("note") or "cloud bucket candidate",
                "low", r.get("sources"), "normalized/review.jsonl",
                [t for t in ("cloud", r.get("provider"), r.get("access"), "verify-ownership") if t]))
        elif klass == "vhost":                          # name-based vhost on an origin IP (verify)
            add("vhost", _item("vhost", r.get("value"), r.get("note") or "vhost candidate",
                "low", r.get("sources"), "normalized/review.jsonl",
                [t for t in ("vhost", r.get("ip"), str(r.get("status_code") or ""), "verify") if t]))
        elif klass == "debug":                          # framework debug/admin endpoint reachable
            exposed = "EXPOSED" in (r.get("note") or "")
            add("debug", _item("debug", r.get("value"), r.get("note") or "framework debug endpoint",
                "high" if exposed else "low", r.get("sources"), "normalized/review.jsonl",
                [t for t in ("debug", r.get("framework"), "exposed" if exposed else "protected") if t]))
        elif klass == "deser":                          # serialized-object / token format fingerprint
            add("deser", _item("deser", r.get("value"), r.get("note") or "deserialization surface",
                "medium", r.get("sources"), "normalized/review.jsonl",
                [t for t in ("deser", r.get("format"), "attack-surface") if t]))
        elif klass == "origin-ip":                      # A2 candidate origin IP behind a CDN (verify)
            add("origin", _item("origin", r.get("value"), r.get("note") or "candidate origin IP",
                "medium", r.get("sources"), "normalized/review.jsonl",
                [t for t in ("origin-ip", r.get("channel"), "verify-ownership") if t]))

    # framework CVE/primitive REFERENCE annotation — recon fires NOTHING from this; it hands the
    # attack/AI layer "this tech is present → here's what's known to try" (provenance = the interface).
    techblob = " ".join(str(t.get("tech", "")).lower() for t in run.read("tech"))
    if techblob:
        for name, spec in _framework_cve().items():
            if not isinstance(spec, dict) or not any(
                    str(m).lower() in techblob for m in (spec.get("match") or [])):
                continue
            intel = [str(x) for x in (spec.get("intel") or [])]
            add("tech-intel", _item("tech-intel", name,
                "known primitives (attack-layer reference): " + "; ".join(intel[:6]),
                "low", ["framework-fingerprint"], "normalized/tech.jsonl",
                ["tech-intel", name, "reference"]))

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

    for o in run.read("oob_interaction"):           # OOB callbacks — CORRELATED (P2) or UNCORRELATED (P1)
        proto = o.get("protocol", "?")
        dom = o.get("interaction_domain") or o.get("correlation_id") or o.get("id")
        if o.get("correlation") == "correlated":    # Quarry-issued token named the source -> specific tags
            pc = o.get("payload_class") or "oob"
            why = (f"out-of-band interaction — CORRELATED to {o.get('source_tool')} "
                   f"(param {o.get('param') or '?'} on {o.get('target_url') or '?'})")
            tags = [t for t in ["oob", proto, pc, "correlated", o.get("source_tool")] if t]
        else:                                       # Phase-1 import / stray callback — no attribution
            why = "out-of-band interaction — UNCORRELATED (no source attribution until a Quarry-issued token matches)"
            tags = ["oob", proto, "unknown-oob", "external-service-interaction", "uncorrelated"]
        add("oob", _item("oob_interaction", f"{proto} · {dom} · from {o.get('remote_address', '?')}",
            why, "candidate", o.get("sources"), "normalized/oob_interaction.jsonl", tags,
            location=o.get("raw_ref")))

    # ── GADGETS: chain material, never a finding ────────────────────────────────────────────────
    # Deliberately its own queue. Every queue above ranks things to VERIFY; this one remembers primitives
    # that are worthless alone and decisive as step two — and mixing them would teach a reviewer to skim
    # both. `impact_state` rides along so a consumer can never mistake one for a claim.
    for g in run.read("gadget_candidate"):
        if not isinstance(g, dict):
            continue
        chains = [c for c in (g.get("chain_potential") or []) if isinstance(c, str)]
        add("gadgets", _item("gadget_candidate", g.get("value"),
            f"{g.get('why') or g.get('klass')} — observed: {g.get('observed_behavior') or 'n/a'}",
            g.get("confidence") or "low", g.get("sources"), "normalized/gadget_candidate.jsonl",
            ["gadget", g.get("klass"), g.get("subtype"),
             f"impact:{g.get('impact_state') or 'none_proven'}"]
            + [f"chain:{c}" for c in chains],
            location=g.get("raw_ref") or None))

    # ── PATH OBSERVATIONS: prioritised EVIDENCE, never a queue of things to fetch ────────────────
    # Its own queue for the same reason gadgets have one: everything above ranks things to VERIFY, and
    # these are strings a parser read out of a bundle. `impact_state` and the "observation" tag ride
    # along so no consumer — including a v0.4 skill — can mistake one for a claim that the route exists.
    from . import ast_obs as _ast_obs
    _obs = [o for o in run.read("path_observation") if isinstance(o, dict)]
    _fresh = _corroboration_now(run)
    for o in _ast_obs.priority_view(_obs, _fresh):
        who = _ast_obs.corroborators(o, _fresh)
        seen = sum(s.get("n", 0) for s in (o.get("sightings") or []) if isinstance(s, dict))
        add("path_observations", _item(
            "path_observation", o.get("id"),
            f"path-like string read out of {len(o.get('bundles') or []) or 1} JS bundle(s), seen {seen}x"
            + (f" — corroborated by {', '.join(who)}" if who else " — not seen by any other tool"),
            "candidate", o.get("sources"), "normalized/path_observation.jsonl",
            ["observation", "path", "impact:none_proven"] + sorted(o.get("tags") or [])
            + [f"corroborated:{w}" for w in who],
            location=o.get("raw_ref") or None))

    for q in queues:                                # dedup by item id (keys already canonical)
        queues[q] = list({it["id"]: it for it in queues[q]}.values())

    by_apex: dict[str, set] = {}                     # simple apex clusters from live
    for l in live:
        h = host_of_url(l["url"])
        apex = ".".join(h.split(".")[-2:]) if h and "." in h else (h or "?")
        by_apex.setdefault(apex, set()).add(l["url"])
    clusters = [{"key": apex, "type": "apex", "members": sorted(m), "signal_strength": "medium"}
                for apex, m in sorted(by_apex.items())]

    # findings are scanner output: split confirmed vs candidate so a bare "findings" number never presents
    # UNCONFIRMED scanner candidates (all confirmed:false today) as if they were confirmed findings.
    _confirmed = sum(1 for f in findings if f.get("confirmed"))
    inventory = {"subdomains": run.count("subdomain"), "resolved": run.count("resolved"),
                 "live": len(live), "urls": len(url_rows), "secrets": len(secrets_e),
                 "confirmed_findings": _confirmed,
                 "scanner_candidates": len(findings) - _confirmed,
                 "findings_total": len(findings),
                 "takeover_candidates": sum(1 for r in reviews
                     if r.get("klass") == "cname" and r.get("takeover_candidate"))}
    return {"inventory": inventory, "clusters": clusters, "queues": queues}


def digest_json(run, scope) -> dict:
    """The versioned, redacted recon↔attack contract (digest.json schema 1.0)."""
    return {"digest_schema": DIGEST_SCHEMA, "target": run.target, "run_id": run.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **collect(run, scope)}
