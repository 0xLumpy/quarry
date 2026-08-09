"""Normalising an ast-analyzer artifact into `path_observation` evidence.

An observation is a path-like string the analyzer found plus what is needed to judge it later: where it
came from, what the surrounding source said, how often it appeared, whether a tool Quarry already runs
corroborates it, and deterministic tags describing its shape. The tags are descriptive: `api-shaped`
says a path looks like an application route, never that the route exists.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

#: analyzers whose matches are path-like; DOM sources and sinks are a separate observation type below
PATH_ANALYZERS = frozenset(("robust-paths", "fetch", "fetch-options", "graphql", "http-methods"))

_TRAILING = re.compile(r"[)\]\}>,;'\"]+$")
#: characters that mean the string is a pattern or an expression, not a path
_META = frozenset("*?[]()|\\{}^$+<>")

ASSET_SUFFIXES = (".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".svg", ".gif",
                  ".woff", ".woff2", ".ttf", ".ico", ".webp", ".mp4", ".json", ".wasm", ".avif")
#: segments that read like an application route — a prioritisation signal, not a promotion rule
API_WORDS = frozenset(("api", "v1", "v2", "v3", "graphql", "gql", "rest", "auth", "oauth", "login",
                       "admin", "user", "users", "account", "accounts", "token", "session", "upload",
                       "download", "search", "config", "callback", "webhook", "internal"))
#: the tz database is a large, recognisable family of non-paths (`/Africa/Nairobi`)
_TZ_ROOTS = frozenset(("Africa", "America", "Asia", "Europe", "Australia", "Pacific", "Antarctica",
                       "Atlantic", "Indian", "Arctic", "Etc"))
#: `type/subtype` — a MIME value is not a route
_MIME_TYPES = frozenset(("application", "audio", "font", "image", "message", "model", "multipart",
                         "text", "video"))


def path_key(value: str, *, host_prefixed: bool = False) -> str | None:
    """Compare and store endpoints by path — source-aware, case-preserving, None when unusable.

    A relative path written in source (`api/users`) keeps every segment; only a producer that emits
    `host/path` (`host_prefixed`) may drop a leading host. Case is preserved, as `/API` and `/api` are
    different resources to a server.
    """
    if not isinstance(value, str):
        return None
    v = value.strip().strip("'\"`")
    v = _TRAILING.sub("", v)
    if not v or len(v) > 512 or any(c in v for c in " \t\n<>"):
        return None
    if "://" in v:
        v = urlsplit(v).path or "/"
    elif v.startswith("//"):
        v = urlsplit("https:" + v).path or "/"
    else:
        v = v.split("?", 1)[0].split("#", 1)[0]
        if host_prefixed and not v.startswith("/") and "/" in v:
            head, _, rest = v.partition("/")
            v = "/" + rest if "." in head else "/" + v
        elif not v.startswith("/"):
            v = "/" + v
    v = v.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
    if not v.startswith("/") or v in ("/", "/.", "/./"):
        return None
    while "/./" in v:
        v = v.replace("/./", "/")
    v = v.replace("//", "/")
    return v if v != "/" else None


def plausible(key: str) -> bool:
    """Whether the string is a path at all, rather than a regex fragment, a placeholder template or a
    single character. Nothing is dropped by this: it only tags, and the raw artifact keeps everything."""
    if not key or any(c in _META for c in key):
        return False
    segs = [s for s in key.strip("/").split("/") if s]
    if not segs or len(segs) > 8:
        return False
    if any(s.lower().startswith("expr") for s in segs):
        return False
    return any(len(s) >= 3 and any(c.isalpha() for c in s) and not s.isdigit() for s in segs)


#: default ports, so `https://acme.com` and `https://acme.com:443` are one origin
_DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def origin_of(url: str, *, default_scheme: str = "https") -> tuple | None:
    """`(scheme, host, effective port)` — the origin, not the hostname; None when there is no host.
    A protocol-relative value inherits `default_scheme`, which is what a browser does with it."""
    if not isinstance(url, str) or not url.strip():
        return None
    u = url.strip()
    if u.startswith("//"):
        u = f"{default_scheme}:{u}"
    parts = urlsplit(u)
    host = (parts.hostname or "").lower()
    if not host:
        return None
    scheme = (parts.scheme or default_scheme).lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    return scheme, host, port or _DEFAULT_PORT.get(scheme, 0)


def position(start) -> tuple:
    """`(line, column)` from an analyzer match — a real int each, or None. Bools and out-of-range
    values are rejected, so a broken artifact is never persisted as a position."""
    if not isinstance(start, dict):
        return None, None
    ln, col = start.get("line"), start.get("column")
    if not isinstance(ln, int) or isinstance(ln, bool) or ln < 1:
        ln = None
    if not isinstance(col, int) or isinstance(col, bool) or col < 0:
        col = None
    return ln, col


def classify(key: str, raw_value: str, origin=None) -> list:
    """Deterministic shape tags — descriptive, ordered, never a verdict: implausible, asset, external,
    localhost, mime, module, tz-database, api-shaped."""
    tags: list = []
    segs = [s for s in key.strip("/").split("/") if s]
    val = raw_value if isinstance(raw_value, str) else ""
    if not plausible(key):
        tags.append("implausible")
    if key.lower().endswith(ASSET_SUFFIXES):
        tags.append("asset")
    bare = val.strip().strip("'\"`")
    if "://" in bare or bare.startswith("//"):
        here = origin if isinstance(origin, tuple) else origin_of(origin or "")
        there = origin_of(bare, default_scheme=(here[0] if here else "https"))
        # external = a different origin (scheme, host, effective port), not merely an absolute URL
        if there and (here is None or there != here):
            tags.append("external")
        host = there[1] if there else ""
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
            tags.append("localhost")
    if len(segs) == 2 and segs[0].lower() in _MIME_TYPES and "." not in segs[0]:
        tags.append("mime")
    if key.startswith("/@") or (segs and segs[0].startswith("@")):
        tags.append("module")
    if segs and segs[0] in _TZ_ROOTS:
        tags.append("tz-database")
    if any(s.lower() in API_WORDS for s in segs):
        tags.append("api-shaped")
    return tags


def observations(doc, *, bundle: str, bundle_digest: str, bundle_url: str, artifact: str,
                 corroborated=None, context=None) -> list:
    """Every path-like match in one artifact, as `path_observation` records.

    Records are keyed by the path; repeated sightings union their provenance instead of duplicating.
    """
    out: dict = {}
    corroborated = corroborated or {}
    origin = origin_of(bundle_url or "")
    for m in (doc if isinstance(doc, list) else []):
        if not isinstance(m, dict) or m.get("analyzerName") not in PATH_ANALYZERS:
            continue
        extra = m.get("extra") if isinstance(m.get("extra"), dict) else {}
        key = path_key(extra.get("pathname") or m.get("value", ""))
        if not key:
            continue
        rec = out.get(key)
        if rec is None:
            rec = out[key] = {
                "id": key, "value": key, "sources": ["jxscout-ast"],
                "tags": classify(key, m.get("value", ""), origin),
                "analyzers": [], "bundles": [bundle], "bundle_digests": [bundle_digest],
                "raw_ref": artifact, "discovered_from": bundle_url,
                # per bundle, and summed by the consumer: the store unions lists but keeps differing
                # scalars as alternates, so one `occurrences` number would merge as "3, alt 2"
                "sightings": [{"bundle": bundle, "digest": bundle_digest, "n": 0}],
                "sites": [],
                "corroborated_by": list(corroborated.get(key, ())),   # who corroborates this path
            }
        rec["sightings"][0]["n"] += 1
        name = m.get("analyzerName")
        if name and name not in rec["analyzers"]:
            rec["analyzers"].append(name)
        if len(rec["sites"]) < 3:                 # a few representative sites, not the whole file
            line, col = position(m.get("start"))
            rec["sites"].append({"bundle": bundle, "line": line,
                                 "column": col, "analyzer": name,
                                 "value": str(m.get("value", ""))[:200],
                                 "context": (context(m) if context else "")[:240]})
    return list(out.values())


# ── the high-priority view ──────────────────────────────────────────────────────────────
#: shape tags that keep an observation out of the endpoint queue; kept in the evidence, not prioritised
EXCLUDED_TAGS = frozenset(("asset", "external", "localhost", "mime", "module", "tz-database"))


def high_priority(record) -> bool:
    """Whether a `path_observation` belongs in the prioritised view: `api-shaped`, not `implausible`,
    and carrying no excluded tag.

    Prioritisation, not promotion — nothing here says the route exists, nothing is requested because it
    matched, and no entity is created. Rows left out stay stored, queryable and in the raw artifact.
    """
    if not isinstance(record, dict):
        return False
    tags = set(record.get("tags") or [])
    if "api-shaped" not in tags or "implausible" in tags:
        return False
    return not (tags & EXCLUDED_TAGS)


def corroborators(record, fresh=None) -> list:
    """Who corroborates this path — the record's stored snapshot unioned with a fresher map when given.
    A union, never a replacement: a resumed observation's snapshot names runs this store never held."""
    names = list(record.get("corroborated_by") or [])
    if isinstance(fresh, dict):
        for s in fresh.get(str(record.get("id", "")), ()) or ():
            if s not in names:
                names.append(s)
    return names


def priority_view(records, fresh=None) -> list:
    """The prioritised rows, most-corroborated first, then most-sighted, then stable by path.
    Corroboration orders but never gates: a path only this analyzer found still appears."""
    rows = [r for r in records if high_priority(r)]
    return sorted(rows, key=lambda r: (-len(corroborators(r, fresh)),
                                       -sum(s.get("n", 0) for s in (r.get("sightings") or [])
                                            if isinstance(s, dict)),
                                       str(r.get("id", ""))))


# ── DOM sources and sinks ───────────────────────────────────────────────────────────────
#: analyzer -> role, by the analyzer's own name. Coarse: where a source or sink is, not that they connect
SINK_ROLES = {
    "inner-html": "sink", "dangerouslySetInnerHTML": "sink", "eval": "sink",
    "window-open": "sink", "document-domain": "sink", "postmessage": "sink",
    "location": "source", "url-search-params": "source", "window-name": "source",
    "onhashchange": "source", "onmessage": "source",
    # storage is both input and output; the analyzer's own tags (`property-getItem` etc.) say which
    "local-storage": "storage", "session-storage": "storage", "cookie": "storage",
    "add-event-listener": "channel",
    "regex": "informational", "regex-match": "informational", "hostname": "informational",
}
#: the DOM data-flow surface — everything but the informational families, which are context and
#: dominate the raw count
FLOW_ROLES = frozenset(("sink", "source", "storage", "channel"))


def sink_observations(doc, *, bundle: str, bundle_digest: str, bundle_url: str, artifact: str,
                      context=None) -> list:
    """Every DOM source/sink match in one artifact, as `sink_observation` records.

    Keyed by (analyzer, matched text), so the same construct in two bundles is one observation with two
    sightings. Only the data-flow roles are normalised; the informational ones stay in the raw artifact,
    which is digest-bound and remains the complete record.
    """
    import hashlib
    out: dict = {}
    for m in (doc if isinstance(doc, list) else []):
        if not isinstance(m, dict):
            continue
        name = m.get("analyzerName")
        role = SINK_ROLES.get(name)
        if role not in FLOW_ROLES:
            continue
        full = " ".join(str(m.get("value", "")).split())   # one line: a match can span a formatted block
        if not full:
            continue
        # the identity is the complete value; only the stored preview is capped, so two minified
        # expressions sharing their first 400 characters stay distinct
        key = hashlib.sha256(f"{name}\x00{full}".encode()).hexdigest()[:16]
        value = full[:400]
        rec = out.get(key)
        if rec is None:
            rec = out[key] = {
                "id": key, "value": value, "value_len": len(full), "truncated": len(full) > 400,
                "sources": ["jxscout-ast"], "analyzer": name, "role": role,
                "tags": [role] + sorted(m.get("tags") or {}),
                "bundles": [bundle], "bundle_digests": [bundle_digest],
                "raw_ref": artifact, "discovered_from": bundle_url,
                "sightings": [{"bundle": bundle, "digest": bundle_digest, "n": 0}],
                "sites": [],
            }
        rec["sightings"][0]["n"] += 1
        for tag in sorted(m.get("tags") or {}):
            if tag not in rec["tags"]:
                rec["tags"].append(tag)
        if len(rec["sites"]) < 3:
            line, col = position(m.get("start"))
            rec["sites"].append({"bundle": bundle, "line": line, "column": col,
                                 "context": (context(m) if context else "")[:240]})
    return list(out.values())


def flow_view(records) -> list:
    """The DOM data-flow rows, most-sighted first, then stable. The role filter is what keeps an
    informational row from an older run out of the ranking."""
    rows = [r for r in records
            if isinstance(r, dict) and r.get("role") in FLOW_ROLES]
    return sorted(rows, key=lambda r: (-sum(s.get("n", 0) for s in (r.get("sightings") or [])
                                            if isinstance(s, dict)),
                                       str(r.get("analyzer", "")), str(r.get("id", ""))))
