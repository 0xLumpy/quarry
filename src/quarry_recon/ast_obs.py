"""Normalising an ast-analyzer artifact into `path_observation` evidence.

COLLECT ONCE, INTERPRET LATER (notes/current/AST-ANALYZER-LANE-DESIGN.md). An observation is a
path-like string the analyzer found, with everything needed to judge it later: where it came from, what
the surrounding source said, how often it appeared, whether a tool Quarry already runs corroborates it,
and deterministic TAGS describing its shape.

The tags are descriptive, never promotion. `api-shaped` says a path looks like an application route on
this corpus; it does not say the route exists. Two rows from the POAB sample are the standing reminder
that no string rule can finish this job: `/masterdata/uas/brands` is a React-Query cache key whose real
request hides behind `A.listBrands()`, and `/admin/companies` is a fragment of
`` `/api/${t?"admin/companies":"operator"}/${id}/logo` ``. Following either needs code analysis, which is
the v0.4 skill layer's work — this module's job is to preserve them faithfully until then.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

#: analyzers whose matches are path-like. The rest (DOM sources and sinks) are a separate observation
#: type — step 6 — and are not silently folded in here.
PATH_ANALYZERS = frozenset(("robust-paths", "fetch", "fetch-options", "graphql", "http-methods"))

_TRAILING = re.compile(r"[)\]\}>,;'\"]+$")
#: characters that mean the string is a pattern or an expression, not a path
_META = frozenset("*?[]()|\\{}^$+<>")

ASSET_SUFFIXES = (".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".svg", ".gif",
                  ".woff", ".woff2", ".ttf", ".ico", ".webp", ".mp4", ".json", ".wasm", ".avif")
#: segments that read like an application route on the corpora measured so far. DESCRIPTIVE — this is
#: the bucketing from the labelled sample, and it is a prioritisation signal, not a promotion rule.
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
    """Compare and store endpoints by PATH — SOURCE-AWARE, and case-preserving.

    A relative path written in source (`api/users`) keeps every segment: treating any value containing a
    slash as `host/path` amputated the first one, which manufactured agreement between tools and destroyed
    the api-shaped signal. Only a producer that emits `host/path` may drop a leading host. The path keeps
    its CASE, because `/API` and `/api` are different resources to a server and Quarry's own
    canonicalisation preserves path case deliberately.
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
    """Whether the string is a PATH at all, as opposed to a regex fragment, a placeholder template or a
    single character. Measured on the labelled sample: of 21 implausible rows, 0 were endpoints — so this
    costs no recall, and everything it drops is still in the raw artifact."""
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
    """`(scheme, host, effective port)` — the ORIGIN, not the hostname.

    A host comparison alone called `http://acme.com:9000/api` same-origin with a bundle from
    `https://acme.com:8443`, which is a different service. A protocol-relative value inherits the
    bundle's scheme, which is what a browser does with it.
    """
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
    """`(line, column)` from an analyzer match — REAL integers or nothing.

    `bool` is an `int` in Python, and a dict or a string reaches slice arithmetic, so a broken artifact
    could both crash a reader and be persisted as evidence. Validated once, here, for every consumer.
    """
    if not isinstance(start, dict):
        return None, None
    ln, col = start.get("line"), start.get("column")
    if not isinstance(ln, int) or isinstance(ln, bool) or ln < 1:
        ln = None
    if not isinstance(col, int) or isinstance(col, bool) or col < 0:
        col = None
    return ln, col


def classify(key: str, raw_value: str, origin=None) -> list:
    """Deterministic SHAPE tags. Descriptive, ordered, and never a verdict.

    What these are for is prioritisation and, later, exclusion from an endpoint queue: a static asset, an
    external service, a localhost dev call, a MIME value, a package specifier and a protobuf type are all
    real strings a bundle contains, and none of them is an application route on the target.
    """
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
        # EXTERNAL means a different ORIGIN — scheme, host and effective port — not merely an absolute
        # URL. `https://app.acme/api/users` in a bundle served from app.acme is the target's own route,
        # and tagging it external would exclude it from exactly the view it belongs in.
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

    EVERY readable one: the expensive work — the analysis — is already paid and its artifact published, so
    stopping short here would produce a partial view of work that succeeded. Records are keyed by the
    path, and repeated sightings union their provenance rather than creating duplicates.
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
                # PER BUNDLE, because the store unions lists and treats differing scalars as ALTERNATES:
                # a scalar `occurrences` merged 3 and 2 into "3, alt 2" rather than 5. A consumer sums
                # these; nothing has to guess what a single number meant.
                "sightings": [{"bundle": bundle, "digest": bundle_digest, "n": 0}],
                "sites": [],
                # WHO corroborates THIS path — not the whole corroborated set, which put thousands of
                # unrelated paths in one row and still named nobody.
                "corroborated_by": list(corroborated.get(key, ())),
            }
        rec["sightings"][0]["n"] += 1
        name = m.get("analyzerName")
        if name and name not in rec["analyzers"]:
            rec["analyzers"].append(name)
        if len(rec["sites"]) < 3:                 # a few representative sites, not the whole file
            line, col = position(m.get("start"))   # VALIDATED: a broken position is not persisted
            rec["sites"].append({"bundle": bundle, "line": line,
                                 "column": col, "analyzer": name,
                                 "value": str(m.get("value", ""))[:200],
                                 "context": (context(m) if context else "")[:240]})
    return list(out.values())
