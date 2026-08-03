"""GADGET CANDIDATES — chain material, kept apart from findings.

    HOTLIST   things to VERIFY as findings
    GADGETS   weird primitives to REMEMBER, because step two of a chain is rarely a finding on its own

A gadget is not a vulnerability and not noise. It is a primitive: a malformed redirect, a parser quirk, a
reflected-but-unexploitable parameter, an odd auth-flow parameter. Most recon tools throw these away
because nothing can be reported from them alone — and then the chain that needed them is never built.
This is the layer-1 substrate: a `gadget_candidate` entity, a `gadgets` digest queue, and DETERMINISTIC
classifiers over evidence Quarry ALREADY holds. Nothing here contacts anything.

Three rules the classifiers obey, because a queue nobody trusts is a queue nobody reads:

  IMPACT IS NEVER CLAIMED     every record is `impact_state: none_proven`. A gadget says "this is odd and
                              might matter later", never "this is exploitable".
  SUPPRESSION IS EXPLICIT     a generic login redirect on every path is not a gadget; it is what the site
                              does. Suppression rules are named and testable, not a similarity score.
  THE EVIDENCE IS CITED       every record carries the entity it came from and that entity's raw_ref, so a
                              reviewer lands on the response, not on our summary of it.

Ranking, clustering and chain SUGGESTIONS are deliberately not here: they belong to the v0.4 relationship
layer, which will link `gadget -> host/url/param/finding/oob` and can then rank with context this layer
does not have.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from . import normalize

#: what KIND of primitive a gadget is. A class is the question "what could this become", not a severity.
CLASSES = ("redirect-parser", "auth-flow", "redirect-chain")

#: chains a class can plausibly feed. Declared per record so a reviewer (and later the relationship layer)
#: can ask "what would I even do with this" without re-deriving it.
CHAINS = ("oauth", "saml", "cache-poisoning", "redirect-chain", "waf-bypass", "request-smuggling", "ato",
          "parser-differential")

#: parameters that carry a redirect destination or an auth-flow round trip. Case-insensitive.
REDIRECT_PARAMS = ("redirect_uri", "redirect_url", "redirecturl", "redirect", "relaystate", "next",
                   "returnurl", "return_to", "returnto", "callback", "continue", "dest", "destination",
                   "goto", "target", "url", "rurl", "back", "backurl", "state")

#: path markers that put a parameter inside an AUTHENTICATION flow. Matched as complete path SEGMENTS
#: (see `_auth_context`), never as substrings: `/authorization-help` is not an auth route, and giving it
#: OAuth/SAML/ATO chain potential is how a queue fills with paths nobody will ever chain. — where a redirect primitive stops
#: being cosmetic. `mellon` and `saml2` are here because the OTC case that motivated this lane was a
#: Mellon SAML flow emitting a malformed Location.
AUTH_MARKERS = ("/oauth", "/oauth2", "/openid", "/oidc", "/saml", "/saml2", "/sso", "/login", "/signin",
                "/sign-in", "/auth", "/adfs", "/mellon", "/cas/", "/idp", "/callback", "/session",
                ".well-known/openid-configuration")

#: statuses that actually REDIRECT a client. Not the whole 3xx class: `304 Not Modified` carries cache
#: validators (and sometimes a Location) while sending nobody anywhere, `300` offers choices without
#: taking one, and `305` is a proxy instruction — treating those as redirects publishes gadgets from
#: responses that redirect nothing, and lets them count toward the suppression population.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: a Location that a client and a server can read DIFFERENTLY. Each is a parser differential in waiting.
_MALFORMED_LOCATION = (
    (re.compile(r"^https?:/(?!/)", re.I), "scheme followed by ONE slash"),
    (re.compile(r"^https?:\\\\", re.I), "scheme followed by backslashes"),
    (re.compile(r"^/{3,}"), "three or more leading slashes"),
    (re.compile(r"^\s|\s$"), "leading or trailing whitespace"),
    (re.compile(r"[\x00-\x1f\x7f]"), "control character"),
    (re.compile(r"^https?://https?://", re.I), "two stacked schemes"),
)


#: every marker as its own segment sequence, so matching is a contiguous run of complete segments.
_AUTH_SEGMENTS = tuple(tuple(s for s in m.lower().split("/") if s) for m in AUTH_MARKERS)


def _auth_context(*urls) -> bool:
    """Whether any of these URLs is INSIDE an authentication flow — judged on the PATH, by SEGMENT.

    Two ways this went wrong before. Searching the whole URL let a value create the context it was
    supposed to be judged in (`/search?next=/oauth/callback` read as an auth flow while its path is
    `/search`) — and that value is exactly what an attacker controls. Then substring matching on the path
    made `/authorization-help` an `/auth` route and `/login-assets` a `/login` one.
    """
    for url in urls:
        if not isinstance(url, str) or not url:
            continue
        try:
            segments = [s for s in urlsplit(url).path.lower().split("/") if s]
        except ValueError:
            continue
        for marker in _AUTH_SEGMENTS:
            if marker and any(tuple(segments[i:i + len(marker)]) == marker
                              for i in range(len(segments) - len(marker) + 1)):
                return True
    return False


def _is_redirect(live: dict) -> bool:
    """A REDIRECT, not merely a response carrying a `Location`.

    A `Location` on a 200 is a curiosity, not a redirect: calling it one published false gadgets and let
    five such responses satisfy the suppression population that protects real ones."""
    status, loc = live.get("status_code"), live.get("location")
    return (type(status) is int and status in REDIRECT_STATUSES
            and isinstance(loc, str) and bool(loc))


def _ours(host: str, scope) -> bool:
    """Whether a host is IN SCOPE. Observed out-of-scope behaviour stays evidence — it is simply not a
    primitive we would ever chain, and publishing it as ours invites exactly the action the RoE forbids."""
    return bool(host) and scope.in_scope(host)


def _provenance(row: dict) -> tuple[list, str]:
    """The entity's OWN sources and raw evidence. Substituting a lane name and an empty ref would land a
    reviewer on our summary instead of the response — the one thing this queue promises not to do."""
    sources = [s for s in (row.get("sources") or []) if isinstance(s, str)] or ["url-corpus"]
    ref = row.get("raw_ref") or ""
    if not ref:
        refs = row.get("raw_refs")
        ref = refs[0] if isinstance(refs, list) and refs and isinstance(refs[0], str) else ""
    return sources, str(ref)


def _host(value: str) -> str:
    try:
        return normalize.host_of_url(value) or ""
    except Exception:                                          # noqa: BLE001 - a report is never a stop
        return ""


def _record(klass: str, subtype: str, *, host: str, value: str, observed: str, why: str,
            chains: tuple, confidence: str, sources, raw_ref: str = "", url: str = "",
            param: str = "") -> dict:
    """One gadget, in the shape the digest and the future relationship layer both read."""
    return {"id": f"{klass}:{subtype}:{value}", "klass": klass, "subtype": subtype,
            "host": host, "value": value, "url": url or value, "param": param,
            "observed_behavior": observed, "why": why,
            "chain_potential": [c for c in chains if c in CHAINS],
            "confidence": confidence,
            # a gadget NEVER claims impact. The whole point is that it is interesting without being a
            # finding, and a queue that quietly promotes itself is a queue an operator stops believing.
            "impact_state": "none_proven",
            # EVERY source, not the first: an endpoint reached through katana AND gau is corroborated,
            # and dropping one is dropping the corroboration.
            "sources": [s for s in (sources if isinstance(sources, list) else [sources]) if s],
            "raw_ref": raw_ref}


def _malformed_location(live: dict) -> dict | None:
    """A `Location` two parsers can disagree about — the primitive behind redirect and auth chains."""
    if not _is_redirect(live):
        return None
    loc = live["location"]
    for pattern, why in _MALFORMED_LOCATION:
        if pattern.search(loc):
            url = live.get("url") or ""
            in_auth = _auth_context(url)
            return _record(
                "redirect-parser", "malformed-location",
                host=live.get("host") or _host(url), value=url, url=url,
                observed=f"Location: {loc!r} (status {live.get('status_code')})",
                why=f"malformed redirect — {why}; a client and a server can resolve it differently",
                chains=("parser-differential", "redirect-chain")
                + (("saml", "oauth", "ato") if in_auth else ()),
                confidence="med" if in_auth else "low",
                sources=_provenance(live)[0], raw_ref=_provenance(live)[1])
    return None


def _auth_redirect_param(row: dict, scope) -> dict | None:
    """A redirect-bearing parameter INSIDE an auth flow. Outside one it is an open-redirect candidate the
    redirect queue already owns; inside one it is where tokens get stolen."""
    url = row.get("url") or row.get("value") or ""
    if not isinstance(url, str) or not _auth_context(url):
        return None
    try:
        params = parse_qs(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return None
    hit = next((p for p in params if p.lower() in REDIRECT_PARAMS), None)
    if not hit:
        return None
    sources, ref = _provenance(row)
    return _record(
        "auth-flow", "redirect-parameter",
        host=_host(url), value=url, url=url, param=hit,
        observed=f"{hit}={(params[hit] or [''])[0][:120]!r} on an auth-flow path",
        why="a redirect destination inside an authentication flow — where a parser difference or a lax "
            "allow-list turns into token or code theft",
        chains=("oauth", "saml", "redirect-chain", "ato"),
        confidence="med", sources=sources, raw_ref=ref)


def _cross_host_redirect(live: dict, scope) -> dict | None:
    """A 3xx pointing at ANOTHER host. Observed only — Quarry never follows it to decide."""
    loc, url = live.get("location"), live.get("url") or ""
    status = live.get("status_code")
    if not _is_redirect(live) or not loc.lower().startswith(("http://", "https://")):
        return None
    src_host, dst_host = live.get("host") or _host(url), _host(loc)
    if not dst_host or dst_host == src_host:
        return None
    in_auth = _auth_context(url, loc)
    if not in_auth and scope.in_scope(dst_host):
        # an in-scope host redirecting to another in-scope host, outside any auth flow, is ordinary site
        # structure. Recording it would bury the queue in what the site simply DOES.
        return None
    return _record(
        "redirect-chain", "cross-host",
        host=src_host, value=url, url=url,
        observed=f"{status} -> {loc} (host {dst_host})",
        why="redirect leaves the origin host" + (" inside an auth flow" if in_auth else ""),
        chains=("redirect-chain", "parser-differential") + (("oauth", "saml", "ato") if in_auth else ()),
        confidence="med" if in_auth else "low",
        sources=_provenance(live)[0], raw_ref=_provenance(live)[1])


def _generic_login_redirect(lives: list) -> set:
    """Hosts whose 3xx ALWAYS lands on the same login destination.

    Explicit suppression, and the only one this layer has: a site that redirects every path to its SSO
    entry point is not offering a primitive, it is describing itself. Without this rule the queue fills
    with one row per URL on exactly the estates worth reading.
    """
    seen: dict = {}
    for live in lives:
        host = live.get("host")
        if _is_redirect(live) and isinstance(host, str):
            seen.setdefault(host, []).append(live["location"])
    # the population is REDIRECTS, not pages: counting every live row let one redirect beside four
    # ordinary responses pass as a five-sample "pattern", and that one redirect is exactly the primitive
    # this rule exists to keep.
    return {host for host, locs in seen.items() if len(set(locs)) == 1 and len(locs) >= 5}


def classify(run, scope) -> int:
    """Read what the run already holds, write `gadget_candidate` rows. Returns how many are NEW.

    Contacts nothing and probes nothing: every input is an entity another lane already produced, so this
    can never change what a run does to a target — only what the run remembers about it.
    """
    # ONE scope gate, before any classifier: the ORIGIN host decides whether a primitive is ours to
    # chain. Gating inside a single classifier left the other two publishing gadgets from out-of-scope
    # origins — observed behaviour is evidence, but it is not a primitive we would ever act on.
    lives = [live for live in run.read("live")
             if isinstance(live, dict) and _ours(live.get("host") or _host(live.get("url") or ""), scope)]
    uniform = _generic_login_redirect(lives)
    added = 0
    for live in lives:
        if live.get("host") in uniform:
            continue
        for hit in (_malformed_location(live), _cross_host_redirect(live, scope)):
            if hit and run.add("gadget_candidate", hit):
                added += 1
    for kind in ("url", "live", "endpoint"):
        for row in run.read(kind):
            if not isinstance(row, dict):
                continue
            value = row.get("url") or row.get("value") or ""
            if not isinstance(value, str) or not _ours(_host(value), scope):
                continue
            hit = _auth_redirect_param(row, scope)
            if hit and run.add("gadget_candidate", hit):
                added += 1
    return added
