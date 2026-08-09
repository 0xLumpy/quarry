"""Gadget candidates — chain material, kept apart from findings.

A gadget is a primitive, not a vulnerability and not noise: a malformed redirect, a parser quirk, a
reflected-but-unexploitable parameter, an odd auth-flow parameter — step two of a chain, rarely a finding
on its own. This module holds the `gadget_candidate` entity, the `gadgets` digest queue, and deterministic
classifiers over evidence Quarry already holds. It contacts nothing.

Three rules the classifiers obey:

  impact is never claimed     every record is `impact_state: none_proven`;
  suppression is explicit     suppression rules are named and testable, not a similarity score;
  the evidence is cited       every record carries the source entity and its raw_ref.

Ranking, clustering and chain suggestions belong to the future relationship layer, which links
`gadget -> host/url/param/finding/oob` with context this layer does not have.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from . import normalize

#: what kind of primitive a gadget is — the question "what could this become", not a severity.
CLASSES = ("redirect-parser", "auth-flow", "redirect-chain")

#: chains a class can plausibly feed, declared per record so a reviewer need not re-derive it.
CHAINS = ("oauth", "saml", "cache-poisoning", "redirect-chain", "waf-bypass", "request-smuggling", "ato",
          "parser-differential")

#: parameters that carry a redirect destination or an auth-flow round trip. Case-insensitive.
REDIRECT_PARAMS = ("redirect_uri", "redirect_url", "redirecturl", "redirect", "relaystate", "next",
                   "returnurl", "return_to", "returnto", "callback", "continue", "dest", "destination",
                   "goto", "target", "url", "rurl", "back", "backurl", "state")

#: path markers that put a parameter inside an authentication flow. Matched as complete path segments
#: (see `_auth_context`), never as substrings, so `/authorization-help` is not an `/auth` route.
AUTH_MARKERS = ("/oauth", "/oauth2", "/openid", "/oidc", "/saml", "/saml2", "/sso", "/login", "/signin",
                "/sign-in", "/auth", "/adfs", "/mellon", "/cas/", "/idp", "/callback", "/session",
                ".well-known/openid-configuration")

#: statuses that actually redirect a client — not the whole 3xx class. 304, 300 and 305 carry a Location
#: (or cache validators) without sending a client anywhere.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: a Location that a client and a server can read differently — a parser differential in waiting.
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
    """Whether any of these URLs is inside an authentication flow — judged on the path, by segment.

    Only the path is examined, so an attacker-controlled query value (`/search?next=/oauth/callback`)
    cannot create the context it is judged in; segments must match whole, so `/authorization-help` is not
    an `/auth` route.
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
    """A redirect, not merely a response carrying a `Location` (a `Location` on a 200 is neither)."""
    status, loc = live.get("status_code"), live.get("location")
    return (type(status) is int and status in REDIRECT_STATUSES
            and isinstance(loc, str) and bool(loc))


def _ours(host: str, scope) -> bool:
    """Whether a host is in scope. Out-of-scope behaviour stays evidence but is not a primitive we chain."""
    return bool(host) and scope.in_scope(host)


def _provenance(row: dict) -> tuple[list, str]:
    """The entity's own sources and raw evidence, so a reviewer lands on the response, not our summary."""
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
            # a gadget never claims impact
            "impact_state": "none_proven",
            # every source, not the first: an endpoint reached through katana and gau is corroborated
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
    """A redirect-bearing parameter inside an auth flow. Outside one it is an open-redirect candidate the
    redirect queue already owns."""
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
    """A 3xx pointing at another host. Observed only — Quarry never follows it to decide."""
    loc, url = live.get("location"), live.get("url") or ""
    status = live.get("status_code")
    if not _is_redirect(live) or not loc.lower().startswith(("http://", "https://")):
        return None
    src_host, dst_host = live.get("host") or _host(url), _host(loc)
    if not dst_host or dst_host == src_host:
        return None
    in_auth = _auth_context(url, loc)
    if not in_auth and scope.in_scope(dst_host):
        # in-scope -> in-scope outside any auth flow is ordinary site structure
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
    """Hosts whose 3xx always lands on the same login destination — a site that redirects every path to
    its SSO entry point is describing itself, not offering a primitive. The only suppression rule here.
    """
    seen: dict = {}
    for live in lives:
        host = live.get("host")
        if _is_redirect(live) and isinstance(host, str):
            seen.setdefault(host, []).append(live["location"])
    # the population is redirects, not pages
    return {host for host, locs in seen.items() if len(set(locs)) == 1 and len(locs) >= 5}


def classify(run, scope) -> int:
    """Read what the run already holds, write `gadget_candidate` rows, returning how many are new.

    Contacts nothing and probes nothing: every input is an entity another lane already produced.
    """
    # one scope gate before any classifier: the origin host decides whether a primitive is ours to chain
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
