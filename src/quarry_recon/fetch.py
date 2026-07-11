"""Shared direct-HTTP choke point for recon fetches to a TARGET.

Direct `urllib` requests bypass the guards the tool flags give nuclei/httpx/ffuf, so ONE place
enforces them for every hand-rolled fetch (evidence probes + crawl JS/sourcemap): RATELIMIT.HTTP
pacing, a bounded read, and the post-redirect FINAL-host re-check. `urlopen` follows redirects
silently — an in-scope URL can 30x OFF-scope — so the caller scope-gates the ORIGINAL host
(`scope.active_allowed`) before calling, and this re-checks the FINAL host so an off-scope body is
never read while the code thinks it's in-scope. Same rule as the boundary: unauthenticated,
in-scope, non-mutating, rate-safe.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from . import normalize

UA = "Mozilla/5.0"
DEFAULT_MAX_BODY = 2 * 1024 * 1024      # 2 MB default cap


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):     # never follow — return None so the 30x is handed back
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def redirect_location(ctx, url, origin_host=None, *, timeout=20):
    """ONE scoped request to `url` WITHOUT following redirects; returns (location_header|None, status).
    Rate-paced like scoped_get. For open-redirect probing: read WHERE the app would send us (the
    Location header) without ever fetching the attacker-controlled target — non-mutating, safe. The
    caller MUST have scope-gated the origin host already (this only touches the in-scope target)."""
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                   # RATELIMIT.HTTP -> pace to rl req/s
        time.sleep(1.0 / rl)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
            return resp.headers.get("Location"), getattr(resp, "status", 200)
    except urllib.error.HTTPError as e:       # a 4xx/5xx (or a 30x surfaced as error) still carries headers
        return e.headers.get("Location"), e.code


def scoped_get(ctx, url, origin_host=None, *, max_body=DEFAULT_MAX_BODY, timeout=20,
               data=None, method="GET", headers=None):
    """Fetch `url` with all guards. Returns (data|None, final_url, status):
      - data is None  => the FINAL host is off-scope after a redirect (caller records context, no
        body is read);
      - otherwise     => bounded body read (<= max_body+1 bytes; caller drops if len > max_body).
    Paces to profile.http_rl when set. The caller MUST have scope-gated the original host already."""
    origin = origin_host or normalize.host_of_url(url)
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                          # RATELIMIT.HTTP -> pace to rl req/s
        time.sleep(1.0 / rl)
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        final = getattr(resp, "url", None) or url
        status = getattr(resp, "status", 200)
        if normalize.host_of_url(final) != origin and not ctx.scope.active_allowed(
                normalize.host_of_url(final)):
            return None, final, status
        return resp.read(max_body + 1), final, status
