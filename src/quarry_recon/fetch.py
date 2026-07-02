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
import urllib.request

from . import normalize

UA = "Mozilla/5.0"
DEFAULT_MAX_BODY = 2 * 1024 * 1024      # 2 MB default cap


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
