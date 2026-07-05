"""Cloud-asset discovery — candidate bucket enumeration (S3 + GCS) from the target's apex/org.

Map-don't-exploit + verify-ownership: DETECT bucket existence + public/private (unauth, non-mutating
GET, **status only — no content is read, downloaded, or modified**), emit candidates for human
confirmation. A guessed name is NOT proof of ownership — items are review candidates tagged
"VERIFY OWNERSHIP", same model as the OSINT RDAP/azmap candidates. Azure *tenancy* is handled
separately (azmap in osint); this is object storage only.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request

# common bucket-name patterns around a seed (apex label / org / brand).
_SUFFIXES = ["", "-backup", "-backups", "-dev", "-staging", "-prod", "-assets", "-static",
             "-media", "-uploads", "-data", "-logs", "-config", "-public", "-private",
             "-files", "-cdn", "-images", "-app", "-test", "-archive", "-internal", "-storage"]
_MAX_NAMES = 120
_PROVIDERS = [
    ("s3", lambda n: f"https://{n}.s3.amazonaws.com/"),
    ("gcs", lambda n: f"https://storage.googleapis.com/{n}/"),
]


def _seeds(profile) -> set:
    s = set()
    for a in profile.apex_domains:
        lbl = a.split(".")[0]
        if lbl:
            s.add(lbl)
    for name in list(getattr(profile, "org_names", []) or []) + list(getattr(profile, "brands", []) or []):
        cleaned = re.sub(r"[^a-z0-9]", "", str(name).lower())
        if cleaned:
            s.add(cleaned)
    return s


def _candidates(profile) -> list:
    out = set()
    for seed in _seeds(profile):
        for suf in _SUFFIXES:
            out.add(f"{seed}{suf}")
    return sorted(out)[:_MAX_NAMES]


def _check(url: str, timeout: int = 8):
    """Return (exists, access). GET status ONLY — the body is never read (non-mutating; no content
    is touched). 200 = exists/public-listable · 403 = exists/private · else = not found."""
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return True, "public" if getattr(r, "status", 200) == 200 else "unknown"
    except urllib.error.HTTPError as e:
        return (True, "private") if e.code == 403 else (False, None)
    except Exception:
        return False, None


def discover(ctx) -> int:
    """Enumerate S3/GCS bucket candidates from the target's apex/org and record the ones that exist
    as `cloud` review candidates (verify-ownership). Returns the count found. Skipped in passive."""
    if ctx.profile.passive_only:
        return 0
    found = 0
    for n in _candidates(ctx.profile):
        for prov, urlf in _PROVIDERS:
            url = urlf(n)
            exists, access = _check(url)
            if exists and ctx.run.add("review", {
                    "id": f"cloud:{url}", "klass": "cloud", "value": url,
                    "provider": prov, "access": access,
                    "note": f"{prov} bucket exists ({access}) — VERIFY OWNERSHIP",
                    "sources": ["cloud-enum"]}):
                found += 1
    return found
