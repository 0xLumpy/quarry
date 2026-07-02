"""Recon-layer evidence extraction — fetch exposed, in-scope, UNAUTHENTICATED, NON-MUTATING
resources and extract secrets from them.

This is the map/attack boundary in code form (Lumpy, 2026-07-02): the rule is not "don't touch
anything," it's **"don't accidentally perform impact."** Recon MAY collect evidence from
unauthenticated, in-scope, non-mutating access — so an exposed `.env` / `.git/config` / config file
is GET-fetched and its secret read + recorded (redacted). Recon MUST NOT send attack payloads, use
the found credentials, change state, bypass controls, or prove exploit impact — that's quarry-attack.
"""
from __future__ import annotations

import hashlib
import re
import urllib.request

from . import normalize, secrets

# Exposed files worth fetching: secret/config stores, VCS metadata, key material, dumps.
SENSITIVE_FILE_RX = re.compile(r"""
    /(?:
        \.env(?:\.[\w.-]+)?                         # .env .env.local .env.production
      | \.git/config | \.git/HEAD | \.git/credentials
      | \.aws/credentials | \.s3cfg | \.netrc | \.htpasswd | \.dockercfg | \.npmrc | \.pypirc
      | config\.(?:json|ya?ml|php|inc) | settings\.py | secrets\.ya?ml | wp-config\.php
      | \.DS_Store
      | id_rsa | id_dsa | id_ecdsa | id_ed25519 | [\w.-]+\.pem
      | (?:db|database|dump|backup)\.sql
    )(?:$|\?)
""", re.IGNORECASE | re.VERBOSE)

# Provider-shaped / structured tokens. lastindex group (if any) is the value, else the whole match.
_TOKEN_RX = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws-secret-key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+]{40})")),
    ("github-pat",     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("stripe-secret",  re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("slack-token",    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt",            re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("private-key",    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

# dotenv / config assignment `KEY = value`; captures a secret-looking VALUE on a secret-looking KEY.
_DOTENV_RX = re.compile(r"""(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*[=:]\s*['"]?([^'"\r\n#]{6,}?)['"]?\s*$""")
_SECRETISH_KEY = re.compile(r"(?i)(key|secret|token|pass|pwd|api|auth|cred|private|access)")

MAX_BODY = 2 * 1024 * 1024    # 2 MB cap per exposed resource (RAM/disk guard)
MAX_FETCHES = 50              # bound how many exposed resources we fetch


def mine(text: str) -> list[tuple[str, str, int]]:
    """(kind, raw_value, line) for each secret found in `text`. Read-only — no exploit.
    Provider-shaped tokens win over the generic dotenv catch for the same value (more specific)."""
    out: list[tuple[str, str, int]] = []
    seen_vals: set[str] = set()
    for kind, rx in _TOKEN_RX:
        for m in rx.finditer(text):
            val = m.group(m.lastindex) if m.lastindex else m.group(0)
            out.append((kind, val, text.count("\n", 0, m.start()) + 1))
            seen_vals.add(val)
    for m in _DOTENV_RX.finditer(text):
        key, val = m.group(1), m.group(2).strip()
        if _SECRETISH_KEY.search(key) and val not in seen_vals:   # already caught as a typed token
            seen_vals.add(val)
            out.append((f"dotenv:{key}", val, text.count("\n", 0, m.start()) + 1))
    return out


def fetch_exposed(ctx, urls: list[str]) -> int:
    """GET each exposed in-scope resource (non-mutating), save the body as evidence, extract +
    store secrets (redacted) with provenance. Returns count of NEW secret entities added."""
    added = 0
    for u in urls[:MAX_FETCHES]:
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):     # in-scope + not-passive + not-OOS
            continue
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=20) as resp:
                final = getattr(resp, "url", None) or u
                status = getattr(resp, "status", 200)
                # urlopen follows redirects silently — an in-scope URL can land OFF-scope. Re-check
                # the FINAL host before reading the body, so we never extract an off-scope resource
                # while thinking it's in-scope. Redirects are useful recon data: record, don't hide.
                final_host = normalize.host_of_url(final)
                if final_host != host and not ctx.scope.active_allowed(final_host):
                    ctx.run.add("review", {
                        "id": f"exposed-redirect:{u}", "klass": "exposure", "value": u, "host": host,
                        "location": final,
                        "note": f"redirected off-scope to {final} (status {status}); body NOT extracted",
                        "sources": ["exposed-fetch"]})
                    continue
                if status != 200:
                    continue
                data = resp.read(MAX_BODY + 1)
        except Exception:
            continue
        if len(data) > MAX_BODY:
            continue
        text = data.decode("utf-8", "replace")
        fname = f"{host}-{hashlib.md5(u.encode()).hexdigest()[:8]}"
        dest = ctx.run.raw_path("params", "exposed", fname)
        dest.write_bytes(data)
        hits = mine(text)
        for kind, val, ln in hits:
            basis = val or f"{kind}|{u}|{ln}"
            if ctx.run.add("secret", {
                    "id": f"exposed:{kind}:{secrets.fingerprint(basis)}",
                    "kind": kind, "preview": secrets.mask(val),
                    "file": str(dest), "location": u, "line": ln,
                    "sources": ["exposed-fetch"]}):
                added += 1
        # The exposure itself as reviewable evidence (raw_ref -> saved body). confirmed:false —
        # collected evidence, still human-reviewed; NO impact performed.
        ctx.run.add("review", {
            "id": f"exposed:{u}", "klass": "exposure", "value": u, "host": host,
            "raw_ref": str(dest),
            "note": f"{len(hits)} secret(s) extracted" if hits else "fetched; no secret pattern",
            "sources": ["exposed-fetch"]})
    return added
