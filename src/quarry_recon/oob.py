"""OOB evidence substrate (Phase 1) — import out-of-band callbacks into a run's store.

Parses interactsh-client ``-json`` (JSONL) into ``oob_interaction`` rows. Phase 1 is IMPORT-based and
UNCORRELATED by default: an interaction is real signal (something reached the collector) but Quarry does
not own the token namespace yet, so it does NOT attribute a source/target/param — that arrives in Phase 2
when Quarry issues + owns the callback session. Never fabricate attribution.

interactsh-client ``-json`` record keys (confirmed from a live session, 2026-07-11):
``protocol · unique-id · full-id · q-type · raw-request · raw-response · remote-address · timestamp``.
``unique-id`` = the registered session (the correlation prefix Phase 2 will map to a source); ``full-id``
= the exact subdomain that was hit.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import runner


def _interaction_id(rec: dict) -> str:
    """Stable dedup id for one interaction (same session can produce many; distinguish by full-id +
    timestamp + protocol + remote)."""
    basis = "|".join(str(rec.get(k, "")) for k in
                     ("unique-id", "full-id", "protocol", "timestamp", "remote-address"))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def parse_interactsh(text: str) -> list[dict]:
    """interactsh-client ``-json`` (JSONL) -> oob_interaction rows. Defensive: skips malformed/empty
    lines. UNCORRELATED by default — Phase 1 owns no token namespace, so no source attribution."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if not isinstance(rec, dict) or not rec.get("protocol"):
            continue
        out.append({
            "id": _interaction_id(rec),
            "protocol": rec.get("protocol"),
            "interaction_domain": rec.get("full-id"),
            "correlation_id": rec.get("unique-id"),      # session id; Phase 2 maps its prefix -> source
            "q_type": rec.get("q-type"),
            "remote_address": rec.get("remote-address"),
            "timestamp": rec.get("timestamp"),
            # Phase-1 stance: evidence WITHOUT attribution (do NOT guess a source)
            "correlation": "uncorrelated",
            "source_tool": None,
            "target_url": None,
            "param": None,
            "payload_class": "unknown-oob",
            "sources": ["oob-import"],
        })
    return out


def import_file(run, path) -> dict:
    """Copy the raw import to ``raw/oob/``, parse it, add oob_interaction rows to the store. Returns
    ``{parsed, added, by_protocol, correlated}``; each row's ``raw_ref`` points at the stored raw file.

    Rows are UNCORRELATED by default (external/stray callbacks Quarry didn't issue). But if this run has a
    Quarry-owned session (session.json with a token_map), imported rows are run through ``correlate()``
    first — an imported log that happens to contain a Quarry-issued token is attributed to its source,
    exactly what the CLI help promises. Rows without a matching token stay uncorrelated (never fabricated)."""
    src = Path(path)
    text = src.read_text(encoding="utf-8", errors="replace")
    # content-hash prefix: two DIFFERENT files sharing a name (e.g. interact.jsonl) must not clobber
    # each other's raw evidence — otherwise earlier oob_interaction.raw_ref rows point at the wrong
    # file. Identical content re-import maps to the same raw file (raw_ref stays stable).
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    raw = run.raw_path("oob", "import", f"{digest}-{src.name}")
    raw.write_text(text, encoding="utf-8")
    rows = parse_interactsh(text)
    session = load_session(run)                 # None if this run never opened a Quarry-owned session
    if session and session.get("token_map"):
        correlate(rows, session)                # upgrade rows whose token matches; others untouched
    added = 0
    correlated = 0
    by_protocol: dict[str, int] = {}
    for row in rows:
        row["raw_ref"] = str(raw)
        if run.add("oob_interaction", row):
            added += 1
            by_protocol[row["protocol"]] = by_protocol.get(row["protocol"], 0) + 1
            if row.get("correlation") == "correlated":
                correlated += 1
    return {"parsed": len(rows), "added": added, "by_protocol": by_protocol, "correlated": correlated}


# ── Phase 2 / P2.1: Quarry-OWNED interactsh session ──────────────────────────────────────────────
# The correlation engine (confirmed from a live session): interactsh registers a callback host
# `<unique-id>.<registered-host>` (public oast.* OR a self-hosted/private collector) and every record's
# full-id is `<prefix-label>.<unique-id>`. Quarry issues `<token>.<unique-id>` as the
# callback (P2.2 mints the token), so on interaction the token is full-id with the trailing
# `.<unique-id>` stripped. token_map{token -> source/target/param} then names the source. P2.1 owns the
# session lifecycle + the correlate hook; P2.2 mints/injects tokens; P2.3 wires params.oob_probe.

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})+)\b", re.I)
_REG_MARKER = "payload for OOB Testing"      # interactsh-client prints the registered host after this


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s or "")


def _server_host(server) -> str:
    """A single server value reduced to a bare lowercase hostname — drops scheme, path, and port
    (`https://oob.example.com:443/x` -> `oob.example.com`)."""
    if not server:
        return ""
    s = str(server).strip().split("://", 1)[-1]
    return s.split("/", 1)[0].split(":", 1)[0].strip().lower().rstrip(".")


def _server_hosts(server) -> list[str]:
    """All hosts from a (comma-list) server config, normalized. interactsh-client `-server a,b,c` can
    register under ANY of them, so the parser accepts a domain-BOUNDARY match against any."""
    if not server:
        return []
    return [h for h in (_server_host(x) for x in str(server).split(",")) if h]


def _parse_registered(text: str, server=None):
    """Extract (registered_host, unique_id) from interactsh-client startup output — GENERIC: works for
    the public oast.* servers AND a self-hosted/private collector (no `oast` baked in). The client
    prints the registered callback host at/after a 'payload for OOB Testing' marker; unique_id = its
    first label (the session id). Marker match is CASE-INSENSITIVE and the host may sit on the marker
    line OR a following one (startup formats drift). When `server` is configured, prefer a host under it
    (scheme/port-tolerant). Returns None until the host is printed."""
    lines = _strip_ansi(text).splitlines()
    srv_hosts = _server_hosts(server)
    marker = _REG_MARKER.lower()
    for i, ln in enumerate(lines):
        if marker in ln.lower():
            for cand in [ln] + lines[i + 1:]:       # host may be on the marker line OR a later one
                for m in _HOST_RE.finditer(cand):
                    host = m.group(1).lower().rstrip(".")   # normalize captured host (case + trailing dot)
                    # domain-BOUNDARY match — plain endswith would accept e.g. evil-oob.example.com
                    if srv_hosts and not any(host == s or host.endswith("." + s) for s in srv_hosts):
                        continue          # a configured server must match the registered host
                    return host, host.split(".")[0]
    return None


def session_path(run) -> Path:
    return run.raw_path("oob", "session", "session.json")


def save_session(run, session: dict) -> Path:
    """Persist the session to raw/oob/session.json ATOMICALLY (temp write + os.replace) — a crash
    mid-write must not corrupt the file the token_map's crash-safety depends on."""
    p = session_path(run)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(session, indent=2), encoding="utf-8")
    os.replace(tmp, p)                            # atomic on POSIX — no torn session.json
    return p


def load_session(run) -> dict | None:
    p = session_path(run)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _drain(stream, q: "queue.Queue") -> None:
    """Read a subprocess stream line-by-line into a queue; sentinel None on EOF. Runs in a daemon
    thread so a blocking readline can never hang the caller (which waits on the queue with a timeout)."""
    try:
        for line in iter(stream.readline, ""):
            q.put(line)
    except Exception:
        pass
    q.put(None)


def _await_register(proc, server, wait):
    """Read the client's stdout (via a daemon-drained queue, never blocks) until it prints its
    registered host or `wait` elapses. Returns (host, unique_id) or None. Shared by open + resume."""
    q: "queue.Queue" = queue.Queue()
    threading.Thread(target=_drain, args=(proc.stdout, q), daemon=True).start()
    parsed = None
    buf: list[str] = []
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline and parsed is None:
        try:
            line = q.get(timeout=0.3)
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        if line is None:
            break
        buf.append(line)
        parsed = _parse_registered("".join(buf), server)
    return parsed


def open_session(run, server=None, token=None, wait: int = 12):
    """Start a Quarry-owned interactsh-client session (shelled). Captures the registered host +
    unique-id from the startup output, persists raw/oob/session.json (token_map empty until P2.2), and
    returns (session_dict, proc). Returns None if interactsh-client is missing or does not register
    within `wait` seconds — it CANNOT hang (stdout is drained in a daemon thread, the wait is a hard
    deadline). `server`/`token` = a self-hosted interactsh + its auth token (interactsh-client -server
    / -token); unset -> the client's default public servers. The live process is the caller's to poll
    (poll_session) and close (close_session)."""
    if not shutil.which("interactsh-client"):
        return None
    log = run.raw_path("oob", "session", "interactions.jsonl")
    sf = run.raw_path("oob", "session", "interactsh.session")
    # -session-file makes the session RESUMABLE: a later interactsh-client (quarry oob poll, P2.4) with
    # the same file re-opens the SAME correlation id and picks up DELAYED callbacks. So closing the
    # client after the immediate poll is fine — late interactions aren't lost.
    cmd = ["interactsh-client", "-json", "-o", str(log), "-session-file", str(sf)]
    # interactsh-client -server wants bare server domains (e.g. `oob.example.com`), NOT a URL — nuclei's
    # -iserver takes the full URL, so the SAME oob.interactsh_server config is normalized PER CONSUMER here.
    srv = ",".join(_server_hosts(server)) if server else ""
    if srv:
        cmd += ["-server", srv]
    if token:
        cmd += ["-token", str(token)]           # auth for a protected/self-hosted interactsh
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)   # own process group -> terminate_group kills the tree
    parsed = _await_register(proc, server, wait)
    if parsed is None:
        close_session(proc)
        return None
    domain, uid = parsed
    session = {"domain": domain, "unique_id": uid, "token_map": {}, "started": _utc(),
               "log": str(log), "session_file": str(sf), "server": server}
    save_session(run, session)
    return session, proc


def resume_session(run, token=None, wait: int = 12):
    """Re-open the run's OWNED session to poll DELAYED callbacks — WITHOUT clobbering the token_map.
    Loads the persisted session.json (with its token_map), re-launches interactsh-client on the SAME
    -session-file (so it resumes the SAME correlation id + registered domain), verifies the re-registered
    domain MATCHES the saved one, and returns (session, proc) with the ORIGINAL token_map intact. Returns
    None if there is no saved session, no interactsh-client, or the resume registers a different domain.
    (open_session mints a FRESH session; this is the resume/poll path — it NEVER overwrites token_map.)"""
    prev = load_session(run)
    if not prev or not prev.get("session_file") or not shutil.which("interactsh-client"):
        return None
    log = prev.get("log") or str(run.raw_path("oob", "session", "interactions.jsonl"))
    cmd = ["interactsh-client", "-json", "-o", str(log), "-session-file", str(prev["session_file"])]
    srv = ",".join(_server_hosts(prev.get("server"))) if prev.get("server") else ""   # bare domains for -server
    if srv:
        cmd += ["-server", srv]
    if token:
        cmd += ["-token", str(token)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)   # own process group -> terminate_group kills the tree
    parsed = _await_register(proc, prev.get("server"), wait)
    if parsed is None or parsed[0] != prev.get("domain"):   # must resume the SAME registered domain
        close_session(proc)
        return None
    return prev, proc                            # keep prev — token_map is NEVER rebuilt/overwritten


def close_session(proc) -> None:
    """Stop the interactsh-client session — its WHOLE process group (best-effort), via the shared runner
    helper, so no interactsh child is left behind."""
    runner.terminate_group(proc)


def correlate(rows: list[dict], session: dict) -> list[dict]:
    """Fill source attribution on rows whose callback token maps to a Quarry-issued probe. full-id is
    `<token>.<unique-id>`; strip the trailing `.<unique-id>` to recover the token, look it up in the
    session's token_map. Unknown/absent token -> stays UNCORRELATED (never fabricate). Mutates + returns
    rows. (P2.1 provides the hook; P2.2 populates token_map so this actually correlates.)"""
    uid = (session.get("unique_id", "") or "").lower()
    tmap = session.get("token_map") or {}
    suffix = "." + uid
    for r in rows:
        fid = (r.get("interaction_domain") or "").lower().rstrip(".")   # normalize (case + trailing dot)
        token = fid[:-len(suffix)] if (uid and fid.endswith(suffix)) else None
        m = tmap.get(token) if token else None
        if m:
            r["correlation"] = "correlated"
            r["source_tool"] = m.get("source_tool")
            r["target_url"] = m.get("target_url")
            r["param"] = m.get("param")
            r["payload_class"] = m.get("payload_class", r.get("payload_class"))
            # provenance: parse_interactsh stamps every row ["oob-import"]; a correlated hit came in
            # over the Quarry-OWNED session, issued by source_tool — fix sources to reflect that, not import.
            src = [s for s in ("oob-owned-session", m.get("source_tool")) if s]
            r["sources"] = src or r.get("sources")
    return rows


def poll_session(run, session: dict) -> list[dict]:
    """Read the owned session's -json log so far -> oob_interaction rows (parse_interactsh), then
    correlate against the session token_map. Does NOT write to the store — the caller decides what to
    persist (kept side-effect-free so it can be polled repeatedly)."""
    log = Path(session.get("log", ""))
    if not log.exists():
        return []
    return correlate(parse_interactsh(log.read_text(encoding="utf-8", errors="replace")), session)


# ── Phase 2 / P2.2: token issuance (the source side of correlation) ───────────────────────────────
# A Quarry OOB probe mints a token, injects `<token>.<registered-host>` into the target param, and
# records token -> (source_tool, target_url, param, payload_class) in the session's token_map. On a
# callback, interactsh reports full-id `<token>.<unique-id>`, which correlate() maps straight back.
# The token is the whole handle Quarry controls — that's why Quarry-issued probes get FULL correlation.

def issue_token(session: dict, source_tool: str, target_url=None, param=None,
                payload_class: str = "oob", run=None) -> str:
    """Mint a unique, DNS-label-safe callback token and record token -> (source_tool, target_url, param,
    payload_class) in the session's token_map. Returns the token. The token is RANDOM and collision-
    checked, so a sparse/restored token_map can never overwrite an existing mapping (which would
    misattribute a callback). If `run` is given the session is persisted immediately (save_session) so a
    crash after injecting a probe can't lose the mapping — a later callback still correlates."""
    tmap = session.setdefault("token_map", {})
    while True:
        token = "q" + os.urandom(4).hex()        # q + 8 hex chars: DNS-label-safe, ~4e9 space
        if token not in tmap:
            break
    tmap[token] = {"source_tool": source_tool, "target_url": target_url,
                   "param": param, "payload_class": payload_class}
    if run is not None:
        save_session(run, session)               # persist atomically — never lose a mapping on a crash
    return token


def callback_host(session: dict, token: str) -> str:
    """The callback hostname to inject: `<token>.<registered-host>`. On a hit interactsh reports full-id
    `<token>.<unique-id>` (server suffix stripped), which correlate() maps back via the token_map.
    DNS-only probes (SSRF/DNS-rebind) can use this host alone."""
    domain = session.get("domain")
    if not domain:
        raise ValueError("OOB session has no registered domain (open_session must succeed first)")
    return f"{token}.{domain}"


def callback_url(session: dict, token: str, scheme: str = "http", path: str = "") -> str:
    """A full callback URL `scheme://<token>.<registered-host>[/<path>]` for probes that need a URL
    (SSRF/open-redirect/webhook params)."""
    host = callback_host(session, token)
    tail = ("/" + path.lstrip("/")) if path else ""
    return f"{scheme}://{host}{tail}"
