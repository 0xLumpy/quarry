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
import queue
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


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
    ``{parsed, added, by_protocol}``; each row's ``raw_ref`` points at the stored raw file."""
    src = Path(path)
    text = src.read_text(encoding="utf-8", errors="replace")
    # content-hash prefix: two DIFFERENT files sharing a name (e.g. interact.jsonl) must not clobber
    # each other's raw evidence — otherwise earlier oob_interaction.raw_ref rows point at the wrong
    # file. Identical content re-import maps to the same raw file (raw_ref stays stable).
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    raw = run.raw_path("oob", "import", f"{digest}-{src.name}")
    raw.write_text(text, encoding="utf-8")
    rows = parse_interactsh(text)
    added = 0
    by_protocol: dict[str, int] = {}
    for row in rows:
        row["raw_ref"] = str(raw)
        if run.add("oob_interaction", row):
            added += 1
            by_protocol[row["protocol"]] = by_protocol.get(row["protocol"], 0) + 1
    return {"parsed": len(rows), "added": added, "by_protocol": by_protocol}


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
    return s.split("/", 1)[0].split(":", 1)[0].strip().lower()


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
                    host = m.group(1)
                    # domain-BOUNDARY match — plain endswith would accept e.g. evil-oob.example.com
                    if srv_hosts and not any(host == s or host.endswith("." + s) for s in srv_hosts):
                        continue          # a configured server must match the registered host
                    return host, host.split(".")[0]
    return None


def session_path(run) -> Path:
    return run.raw_path("oob", "session", "session.json")


def save_session(run, session: dict) -> Path:
    p = session_path(run)
    p.write_text(json.dumps(session, indent=2), encoding="utf-8")
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
    cmd = ["interactsh-client", "-json", "-o", str(log)]
    if server:
        cmd += ["-server", str(server)]
    if token:
        cmd += ["-token", str(token)]           # auth for a protected/self-hosted interactsh
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    q: "queue.Queue" = queue.Queue()
    threading.Thread(target=_drain, args=(proc.stdout, q), daemon=True).start()

    parsed = None
    buf: list[str] = []
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline and parsed is None:
        try:
            line = q.get(timeout=0.3)           # bounded wait — never blocks indefinitely
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        if line is None:                        # EOF (client exited)
            break
        buf.append(line)
        parsed = _parse_registered("".join(buf), server)
    if parsed is None:
        close_session(proc)
        return None
    domain, uid = parsed
    session = {"domain": domain, "unique_id": uid, "token_map": {},
               "started": _utc(), "log": str(log), "server": server}
    save_session(run, session)
    return session, proc


def close_session(proc) -> None:
    """Stop the interactsh-client session process (best-effort)."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def correlate(rows: list[dict], session: dict) -> list[dict]:
    """Fill source attribution on rows whose callback token maps to a Quarry-issued probe. full-id is
    `<token>.<unique-id>`; strip the trailing `.<unique-id>` to recover the token, look it up in the
    session's token_map. Unknown/absent token -> stays UNCORRELATED (never fabricate). Mutates + returns
    rows. (P2.1 provides the hook; P2.2 populates token_map so this actually correlates.)"""
    uid = session.get("unique_id", "") or ""
    tmap = session.get("token_map") or {}
    suffix = "." + uid
    for r in rows:
        fid = r.get("interaction_domain") or ""
        token = fid[:-len(suffix)] if (uid and fid.endswith(suffix)) else None
        m = tmap.get(token) if token else None
        if m:
            r["correlation"] = "correlated"
            r["source_tool"] = m.get("source_tool")
            r["target_url"] = m.get("target_url")
            r["param"] = m.get("param")
            r["payload_class"] = m.get("payload_class", r.get("payload_class"))
    return rows


def poll_session(run, session: dict) -> list[dict]:
    """Read the owned session's -json log so far -> oob_interaction rows (parse_interactsh), then
    correlate against the session token_map. Does NOT write to the store — the caller decides what to
    persist (kept side-effect-free so it can be polled repeatedly)."""
    log = Path(session.get("log", ""))
    if not log.exists():
        return []
    return correlate(parse_interactsh(log.read_text(encoding="utf-8", errors="replace")), session)
