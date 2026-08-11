"""OOB evidence substrate — import out-of-band callbacks into a run's store.

Parses interactsh-client ``-json`` (JSONL) into ``oob_interaction`` rows. A row stays uncorrelated
unless its callback token is one this run issued: an interaction is real signal on its own, but a
source/target/param is only ever claimed when Quarry owns the token. Never fabricate attribution.

In a record, ``unique-id`` is the registered session and ``full-id`` the exact subdomain that was hit.
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

from . import privfs, runner


def _interaction_id(rec: dict) -> str:
    """Stable dedup id for one interaction: session + full-id + protocol + timestamp + remote."""
    basis = "|".join(str(rec.get(k, "")) for k in
                     ("unique-id", "full-id", "protocol", "timestamp", "remote-address"))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def parse_interactsh(text: str) -> list[dict]:
    """interactsh-client ``-json`` (JSONL) -> oob_interaction rows, skipping malformed/empty lines.
    Every row comes out uncorrelated; only ``correlate`` may attribute one."""
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
            "correlation_id": rec.get("unique-id"),      # the session id
            "q_type": rec.get("q-type"),
            "remote_address": rec.get("remote-address"),
            "timestamp": rec.get("timestamp"),
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

    When the run has a Quarry-owned session, imported rows carrying one of its tokens are correlated;
    the rest stay uncorrelated.
    """
    src = Path(path)
    text = src.read_text(encoding="utf-8", errors="replace")
    # content-hash prefix: two different files sharing a name must not clobber each other's raw
    # evidence, while identical content re-imports to the same file (raw_ref stays stable)
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    raw = run.raw_path("oob", "import", f"{digest}-{src.name}")
    privfs.write_private(raw, text)             # 0600: imported callback data can carry correlated secrets
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


# ── the Quarry-owned interactsh session ──────────────────────────────────────────────────────────
# interactsh registers `<unique-id>.<registered-host>`; each hit's full-id is `<token>.<unique-id>`

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
    """All hosts from a comma-list server config, normalized — `-server a,b,c` may register under any."""
    if not server:
        return []
    return [h for h in (_server_host(x) for x in str(server).split(",")) if h]


def _parse_registered(text: str, server=None):
    """(registered_host, unique_id) from interactsh-client startup output, or None until the host is
    printed. No server name is baked in: the host is whatever follows the marker, on that line or a
    later one, and a configured `server` restricts it to a domain-boundary match under one of its
    hosts. unique_id is the host's first label."""
    lines = _strip_ansi(text).splitlines()
    srv_hosts = _server_hosts(server)
    marker = _REG_MARKER.lower()
    for i, ln in enumerate(lines):
        if marker in ln.lower():
            for cand in [ln] + lines[i + 1:]:
                for m in _HOST_RE.finditer(cand):
                    host = m.group(1).lower().rstrip(".")
                    # domain boundary — a plain endswith would accept e.g. evil-oob.example.com
                    if srv_hosts and not any(host == s or host.endswith("." + s) for s in srv_hosts):
                        continue
                    return host, host.split(".")[0]
    return None


def session_path(run) -> Path:
    return run.raw_path("oob", "session", "session.json")


def save_session(run, session: dict) -> Path:
    """Persist the session to raw/oob/session.json atomically — the token_map must survive a crash
    mid-write. Written 0600, O_NOFOLLOW: the token_map is a private map."""
    p = session_path(run)
    privfs.write_private(p, json.dumps(session, indent=2))
    return p


def load_session(run) -> dict | None:
    try:
        with os.fdopen(privfs.open_ro_private(session_path(run)), "r", encoding="utf-8") as fh:  # symlink-safe read
            obj = json.loads(fh.read())
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict):                    # a non-object session (string/list) is not usable
        return None
    for key in ("unique_id", "log"):                 # string fields used by .lower() / Path(); coerce a bad type
        if key in obj and not isinstance(obj[key], str):
            obj[key] = ""
    tm = obj.get("token_map")                        # a token maps to an attribution dict; drop malformed entries
    obj["token_map"] = {k: v for k, v in tm.items() if isinstance(k, str) and isinstance(v, dict)} \
        if isinstance(tm, dict) else {}
    return obj


def _drain(stream, q: "queue.Queue") -> None:
    """Read a subprocess stream line-by-line into a queue, sentinel None on EOF. Belongs in a daemon
    thread: the caller waits on the queue with a timeout, never on readline."""
    try:
        for line in iter(stream.readline, ""):
            q.put(line)
    except Exception:
        pass
    q.put(None)


def _await_register(proc, server, wait):
    """Read the client's stdout until it prints its registered host or `wait` elapses; returns
    (host, unique_id) or None. Cannot block: the stdout drain runs in a daemon thread."""
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
    """Start a Quarry-owned interactsh-client session and return (session_dict, proc), persisting
    raw/oob/session.json with an empty token_map.

    `server`/`token` name a self-hosted interactsh and its auth token; unset uses the client's default
    public servers. Returns None if interactsh-client is missing or does not register within `wait`
    seconds, which is a hard deadline — this cannot hang. The live process is the caller's to poll
    (poll_session) and close (close_session).
    """
    if not shutil.which("interactsh-client"):
        return None
    log = run.raw_path("oob", "session", "interactions.jsonl")
    sf = run.raw_path("oob", "session", "interactsh.session")
    # pre-create 0600 so the client appends into private files (its own O_CREAT keeps an existing mode);
    # the containing dir is already 0700 via raw_path
    privfs.touch_private(log)
    privfs.touch_private(sf)
    # -session-file makes the session resumable: a later client on the same file re-opens the same
    # correlation id, so closing after a poll does not lose delayed callbacks
    cmd = ["interactsh-client", "-json", "-o", str(log), "-session-file", str(sf)]
    # -server wants bare domains, not a URL (nuclei's -iserver takes the full URL)
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


def _resume_token(saved_server, current_server, token):
    """The token to reuse on resume: kept only for a self-hosted saved session whose server the current
    config still matches; a public or changed session gets none."""
    saved = _server_hosts(saved_server)
    if not saved or not token:
        return None
    return str(token) if set(_server_hosts(current_server)) == set(saved) else None


def resume_session(run, token=None, server=None, wait: int = 12):
    """Re-open the run's owned session to poll delayed callbacks, returning (session, proc) with the
    saved token_map intact — this path never rebuilds it (open_session mints a fresh session instead).

    `server`/`token` are the current oob config; the token is coupled to the saved server (see
    `_resume_token`). Returns None if there is no saved session, no interactsh-client, or the re-registered
    domain does not match the saved one.
    """
    prev = load_session(run)
    if not prev or not prev.get("session_file") or not shutil.which("interactsh-client"):
        return None
    log = prev.get("log") or str(run.raw_path("oob", "session", "interactions.jsonl"))
    cmd = ["interactsh-client", "-json", "-o", str(log), "-session-file", str(prev["session_file"])]
    srv = ",".join(_server_hosts(prev.get("server"))) if prev.get("server") else ""   # bare domains for -server
    if srv:
        cmd += ["-server", srv]
    eff_token = _resume_token(prev.get("server"), server, token)
    if eff_token:
        cmd += ["-token", eff_token]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)   # own process group -> terminate_group kills the tree
    parsed = _await_register(proc, prev.get("server"), wait)
    if parsed is None or parsed[0] != prev.get("domain"):   # must resume the same registered domain
        close_session(proc)
        return None
    return prev, proc


def close_session(proc) -> None:
    """Stop the session's whole process group (best-effort, reaped) and close its stdout pipe."""
    runner.terminate_group(proc)
    try:
        if proc.stdout:
            proc.stdout.close()
    except Exception:
        pass


def correlate(rows: list[dict], session: dict) -> list[dict]:
    """Fill source attribution on rows whose callback token maps to a Quarry-issued probe: the token is
    full-id with the trailing `.<unique-id>` stripped, looked up in the session's token_map. An unknown
    or absent token leaves the row uncorrelated. Mutates and returns rows."""
    uid = (session.get("unique_id", "") or "").lower()
    tmap = session.get("token_map") or {}
    suffix = "." + uid
    for r in rows:
        dom = r.get("interaction_domain")
        fid = dom.lower().rstrip(".") if isinstance(dom, str) else ""   # a non-str field is not a domain
        token = fid[:-len(suffix)] if (uid and fid.endswith(suffix)) else None
        m = tmap.get(token) if token else None
        if m:
            r["correlation"] = "correlated"
            r["source_tool"] = m.get("source_tool")
            r["target_url"] = m.get("target_url")
            r["param"] = m.get("param")
            r["payload_class"] = m.get("payload_class", r.get("payload_class"))
            # provenance: a correlated hit arrived over the owned session, not by import
            src = [s for s in ("oob-owned-session", m.get("source_tool")) if s]
            r["sources"] = src or r.get("sources")
    return rows


def poll_session(run, session: dict) -> list[dict]:
    """Read the owned session's -json log so far -> correlated oob_interaction rows. Side-effect-free,
    so it can be polled repeatedly; the caller decides what to persist."""
    lp = session.get("log")
    if not isinstance(lp, str) or not lp:            # no/blank/non-str log path -> nothing to poll
        return []
    log = Path(lp)
    if not log.exists():
        return []
    return correlate(parse_interactsh(log.read_text(encoding="utf-8", errors="replace")), session)


# ── token issuance (the source side of correlation) ──────────────────────────────────────────────

def issue_token(session: dict, source_tool: str, target_url=None, param=None,
                payload_class: str = "oob", run=None) -> str:
    """Mint a DNS-label-safe callback token and record token -> (source_tool, target_url, param,
    payload_class) in the session's token_map; returns the token.

    The token is random and collision-checked against the map, so a mapping is never overwritten and a
    callback never misattributed. With `run` given, the session is persisted before returning, so a
    crash after a probe is injected still leaves the callback correlatable.
    """
    tmap = session.setdefault("token_map", {})
    while True:
        token = "q" + os.urandom(4).hex()        # q + 8 hex chars: DNS-label-safe, ~4e9 space
        if token not in tmap:
            break
    tmap[token] = {"source_tool": source_tool, "target_url": target_url,
                   "param": param, "payload_class": payload_class}
    if run is not None:
        save_session(run, session)
    return token


def callback_host(session: dict, token: str) -> str:
    """The callback hostname to inject: `<token>.<registered-host>` — enough on its own for a DNS-only
    probe. Raises ValueError when the session never registered a domain."""
    domain = session.get("domain")
    if not domain:
        raise ValueError("OOB session has no registered domain (open_session must succeed first)")
    return f"{token}.{domain}"


def callback_url(session: dict, token: str, scheme: str = "http", path: str = "") -> str:
    """A full callback URL `scheme://<token>.<registered-host>[/<path>]`, for probes that need a URL."""
    host = callback_host(session, token)
    tail = ("/" + path.lstrip("/")) if path else ""
    return f"{scheme}://{host}{tail}"
