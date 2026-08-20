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
import signal
import shutil
import subprocess
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import privfs, runner, runtime_identity, secrets
from .state import ContractError


_OOB_SESSION_COMPONENTS = ("raw", "oob", "session", "session.json")
_OOB_LOG_COMPONENTS = ("raw", "oob", "session", "interactions.jsonl")
_OOB_CLIENT_SESSION_COMPONENTS = ("raw", "oob", "session", "interactsh.session")
_SESSION_REFERENCE_FIELDS = frozenset({"log", "session_file"})
_POPEN_TYPE = subprocess.Popen


@contextmanager
def _owned_descriptor(what, *, expected_identity=None):
    """Activate two settlement passes before one descriptor can be allocated."""
    from . import store as _store
    owner = _store._OwnedDescriptor(expected_identity)
    settlement = _store._SettlementOwner(
        lambda: _store._settle_descriptor_owners(
            (owner,), what,
        ),
    )
    with _store._SettlementFence(settlement):
        with _store._SettlementFence(settlement):
            yield owner


@contextmanager
def _owned_run_anchor(run):
    """Keep one exact run descriptor owned across a bounded OOB operation."""
    from . import store as _store
    with _owned_descriptor(
        "OOB run descriptor",
        expected_identity=run._run_directory_identity,
    ) as owner:
        _store._open_run_fd_into(
            owner,
            run.project_dir,
            run.run_id,
            expected_identity=run._run_directory_identity,
        )
        yield owner.fd


def _repository_ref(run, path, *, field: str) -> str:
    """Convert one strict in-run path to its stable repository-relative name."""
    if field not in _SESSION_REFERENCE_FIELDS:
        raise ContractError("unknown OOB session reference field")
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = run.dir / candidate
    try:
        relative = candidate.relative_to(run.dir)
    except ValueError:
        raise ContractError(f"OOB {field} must stay inside run {run.run_id}") from None
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ContractError(f"OOB {field} is not a safe repository reference")
    from . import store as _store
    for index, part in enumerate(relative.parts):
        _store.validate_artifact_component(part, f"OOB {field} component {index}")
    return relative.as_posix()


def resolve_session_ref(run, value, *, field: str, require_file: bool = True) -> Path:
    """Resolve a stored OOB reference without accepting absolute/escaping/link paths.

    This function intentionally validates the complete ancestor chain even when
    the caller will later pass the result to a subprocess.  A path that is safe
    only at JSON parse time is not a safe client destination.
    """
    if field not in _SESSION_REFERENCE_FIELDS or not isinstance(value, str) or not value:
        raise ContractError(f"OOB {field} is not a repository-relative reference")
    ref = Path(value)
    if ref.is_absolute() or not ref.parts or any(part in ("", ".", "..") for part in ref.parts):
        raise ContractError(f"OOB {field} is not a repository-relative reference")
    from . import store as _store
    components = tuple(
        _store.validate_artifact_component(part, f"OOB {field} component {index}")
        for index, part in enumerate(ref.parts)
    )
    with _owned_run_anchor(run) as anchor_fd:
        with _owned_descriptor("OOB session parent descriptor") as parent:
            _store._open_strict_directory_into(
                parent, anchor_fd, components[:-1],
            )
            if require_file:
                with _owned_descriptor("OOB session file descriptor") as file_owner:
                    try:
                        file_owner.open(
                            components[-1],
                            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                            dir_fd=parent.fd,
                        )
                    except OSError as exc:
                        raise ContractError(
                            f"OOB {field} is not a safe private file",
                        ) from exc
                    observed = os.fstat(file_owner.fd)
                    named = os.stat(
                        components[-1], dir_fd=parent.fd, follow_symlinks=False,
                    )
                    if ((observed.st_dev, observed.st_ino) != (named.st_dev, named.st_ino)
                            or not privfs.is_private(run.dir.joinpath(*components))):
                        raise ContractError(f"OOB {field} is not a safe private file")
    return run.dir.joinpath(*components)


def _portable_session(run, session: dict) -> dict:
    """A copy safe to persist: path fields are repository-relative references."""
    if not isinstance(session, dict):
        raise ContractError("OOB session must be an object")
    document = dict(session)
    for field in _SESSION_REFERENCE_FIELDS:
        if field in document and document[field]:
            document[field] = _repository_ref(run, document[field], field=field)
    return document


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


def import_file(run, path, *, scope=None) -> dict:
    """Copy the raw import beside the run's other raw evidence, parse it, add oob_interaction rows. Returns
    ``{parsed, added, by_protocol, correlated, revision}``; each row's ``raw_ref`` points at the stored
    raw file.

    When the run has a Quarry-owned session, imported rows carrying one of its tokens are correlated;
    the rest stay uncorrelated. A run that already finished is never rewritten: its rows go to a
    supplement and `revision` names the combined view they were published into.
    """
    src = Path(path)
    text = src.read_text(encoding="utf-8", errors="replace")
    # content-hash prefix: two different files sharing a name must not clobber each other's raw
    # evidence, while identical content re-imports to the same file (raw_ref stays stable)
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    rows = parse_interactsh(text)
    session = load_session(run)                 # None if this run never opened a Quarry-owned session
    if session and session.get("token_map"):
        correlate(rows, session)                # upgrade rows whose token matches; others untouched
    from . import revision as _revision
    disposition, why = _revision.base_disposition(run.dir)
    if disposition in (_revision.UNKNOWN, _revision.FINALIZING):
        raise _revision.RevisionError(
            f"{run.dir}: {why} — refusing to record late evidence; retry once lifecycle settles",
            retryable=True,
        )
    try:
        result = _revision.commit_oob_candidate(
            run,
            raw_name=f"{digest}-{src.name}",
            raw_bytes=text.encode("utf-8"),
            rows=rows,
            origin="oob.import",
            scope=scope,
        )
    except ContractError as exc:
        if run.state == "unknown":
            raise _revision.RevisionError(
                f"{run.dir}: unknown lifecycle state — refusing OOB mutation; retry after repair",
                retryable=True,
            ) from exc
        raise
    return {"parsed": len(rows), **result}


def import_polled(run, session: dict, rows: list[dict], *, scope=None) -> dict:
    """Persist rows read from the run's owned session. Same revision rules as ``import_file``: a finished
    run is supplemented, never rewritten."""
    from . import revision as _revision
    candidate_ref = session.get("log")
    if session.get("revision_candidate"):
        log = resolve_session_ref(run, candidate_ref, field="log")
        raw_bytes = log.read_bytes()
        result = _revision.commit_oob_candidate(
            run,
            raw_name=f"poll-{session['revision_candidate']}.jsonl",
            raw_bytes=raw_bytes,
            rows=rows,
            origin="oob.poll",
            scope=scope,
        )
        return result
    for row in rows:
        row.setdefault("raw_ref", candidate_ref)
    return _ingest(run, rows, origin="oob.poll", scope=scope)


def _ingest(run, rows: list[dict], *, origin: str, scope=None) -> dict:
    """Route rows to the live store or to a supplement revision, and publish the revision if one was
    opened. Returns ``{added, by_protocol, correlated, revision}``."""
    from . import revision as _revision

    sink = _revision.ingest(run, origin)
    added = 0
    correlated = 0
    by_protocol: dict[str, int] = {}
    for row in rows:
        if sink.add("oob_interaction", row):
            added += 1
            by_protocol[row["protocol"]] = by_protocol.get(row["protocol"], 0) + 1
            if row.get("correlation") == "correlated":
                correlated += 1
    published = sink.commit(scope)
    # the corpus envelope may have turned rows away; the caller reports an incomplete ingest, so it may
    # not have to read the pointer to learn that
    return {"added": added, "by_protocol": by_protocol, "correlated": correlated,
            "refused": int(sink.refused),
            # what this ingest turned away, and what the run still owes across every revision
            "outstanding": len(published.refused) if published is not None else 0,
            "revision": published}


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


def session_path(run, *, create: bool = True) -> Path:
    """The owned session file. `create=False` is the pure read path — it materializes no directory, so
    looking for a session never writes into a run that has already finished."""
    if not create:
        return run.raw / "oob" / "session" / "session.json"
    return run.raw_path("oob", "session", "session.json")


def save_session(run, session: dict) -> Path:
    """Persist the session to raw/oob/session.json atomically — the token_map must survive a crash
    mid-write. Written 0600, O_NOFOLLOW: the token_map is a private map."""
    document = _portable_session(run, session)
    data = json.dumps(document, indent=2).encode("utf-8")
    replace = getattr(run, "_replace_artifact", None)
    if callable(replace):
        from .store import MutationScope
        return replace(MutationScope.BASE_EVIDENCE, _OOB_SESSION_COMPONENTS, data)
    p = session_path(run)
    privfs.write_private(p, data.decode("utf-8"))
    return p


def load_session(run) -> dict | None:
    p = session_path(run, create=False)
    if not p.is_file():
        return None                      # short-circuit: the symlink-safe walk would create the parent
    try:
        with os.fdopen(privfs.open_ro_private(p), "r", encoding="utf-8") as fh:  # symlink-safe read
            obj = json.loads(fh.read())
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict):                    # a non-object session (string/list) is not usable
        return None
    for key in ("unique_id", "log", "session_file"):
        # string fields used by .lower() / Path(); coerce a bad type
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


def _prepare_client_launch(run, command: list[str], *, lifetime: ExitStack,
                           record_directory: Path | None = None):
    """Admit one Interactsh process and bind its exact runtime without serializing argv.

    A live base can publish through its artifact authority.  A sealed-base resume instead places the
    identity beside the already-isolated revision candidate, so it never re-opens a canonical base name.
    Lightweight compatibility callers still receive the same fail-closed executable admission, but have no
    repository in which an evidence record could honestly be published.
    """
    prepared = runtime_identity.prepare_launch(
        "interactsh-client", command,
        payload_scope=getattr(run, "_runtime_payload_scope", None),
    )
    request_id = os.urandom(16).hex()
    try:
        runtime_identity.revalidate_launch(prepared)
        if record_directory is not None:
            body = (json.dumps(prepared.record, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False) + "\n")
            privfs.write_private(Path(record_directory) / f"runtime-identity-{request_id}.json", body)
        else:
            from . import store as _store
            if type(run) is _store.Run:
                runtime_identity.publish_launch_identity(run, request_id, prepared.record)
    except BaseException as primary:
        cleanup_fault = None
        try:
            prepared.close()
        except BaseException as exc:
            cleanup_fault = exc
        if not isinstance(primary, Exception):
            if cleanup_fault is not None:
                primary.add_note(
                    f"runtime identity cleanup also failed: {type(cleanup_fault).__name__}: "
                    f"{cleanup_fault}"
                )
            raise primary.with_traceback(primary.__traceback__)
        if cleanup_fault is not None and not isinstance(cleanup_fault, Exception):
            raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
        if cleanup_fault is not None:
            primary.add_note(
                f"runtime identity cleanup also failed: {type(cleanup_fault).__name__}: "
                f"{cleanup_fault}"
            )
        raise primary.with_traceback(primary.__traceback__)
    lifetime.callback(prepared.close)
    return list(prepared.argv), dict(prepared.environment)


def _settle_partial_popen(proc) -> None:
    """Kill, exactly reap, and close a Popen whose constructor raised after creating a child."""
    faults: list[BaseException] = []
    try:
        pid = getattr(proc, "pid", None)
    except BaseException as exc:
        pid = None
        faults.append(exc)
    if type(pid) is int and pid > 0:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            faults.append(exc)
        try:
            waited, status = os.waitpid(pid, 0)
            if waited == pid:
                proc.returncode = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            try:
                proc.poll()
            except BaseException as exc:
                faults.append(exc)
        except BaseException as exc:
            faults.append(exc)
    for name in ("stdin", "stdout", "stderr"):
        try:
            stream = getattr(proc, name, None)
            if stream is not None:
                stream.close()
        except BaseException as exc:
            faults.append(exc)
    cancellation = next((fault for fault in faults if not isinstance(fault, Exception)), None)
    if cancellation is not None:
        raise cancellation.with_traceback(cancellation.__traceback__)
    if faults:
        raise faults[0].with_traceback(faults[0].__traceback__)


def _spawn_client(owner: dict, claims: ExitStack, argv: list[str], environment: dict[str, str],
                  *, cwd: Path):
    """Publish child authority before fork so constructor cancellation cannot orphan a credential user."""
    kwargs = {
        "stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "text": True,
        "start_new_session": True, "env": environment, "cwd": str(cwd),
    }
    factory = subprocess.Popen
    if factory is _POPEN_TYPE:
        proc = _POPEN_TYPE.__new__(_POPEN_TYPE)
        owner["proc"] = proc
        setattr(proc, "_quarry_oob_claims", claims)
        try:
            _POPEN_TYPE.__init__(proc, argv, **kwargs)
        except BaseException as primary:
            try:
                _settle_partial_popen(proc)
                owner["constructor_settled"] = True
            except BaseException as cleanup_fault:
                if isinstance(primary, Exception) and not isinstance(cleanup_fault, Exception):
                    raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
                primary.add_note(
                    f"OOB constructor cleanup also failed: {type(cleanup_fault).__name__}: "
                    f"{cleanup_fault}"
                )
            raise primary.with_traceback(primary.__traceback__)
    else:
        # Test doubles retain Popen's documented postcondition that a raise creates no child authority.
        proc = factory(argv, **kwargs)
        owner["proc"] = proc
        setattr(proc, "_quarry_oob_claims", claims)
    return proc


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
    claims = ExitStack()
    proc = None
    spawn_owner: dict = {}
    try:
        # These lifetime claims exist even though interactsh opens the files by
        # name.  They keep the base seal from racing a process that can still
        # append to either canonical artifact.
        log_claim = claims.enter_context(run.artifact_claim(*_OOB_LOG_COMPONENTS))
        session_claim = claims.enter_context(run.artifact_claim(*_OOB_CLIENT_SESSION_COMPONENTS))
        log_writer = log_claim.open_writer()
        session_writer = session_claim.open_writer()
        os.close(log_writer)
        os.close(session_writer)
        log_claim.publish()
        session_claim.publish()
        log = run.dir.joinpath(*_OOB_LOG_COMPONENTS)
        sf = run.dir.joinpath(*_OOB_CLIENT_SESSION_COMPONENTS)
        # -session-file makes the session resumable: a later client on the same file re-opens the same
        # correlation id, so closing after a poll does not lose delayed callbacks
        cmd = ["interactsh-client", "-duc", "-json", "-o", str(log),
               "-session-file", str(sf)]
        # -server wants bare domains, not a URL (nuclei's -iserver takes the full URL)
        srv = ",".join(_server_hosts(server)) if server else ""
        if srv:
            cmd += ["-server", srv]
        if token:
            # The config remains private for exactly the process lifetime.  Authentication material is
            # never exposed through argv, process listings, telemetry, or runtime-identity evidence.
            config = claims.enter_context(
                secrets.private_tool_config("interactsh", {"token": str(token)}),
            )
            cmd += ["-config", str(config)]
        admitted_cmd, admitted_env = _prepare_client_launch(run, cmd, lifetime=claims)
        proc = _spawn_client(spawn_owner, claims, admitted_cmd, admitted_env, cwd=run.dir)
        parsed = _await_register(proc, server, wait)
        if parsed is None:
            close_session(proc)
            return None
        domain, uid = parsed
        session = {"domain": domain, "unique_id": uid, "token_map": {}, "started": _utc(),
                   "log": _repository_ref(run, log, field="log"),
                   "session_file": _repository_ref(run, sf, field="session_file"), "server": server}
        save_session(run, session)
        return session, proc
    except BaseException:
        proc = proc or spawn_owner.get("proc")
        if proc is None or spawn_owner.get("constructor_settled"):
            claims.close()
        else:
            close_session(proc)
        raise


def _resume_token(saved_server, current_server, token):
    """The token to reuse on resume: kept only for a self-hosted saved session whose server the current
    config still matches; a public or changed session gets none."""
    saved = _server_hosts(saved_server)
    if not saved or not token:
        return None
    return str(token) if set(_server_hosts(current_server)) == set(saved) else None


_EXPECTED_SERVER_UNSET = object()


def resume_session(run, token=None, server=None, wait: int = 12, *,
                   expected_server=_EXPECTED_SERVER_UNSET):
    """Re-open the run's owned session to poll delayed callbacks, returning (session, proc) with the
    saved token_map intact — this path never rebuilds it (open_session mints a fresh session instead).

    `server`/`token` are the current oob config; the token is coupled to the saved server (see
    `_resume_token`). Returns None if there is no saved session, no interactsh-client, or the re-registered
    domain does not match the saved one.
    """
    prev = load_session(run)
    if not prev or not prev.get("session_file"):
        return None
    # A run-scoped caller may bind the resume to its already-published channel origin.  Compare the exact
    # persisted value before staging files, creating a private config, or launching/contacting a client.
    if expected_server is not _EXPECTED_SERVER_UNSET and prev.get("server") != expected_server:
        return None
    if not shutil.which("interactsh-client"):
        return None
    from . import revision as _revision
    repository_run = all(hasattr(run, name) for name in ("dir", "project_dir", "run_id", "artifact_claim"))
    if repository_run:
        disposition, why = _revision.base_disposition(run.dir)
        old_session = resolve_session_ref(run, prev["session_file"], field="session_file")
        old_log = resolve_session_ref(run, prev.get("log") or "", field="log")
    else:
        # Narrow compatibility for lightweight argv-only adapters/tests.  Real
        # repository callers always take the strict branch above.
        disposition, why = "live", ""
        old_session = Path(prev["session_file"])
        old_log = Path(prev.get("log") or "")
    if disposition in ("finalizing", "unknown"):
        from .revision import RevisionError
        raise RevisionError(
            f"{run.dir}: {why} — refusing to resume OOB acquisition against it",
            retryable=True,
        )
    claims = ExitStack()
    spawn_owner: dict = {}
    if disposition == "live":
        # The original session remains the live candidate.  Claims cover the
        # complete interval in which an external process owns its two names.
        if repository_run:
            claims.enter_context(run.artifact_claim())
            claims.enter_context(run.artifact_claim())
        log, session_file = old_log, old_session
        session = dict(prev)
    else:
        # A sealed base is never handed back to a mutable client.  Both files
        # are copied into one unique revision candidate before launch.
        candidate = _revision.stage_oob_resume_candidate(run, old_log, old_session)
        log, session_file = candidate.log, candidate.session_file
        session = dict(prev)
        session["log"] = _repository_ref(run, log, field="log")
        session["session_file"] = _repository_ref(run, session_file, field="session_file")
        session["revision_candidate"] = candidate.name
    cmd = ["interactsh-client", "-duc", "-json", "-o", str(log),
           "-session-file", str(session_file)]
    srv = ",".join(_server_hosts(prev.get("server"))) if prev.get("server") else ""   # bare domains for -server
    if srv:
        cmd += ["-server", srv]
    eff_token = _resume_token(prev.get("server"), server, token)
    if eff_token:
        config = claims.enter_context(
            secrets.private_tool_config("interactsh", {"token": eff_token}),
        )
        cmd += ["-config", str(config)]
    proc = None
    try:
        identity_directory = log.parent if disposition == "sealed" else None
        admitted_cmd, admitted_env = _prepare_client_launch(
            run, cmd, lifetime=claims, record_directory=identity_directory,
        )
        spawn_cwd = run.dir if repository_run else log.parent
        proc = _spawn_client(spawn_owner, claims, admitted_cmd, admitted_env, cwd=spawn_cwd)
        parsed = _await_register(proc, prev.get("server"), wait)
        if parsed is None or parsed[0] != prev.get("domain"):
            close_session(proc)
            return None
        return session, proc
    except BaseException:
        proc = proc or spawn_owner.get("proc")
        if proc is None or spawn_owner.get("constructor_settled"):
            claims.close()
        elif proc is not None:
            close_session(proc)
        raise


def close_session(proc) -> None:
    """Settle process, streams, and private claims while preserving cleanup-time cancellation."""
    faults: list[BaseException] = []
    try:
        # interactsh-client writes its resumable session from its SIGINT
        # handler.  Keep the runner's normal bounded SIGKILL/reap fallback.
        runner.terminate_group(proc, graceful_signal=signal.SIGINT)
    except BaseException as exc:
        faults.append(exc)
    try:
        if getattr(proc, "stdout", None):
            proc.stdout.close()
    except BaseException as exc:
        faults.append(exc)
    claims = getattr(proc, "_quarry_oob_claims", None)
    if claims is not None:
        try:
            claims.close()
        except BaseException as exc:
            faults.append(exc)
        finally:
            try:
                delattr(proc, "_quarry_oob_claims")
            except (AttributeError, TypeError):
                pass
    cancellation = next((fault for fault in faults if not isinstance(fault, Exception)), None)
    if cancellation is not None:
        raise cancellation.with_traceback(cancellation.__traceback__)
    if faults:
        raise faults[0].with_traceback(faults[0].__traceback__)


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
    log = resolve_session_ref(run, lp, field="log")
    try:
        with os.fdopen(privfs.open_ro_private(log), "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        return []
    return correlate(parse_interactsh(text), session)


# ── token issuance (the source side of correlation) ──────────────────────────────────────────────

def issue_token(session: dict, source_tool: str, target_url=None, param=None,
                payload_class: str = "oob", run=None) -> str:
    """Mint a DNS-label-safe callback token and record token -> (source_tool, target_url, param,
    payload_class) in the session's token_map; returns the token.

    The token is random and collision-checked against the map, so a mapping is never overwritten and a
    callback never misattributed. With `run` given, the session is persisted before returning, so a
    crash after a probe is injected still leaves the callback correlatable.
    """
    # Build on a copy: a rejected/durability-failed repository commit must not
    # make a token visible in memory when it never became correlatable on disk.
    candidate = dict(session)
    tmap = dict(candidate.get("token_map") or {})
    while True:
        token = "q" + os.urandom(4).hex()        # q + 8 hex chars: DNS-label-safe, ~4e9 space
        if token not in tmap:
            break
    tmap[token] = {"source_tool": source_tool, "target_url": target_url,
                   "param": param, "payload_class": payload_class}
    candidate["token_map"] = tmap
    if run is not None:
        save_session(run, candidate)
    session.clear()
    session.update(candidate)
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
