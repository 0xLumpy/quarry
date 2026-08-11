"""QR39-006 — sensitive artifacts are private BY CONSTRUCTION, under any umask.

Run / OSINT / OOB / normalized-secret / export data (including full discovered secret values) must be
created 0700/0600 with descriptor-based, no-follow semantics — never inheriting a permissive umask, never
chmod-after-write. The matrix runs the real write paths under umask 000/002/022/077 and asserts no
sensitive artifact is group- or other-readable.
"""
import os
import stat
from pathlib import Path

import pytest

from quarry_recon import exports, oob, privfs
from quarry_recon.config import TargetProfile
from quarry_recon.osint import OsintSession
from quarry_recon.store import Run

pytestmark = pytest.mark.offline

_UMASKS = [0o000, 0o002, 0o022, 0o077]


def _group_other_readable(root: Path, *, exclude=()):
    bad = []
    for p in Path(root).rglob("*"):
        if p.is_symlink() or p.name in exclude:
            continue
        if stat.S_IMODE(p.lstat().st_mode) & 0o077:
            bad.append((str(p), oct(stat.S_IMODE(p.lstat().st_mode))))
    return bad


@pytest.fixture
def umask(request):
    prev = os.umask(request.param)
    try:
        yield request.param
    finally:
        os.umask(prev)


@pytest.mark.parametrize("umask", _UMASKS, indirect=True, ids=lambda u: f"umask{oct(u)}")
def test_run_artifacts_are_private_under_any_umask(tmp_path: Path, umask):
    run = Run.create(tmp_path, "audit")
    run.add("secret", {"id": "s1", "value": "AKIA-full-discovered-secret"})
    run.add("subdomain", {"host": "a.example.com"})
    run.write_manifest({}, [], metrics=None, policy=None)
    exports.write_all(run)
    exports.write_delta(run)

    bad = _group_other_readable(tmp_path / "recon")
    assert not bad, f"group/other-readable under umask {oct(umask)}: {bad}"

    # the run tree roots are 0700, the sensitive logs/exports are 0600
    assert stat.S_IMODE(run.dir.lstat().st_mode) == 0o700
    assert stat.S_IMODE(run.normalized.lstat().st_mode) == 0o700
    assert stat.S_IMODE((run.normalized / "secret.jsonl").lstat().st_mode) == 0o600
    assert stat.S_IMODE((run.exports / "secrets.jsonl").lstat().st_mode) == 0o600
    assert stat.S_IMODE(run.manifest_path.lstat().st_mode) == 0o600


def _profile(tmp_path: Path) -> "TargetProfile":
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: audit\nAPEX_DOMAINS: [example.com]\n"
                 "OOS: []\nCIDR: []\nASN: []\nRATELIMIT: {}\nPORTS: {HTTP: [443]}\nMODES: {}\n")
    return TargetProfile.load(p)


@pytest.mark.parametrize("umask", _UMASKS, indirect=True, ids=lambda u: f"umask{oct(u)}")
def test_osint_session_artifacts_are_private(tmp_path: Path, umask):
    profile = _profile(tmp_path)
    session = OsintSession(tmp_path, "audit")
    session.candidate("acme-corp.example", "apex", "azmap-tenant", "related", "tenant of example.com")
    session.raw_path("azmap", "example.com.json").write_text("x")  # a raw file we create the DIR for
    session.finalize(profile)

    # the raw file above is written by write_text (tool-shaped); exclude it — the DIR must still be private
    bad = _group_other_readable(tmp_path / "osint", exclude=("example.com.json",))
    assert not bad, f"group/other-readable under umask {oct(umask)}: {bad}"
    assert stat.S_IMODE((session.raw / "azmap").lstat().st_mode) == 0o700
    assert stat.S_IMODE((session.dir / "candidates.jsonl").lstat().st_mode) == 0o600


@pytest.mark.parametrize("umask", _UMASKS, indirect=True, ids=lambda u: f"umask{oct(u)}")
def test_oob_session_map_is_private(tmp_path: Path, umask):
    run = Run.create(tmp_path, "audit")
    oob.save_session(run, {"domain": "x.oast.pro", "unique_id": "x",
                           "token_map": {"tok": "correlated-secret"}, "started": "now"})
    p = oob.session_path(run)
    assert stat.S_IMODE(p.lstat().st_mode) == 0o600
    assert not (stat.S_IMODE(p.parent.lstat().st_mode) & 0o077)


def test_load_session_hardens_a_loose_pre_existing_map(tmp_path: Path):
    run = Run.create(tmp_path, "audit")
    p = oob.session_path(run)
    privfs.private_dir(p.parent)
    p.write_text('{"token_map": {}}')       # a map written loosely by an earlier vulnerable version
    os.chmod(p, 0o644)
    assert oob.load_session(run) == {"token_map": {}}
    assert stat.S_IMODE(p.lstat().st_mode) == 0o600   # validated + restored to private on load


def test_load_session_refuses_a_symlinked_map(tmp_path: Path):
    run = Run.create(tmp_path, "audit")
    p = oob.session_path(run)
    privfs.private_dir(p.parent)
    secret = tmp_path / "elsewhere.json"
    secret.write_text('{"token_map": {"tok": "attacker-reads-this"}}')
    p.symlink_to(secret)                     # session path swapped to a symlink after harden's stat
    assert oob.load_session(run) is None     # refused, never followed


def test_events_sink_dir_is_private(tmp_path: Path):
    from quarry_recon import events
    d = tmp_path / "run"
    events.configure(d)
    try:
        events.tool_finish("probe.httpx", status="success")
        assert stat.S_IMODE(d.lstat().st_mode) == 0o700   # 0700 parent: group/other cannot traverse to the sink
    finally:
        events.reset()


@pytest.mark.parametrize("umask", _UMASKS, indirect=True, ids=lambda u: f"umask{oct(u)}")
def test_privfs_primitives_ignore_umask(tmp_path: Path, umask):
    d = privfs.private_dir(tmp_path / "a" / "b" / "c")
    assert stat.S_IMODE(d.lstat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "a").lstat().st_mode) == 0o700   # every created level, not just the leaf
    f = tmp_path / "a" / "secret.txt"
    privfs.write_private(f, "s")
    assert stat.S_IMODE(f.lstat().st_mode) == 0o600
    privfs.append_private(tmp_path / "a" / "log.jsonl", "{}\n")
    assert stat.S_IMODE((tmp_path / "a" / "log.jsonl").lstat().st_mode) == 0o600


def test_write_private_is_unaffected_by_a_planted_predictable_temp(tmp_path: Path):
    # the exclusive random temp defeats a plant at the old predictable name; the attacker target is untouched
    target = tmp_path / "outside"
    target.write_text("original")
    dest = tmp_path / "dest.json"
    dest.with_name(f".{dest.name}.{os.getpid()}.tmp").symlink_to(target)
    privfs.write_private(dest, "payload")
    assert target.read_text() == "original"
    assert dest.read_text() == "payload" and privfs.is_private(dest)


def test_open_private_refuses_a_symlinked_parent(tmp_path: Path):
    # a symlinked PARENT component must not redirect a private write outside the intended tree
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "evil").symlink_to(outside)
    with pytest.raises(OSError):
        privfs.open_private(tmp_path / "evil" / "secret.txt")
    assert not (outside / "secret.txt").exists()


def test_open_private_refuses_a_fifo(tmp_path: Path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)                              # a planted FIFO must not hang or be written as "private"
    with pytest.raises(OSError):
        privfs.open_private(fifo)


def test_open_private_tightens_an_existing_loose_file(tmp_path: Path):
    f = tmp_path / "loose"
    f.write_text("x")
    os.chmod(f, 0o666)
    os.close(privfs.open_private(f, append=True))   # must not report success while leaving it group/other-readable
    assert stat.S_IMODE(f.lstat().st_mode) == 0o600


def test_events_sink_file_is_0600(tmp_path: Path):
    from quarry_recon import events
    events.configure(tmp_path / "run")
    try:
        events.tool_finish("probe.httpx", status="success")
        j = tmp_path / "run" / "events.jsonl"
        assert stat.S_IMODE(j.lstat().st_mode) == 0o600   # the file contract, not only the 0700 parent
    finally:
        events.reset()


def test_load_session_rejects_a_non_object_json(tmp_path: Path):
    run = Run.create(tmp_path, "audit")
    p = oob.session_path(run)
    privfs.private_dir(p.parent)
    privfs.write_private(p, '"just a string"')   # a stored non-object must not reach a caller's .get()
    assert oob.load_session(run) is None


def test_degradation_marker_is_private(tmp_path: Path):
    from quarry_recon import events
    events.configure(tmp_path / "run")
    try:
        events._degraded["writes_failed"] = 1
        events.persist_degraded()
        m = tmp_path / "run" / "events.degraded.json"
        assert stat.S_IMODE(m.lstat().st_mode) == 0o600
    finally:
        events.reset()


def test_degradation_marker_load_refuses_a_symlink(tmp_path: Path):
    from quarry_recon import events
    d = tmp_path / "run"
    privfs.private_dir(d)
    secret = tmp_path / "elsewhere.json"
    secret.write_text('{"writes_failed": 99, "first_error": "attacker"}')
    (d / "events.degraded.json").symlink_to(secret)   # planted symlink must not be followed on load
    events.configure(d)
    try:
        assert events._degraded["writes_failed"] == 0   # refused, fresh record
    finally:
        events.reset()


def test_load_session_sanitizes_a_malformed_token_map(tmp_path: Path):
    run = Run.create(tmp_path, "audit")
    p = oob.session_path(run)
    privfs.private_dir(p.parent)
    privfs.write_private(p, '{"token_map": {"good": {"source_tool": "x"}, "bad": "a-string"}}')
    s = oob.load_session(run)
    assert s["token_map"] == {"good": {"source_tool": "x"}}   # string entry dropped; correlate() can't crash


def test_open_ro_private_refuses_a_symlinked_parent(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("data")
    (tmp_path / "evil").symlink_to(outside)                 # a symlinked parent must not redirect the read
    with pytest.raises(OSError):
        privfs.open_ro_private(tmp_path / "evil" / "secret")


def test_load_session_coerces_a_list_unique_id(tmp_path: Path):
    from quarry_recon import oob as _oob
    run = Run.create(tmp_path, "audit")
    p = _oob.session_path(run)
    privfs.private_dir(p.parent)
    privfs.write_private(p, '{"unique_id": ["not", "a", "string"], "token_map": {}}')
    s = _oob.load_session(run)
    _oob.correlate([{"interaction_domain": "x.y"}], s)      # must not crash on .lower() of a list
    assert s["unique_id"] == ""


def test_open_ro_private_raises_when_it_cannot_make_the_file_private(tmp_path, monkeypatch):
    f = tmp_path / "loose"
    f.write_text("x")
    os.chmod(f, 0o644)
    monkeypatch.setattr(privfs.os, "fchmod", lambda *a, **k: (_ for _ in ()).throw(OSError("EPERM")))
    with pytest.raises(OSError):                        # a loose file we can't tighten is refused, not accepted
        privfs.open_ro_private(f)


def test_correlate_tolerates_a_non_str_interaction_domain():
    from quarry_recon import oob as _oob
    rows = [{"interaction_domain": ["not", "a", "str"]}]
    _oob.correlate(rows, {"unique_id": "u", "token_map": {}})   # must not crash on .lower()


def test_load_session_coerces_a_list_log(tmp_path: Path):
    from quarry_recon import oob as _oob
    run = Run.create(tmp_path, "audit")
    p = _oob.session_path(run)
    privfs.private_dir(p.parent)
    privfs.write_private(p, '{"log": ["a", "b"], "token_map": {}}')
    s = _oob.load_session(run)
    assert s["log"] == "" and _oob.poll_session(run, s) == []   # Path("") does not crash
