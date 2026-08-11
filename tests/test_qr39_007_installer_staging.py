"""QR39-007 — safe Go archive staging: private op dir, no-follow single descriptor, member validation.

The remediation must verify and extract from the SAME descriptor (never reopen a name a privileged step
will use) and must refuse any traversal/absolute/symlink member, extracting nothing outside the op dir.
"""
import gzip
import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest

from quarry_recon import bootstrap
from quarry_recon.bootstrap import _ArchiveError, _safe_tar_members, _verify_and_extract

pytestmark = pytest.mark.offline


def _sink(*a, **k):
    pass


def _write_tar(path: Path, members) -> str:
    """members: list of (name, kind, payload). kind in {'file','dir','symlink','abs'}. Returns sha256."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, payload in members:
            if kind == "dir":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "symlink":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            else:  # 'file' / 'abs' both write a regular file with the given name
                data = payload.encode()
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                ti.mode = 0o755
                tf.addfile(ti, io.BytesIO(data))
    raw = gzip.compress(buf.getvalue())
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_happy_path_extracts_go_tree_inside_op_dir(tmp_path):
    arc = tmp_path / "go.tgz"
    sha = _write_tar(arc, [("go", "dir", None), ("go/bin", "dir", None),
                           ("go/bin/go", "file", "#!/bin/true\n")])
    dest = tmp_path / "root"
    _verify_and_extract(arc, sha, dest)
    extracted = dest / "go" / "bin" / "go"
    assert extracted.is_file()
    # every extracted path stays under the op dir
    assert dest.resolve() in extracted.resolve().parents


def test_sha_mismatch_refuses(tmp_path):
    arc = tmp_path / "go.tgz"
    _write_tar(arc, [("go/bin/go", "file", "x")])
    with pytest.raises(_ArchiveError, match="sha256 mismatch"):
        _verify_and_extract(arc, "0" * 64, tmp_path / "root")


def test_traversal_member_refused_and_nothing_escapes(tmp_path):
    op = tmp_path / "op"
    op.mkdir()
    arc = op / "go.tgz"
    sha = _write_tar(arc, [("../evil.txt", "file", "pwn")])
    with pytest.raises(_ArchiveError, match="escapes"):
        _verify_and_extract(arc, sha, op / "root")
    assert not (tmp_path / "evil.txt").exists()   # the traversal target above the op dir
    assert not (op / "evil.txt").exists()


def test_absolute_member_refused(tmp_path):
    arc = tmp_path / "go.tgz"
    sha = _write_tar(arc, [("/etc/evil", "abs", "pwn")])
    with pytest.raises(_ArchiveError, match="escapes|unsafe"):
        _verify_and_extract(arc, sha, tmp_path / "root")


def test_symlink_member_refused(tmp_path):
    arc = tmp_path / "go.tgz"
    sha = _write_tar(arc, [("go/link", "symlink", "/etc/passwd")])
    with pytest.raises(_ArchiveError, match="unsafe archive member"):
        _verify_and_extract(arc, sha, tmp_path / "root")


def test_verified_descriptor_is_the_used_descriptor(tmp_path, monkeypatch):
    """The archive is opened exactly once: the bytes hashed are the bytes extracted (no TOCTOU reopen)."""
    arc = tmp_path / "go.tgz"
    sha = _write_tar(arc, [("go/bin/go", "file", "ok")])
    opens = {"n": 0}
    real_open = os.open

    def counting_open(path, flags, *a, **k):
        if Path(path) == arc:
            opens["n"] += 1
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(bootstrap.os, "open", counting_open)
    _verify_and_extract(arc, sha, tmp_path / "root")
    assert opens["n"] == 1


def test_safe_members_returns_all_when_clean(tmp_path):
    arc = tmp_path / "go.tgz"
    _write_tar(arc, [("go", "dir", None), ("go/x", "file", "y")])
    with tarfile.open(arc) as tf:
        members = _safe_tar_members(tf, (tmp_path / "root").resolve())
    assert {m.name for m in members} == {"go", "go/x"}


def _go_calls(monkeypatch, fail_on):
    """Drive _swap_in_golang with sudo disabled and _sh stubbed; `fail_on(cmd)->bool` chooses which shell
    command returns nonzero. Returns (ok, detail, recorded_calls)."""
    calls = []

    def fake_sh(cmd, dry, timeout=1800):
        calls.append(cmd)
        return (1, "stub-fail") if fail_on(cmd) else (0, "")

    monkeypatch.setattr(bootstrap, "_sudo", lambda: "")
    monkeypatch.setattr(bootstrap, "_sh", fake_sh)
    ok, detail = bootstrap._swap_in_golang(Path("/tmp/cand"))
    return ok, detail, calls


def test_go_swap_builds_replacement_before_touching_live_and_exchanges_atomically(monkeypatch):
    """The replacement is copied into place BEFORE anything live is touched, and (live present) activation is an
    atomic RENAME_EXCHANGE — the live tree is never moved/deleted before its replacement is staged."""
    ok, _detail, calls = _go_calls(monkeypatch, fail_on=lambda c: False)
    assert ok is True
    cp_at = next(i for i, c in enumerate(calls) if c.startswith("cp -a"))
    exch_at = next(i for i, c in enumerate(calls) if "renameat2" in c)
    assert cp_at < exch_at                                        # build fully, then activate
    # no destructive displacement of the live tree before the exchange
    assert not any("mv /usr/local/go " in c for c in calls[:exch_at])
    assert not any(c.startswith("rm -rf") and "/usr/local/go " in c and ".new" not in c and "last-good" not in c
                   for c in calls[:exch_at])


def test_go_swap_rolls_back_last_good_after_symlink_step_fails(monkeypatch):
    """A post-activation /usr/local/bin/go symlink failure swaps the rejected tree back out for last-good."""
    ok, detail, calls = _go_calls(monkeypatch, fail_on=lambda c: c.startswith("ln -sf"))
    assert ok is False and "symlink step failed" in detail
    # the exchange-back restores last-good into /usr/local/go
    assert any("renameat2" in c and "last-good" in c for c in calls)


def test_go_swap_staging_copy_failure_leaves_live_untouched(monkeypatch):
    """If the staging copy fails, nothing that mutates the live tree ever runs."""
    ok, _detail, calls = _go_calls(monkeypatch, fail_on=lambda c: c.startswith("cp -a"))
    assert ok is False
    assert not any("renameat2" in c for c in calls)              # never reached activation
    assert not any("/usr/local/go/bin/go" in c for c in calls)   # never re-pointed the launcher


def test_go_swap_falls_back_when_renameat2_unavailable(monkeypatch):
    """With no renameat2, activation falls back to a move-in that still displaces the live tree only AFTER the
    replacement is staged, and keeps last-good."""
    ok, _detail, calls = _go_calls(monkeypatch, fail_on=lambda c: "renameat2" in c)
    assert ok is True
    assert any("mv /usr/local/go /usr/local/go.last-good && mv /usr/local/go.new" in c for c in calls)


def test_jxscout_swaps_only_after_verification_and_is_transactional():
    """The jxscout install verifies the engine (sha256 + a live node run) entirely in the temp dir BEFORE the
    rollback trap is armed and the staged tree/cjs are swapped in; the live tree is moved aside to last-good
    (never rm'd before staging), and the only rm of the live tree lives inside the rollback body."""
    from quarry_recon.registry import load_tools

    t = next(t for t in load_tools() if t.bin == "jxscout-chunks")
    inst = t.install
    sha_at = inst.index("sha256sum -c")
    node_at = inst.index('node "$D')
    trap_at = inst.index("trap ")
    activate_at = inst.index('mv "$Q/jxscout.new" "$Q/jxscout"')
    disarm_at = inst.index("trap - EXIT")
    assert sha_at < trap_at and node_at < trap_at                # verified before the transaction is armed
    assert trap_at < activate_at < disarm_at
    # the live tree is preserved (moved to last-good), not deleted, before the swap
    assert 'mv "$Q/jxscout" "$Q/jxscout.last-good"' in inst
    # the replacement staged in the share dir is what gets moved in (not a temp clone), and the cjs likewise
    assert 'mv "$Q/.cjs.new" "$Q/jxscout-chunk-discoverer.cjs"' in inst


def test_failed_data_refresh_leaves_previous_file_intact(tmp_path, monkeypatch):
    """A failed or empty download replaces nothing: it goes to a temp and only atomic-replaces on success, so
    the previous resolver/wordlist file survives."""
    dest = tmp_path / "resolvers.txt"
    dest.write_text("GOOD-RESOLVERS\n")

    monkeypatch.setattr(bootstrap, "_curl_to", lambda url, d, dry, timeout=300: (22, "404"))
    code, _ = bootstrap._download_atomic("https://x/r", dest, False)
    assert code != 0
    assert dest.read_text() == "GOOD-RESOLVERS\n"                 # untouched on HTTP failure

    def empty_curl(url, d, dry, timeout=300):
        Path(d).write_text("")                                   # 200 but zero bytes
        return 0, ""

    monkeypatch.setattr(bootstrap, "_curl_to", empty_curl)
    code, _ = bootstrap._download_atomic("https://x/r", dest, False)
    assert code != 0
    assert dest.read_text() == "GOOD-RESOLVERS\n"                 # untouched on empty body
    assert not list(tmp_path.glob(".resolvers.txt.*"))           # temp cleaned up


def test_go_preservation_failure_is_loud_no_false_restore(monkeypatch):
    """If the old tree cannot be preserved as last-good after the atomic exchange, that is surfaced — never
    reported as a restored last-good."""
    ok, detail, _calls = _go_calls(
        monkeypatch, fail_on=lambda c: c.startswith("mv /usr/local/go.new") and "last-good" in c)
    assert ok is False
    assert "could NOT preserve" in detail and "restored last-good" not in detail


def test_go_symlink_and_restore_failure_reports_inconsistent(monkeypatch):
    """When the symlink step fails AND last-good cannot be restored, the result says so — it does not falsely
    claim last-good was restored."""
    def fail_on(c):
        return (c.startswith("ln -sf")
                or ("renameat2" in c and "last-good" in c)              # exchange-back fails
                or "rm -rf /usr/local/go && mv /usr/local/go.last-good" in c)   # mv fallback fails
    ok, detail, _calls = _go_calls(monkeypatch, fail_on=fail_on)
    assert ok is False
    assert "could NOT be restored" in detail and "may be inconsistent" in detail


def test_failed_data_update_keeps_existing_valid_file_and_reports_failure(tmp_path, monkeypatch):
    """A failed UPDATE of an existing valid file leaves it intact (never overwritten with fallback) AND is
    recorded as a failure in the InstallResult, so `quarry update` reports it instead of exiting success."""
    dest = tmp_path / "resolvers.txt"
    dest.write_text("GOOD-EXISTING\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(bootstrap, "load_bootstrap",
                        lambda: {"data_files": [{"name": "resolvers", "url": "https://x/r",
                                                 "dest": str(dest), "update": True,
                                                 "fallback": "FALLBACK-CONTENT"}]})
    monkeypatch.setattr(bootstrap, "_download_atomic", lambda url, d, dry, timeout=300: (22, "404"))

    res = bootstrap.install_data_files(_sink, False, update=True)
    assert dest.read_text() == "GOOD-EXISTING\n"               # not clobbered with fallback
    assert res.ok is False and "resolvers" in (res.detail or "")   # failure recorded, not a false success


def test_set_data_file_failed_refresh_keeps_existing_and_reports_failure(tmp_path, monkeypatch):
    """set_data_file: a failed refresh of an existing valid file keeps it (no fallback clobber) and returns
    False — never a false success."""
    dest = tmp_path / "resolvers.txt"
    dest.write_text("GOOD-EXISTING\n")
    monkeypatch.setattr(bootstrap, "load_bootstrap",
                        lambda: {"data_files": [{"name": "resolvers", "url": "https://x/r",
                                                 "dest": str(dest), "fallback": "FALLBACK-CONTENT"}]})
    monkeypatch.setattr(bootstrap, "_download_atomic", lambda url, d, dry, timeout=300: (22, "404"))

    ok = bootstrap.set_data_file("resolvers", None, _sink, False)
    assert ok is False
    assert dest.read_text() == "GOOD-EXISTING\n"               # kept, not fallback-clobbered


def test_go_preserve_failure_exchanges_back_keeps_original(monkeypatch):
    """A preserve failure after the atomic exchange EXCHANGES BACK to the original tree (live install
    unchanged) and drops the rejected new tree — never deletes the old tree, never claims restored-last-good."""
    ok, detail, calls = _go_calls(
        monkeypatch, fail_on=lambda c: c.startswith("mv /usr/local/go.new") and "last-good" in c)
    assert ok is False
    assert "restored the original" in detail and "restored last-good" not in detail
    assert sum(1 for c in calls if "renameat2" in c) >= 2       # forward exchange + exchange-back


def test_jxscout_ast_verifies_both_digests_before_activating():
    """jxscout-ast verifies BOTH pinned digests against the TEMP tree before moving anything live, so a bad
    digest installs nothing."""
    from quarry_recon.registry import load_tools

    inst = next(t for t in load_tools() if t.bin == "jxscout-ast").install
    verify_at = inst.index("sha256sum -c")
    move_live_at = inst.index('mv "$D/jxscout_ast" "$Q/jxscout"')
    assert verify_at < move_live_at                             # verify precedes activation
    assert "%s/jxscout_ast/internal/modules/ast-analyzer/ast-analyzer.js" in inst   # verified in the TEMP tree
    assert 'mv "$D/jxscout_ast" ~/.local/share/quarry/jxscout' not in inst          # no pre-verify live move


def test_jxscout_chunks_first_install_rollback_removes_new_tree():
    """On a FIRST install (no last-good) the rollback trap REMOVES the newly-placed tree + cjs, so a failed
    second move leaves nothing half-installed."""
    from quarry_recon.registry import load_tools

    inst = next(t for t in load_tools() if t.bin == "jxscout-chunks").install
    assert 'else rm -rf "$Q/jxscout" "$Q/jxscout-chunk-discoverer.cjs"; fi' in inst
