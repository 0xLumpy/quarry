"""File-output status adapters — the shared matrix and each tool's fail-closed parser.

These are the highest-risk code in the recon path: a laundered status (a degraded/failed run reported
SUCCESS) or a crash on a malformed artifact both corrupt the run verdict. Every case here mirrors a
verify-quarry.sh regression, now as a hermetic offline test.
"""
import json

import pytest

from quarry_recon.runner import (RunResult, Status, ffuf_results, reclassify_ffuf,
                                  reclassify_from_artifact, reclassify_from_files)

pytestmark = pytest.mark.offline


def _r(status, exit_code=0, stderr_tail=""):
    return RunResult("t", [], status, exit_code, 0.1, None, 0, stderr_tail=stderr_tail)


# ── shared core: reclassify_from_artifact (T1.6) ──────────────────────────────
class TestReclassifyFromArtifact:
    def test_skipped_untouched(self):
        assert reclassify_from_artifact(_r(Status.SKIPPED), 5).status == Status.SKIPPED

    @pytest.mark.parametrize("n,expect", [(3, Status.SUCCESS), (0, Status.EMPTY), (None, Status.PARTIAL)])
    def test_clean(self, n, expect):
        assert reclassify_from_artifact(_r(Status.SUCCESS), n).status == expect

    @pytest.mark.parametrize("hard", [Status.FAILED, Status.TIMED_OUT, Status.BLOCKED])
    def test_degraded_with_findings_is_partial_never_success(self, hard):
        assert reclassify_from_artifact(_r(hard), 2).status == Status.PARTIAL

    @pytest.mark.parametrize("hard", [Status.FAILED, Status.TIMED_OUT, Status.BLOCKED])
    def test_degraded_empty_keeps_hard_state(self, hard):
        # an empty/absent artifact preserves nothing → the hard state stands
        assert reclassify_from_artifact(_r(hard), 0).status == hard
        assert reclassify_from_artifact(_r(hard), None).status == hard

    def test_partial_is_not_clean(self):
        # PARTIAL + findings must stay PARTIAL, never be laundered up to SUCCESS
        assert reclassify_from_artifact(_r(Status.PARTIAL), 2).status == Status.PARTIAL

    @pytest.mark.parametrize("bad", [-1, True, 1.5, "2"])
    def test_invalid_count_fails_closed(self, bad):
        # bool/float/str/negative → treated as None (no trustworthy count), so clean → PARTIAL not SUCCESS
        assert reclassify_from_artifact(_r(Status.SUCCESS), bad).status == Status.PARTIAL

    def test_gowitness_wrapper_de_launders(self):
        # reclassify_from_files (gowitness) delegates to the core: FAILED + shots is PARTIAL, not SUCCESS
        assert reclassify_from_files(_r(Status.FAILED), 1, "screenshot").status == Status.PARTIAL
        assert reclassify_from_files(_r(Status.EMPTY), 9, "screenshot").status == Status.SUCCESS


# ── ffuf artifact adapter (batch 3 + T2.2) ────────────────────────────────────
class TestFfuf:
    def _art(self, tmp_path, payload):
        p = tmp_path / "o.json"
        p.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)
        return p

    def test_results_root_validation(self, tmp_path):
        assert ffuf_results(self._art(tmp_path, {"results": [{"u": 1}]})) == [{"u": 1}]
        assert ffuf_results(self._art(tmp_path, [])) is None          # bare list root → None (no AttributeError)
        assert ffuf_results(self._art(tmp_path, {"results": "x"})) is None
        assert ffuf_results(tmp_path / "nope.json") is None

    def test_hits_hidden_by_silent_become_success(self, tmp_path):
        a = self._art(tmp_path, {"results": [{"u": 1}]})
        assert reclassify_ffuf(_r(Status.EMPTY), a).status == Status.SUCCESS

    def test_preserved_final_is_not_current_without_native_receipt_claim(self, tmp_path):
        prior = self._art(tmp_path, {"results": [{"u": 1}]})
        result = _r(Status.EMPTY)
        result.meta["native_outputs"] = {"current_paths": []}

        reclassify_ffuf(result, prior)

        assert result.status == Status.PARTIAL
        assert "missing/malformed" in result.note

    def test_blocked_matrix_keyed_on_exit(self, tmp_path):
        empty = self._art(tmp_path, {"results": []})
        # clean exit + block signature + 0 → PARTIAL (completed); nonzero exit + 0 → stays BLOCKED
        assert reclassify_ffuf(RunResult("ffuf", [], Status.BLOCKED, 0, 0.1, empty, 0), empty).status == Status.PARTIAL
        assert reclassify_ffuf(RunResult("ffuf", [], Status.BLOCKED, 1, 0.1, empty, 0), empty).status == Status.BLOCKED

    def test_hard_state_not_laundered(self, tmp_path):
        hits = self._art(tmp_path, {"results": [{"u": 1}]})
        assert reclassify_ffuf(RunResult("ffuf", [], Status.FAILED, 0, 0.1, hits, 0), hits).status == Status.PARTIAL
        empty = self._art(tmp_path, {"results": []})
        assert reclassify_ffuf(RunResult("ffuf", [], Status.FAILED, 0, 0.1, empty, 0), empty).status == Status.FAILED

    def test_native_maxtime_demotes_clean_to_partial(self, tmp_path):
        # ffuf -maxtime stops mid-wordlist, finalizes the artifact, exits clean → must NOT be SUCCESS/EMPTY
        mt = "[WARN] Maximum running time for entire process reached, exiting."
        hits = self._art(tmp_path, {"results": [{"u": 1}]})
        empty = self._art(tmp_path, {"results": []})
        assert reclassify_ffuf(RunResult("ffuf", [], Status.EMPTY, 0, 0.1, hits, 0, stderr_tail=mt), hits).status == Status.PARTIAL
        assert reclassify_ffuf(RunResult("ffuf", [], Status.EMPTY, 0, 0.1, empty, 0, stderr_tail=mt), empty).status == Status.PARTIAL


# ── gitleaks report adapter (T1.3) ────────────────────────────────────────────
class TestGitleaks:
    def _rep(self, tmp_path, content):
        from quarry_recon.phases import crawl
        p = tmp_path / "rep.json"
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        r = _r(Status.EMPTY)
        return crawl._gitleaks_status(r, p), r.status

    def test_clean_findings(self, tmp_path):
        items, st = self._rep(tmp_path, '[{"RuleID":"aws","Secret":"x"}]')
        assert items == [{"RuleID": "aws", "Secret": "x"}] and st == Status.SUCCESS

    def test_clean_empty(self, tmp_path):
        assert self._rep(tmp_path, "[]") == ([], Status.EMPTY)

    @pytest.mark.parametrize("bad", ['{"x":1}', "null", '[{"a":1},"nope"]', "GARBAGE{", b"\xff\xfe"])
    def test_malformed_root_or_row_returns_none(self, tmp_path, bad):
        items, st = self._rep(tmp_path, bad)
        assert items is None and st == Status.PARTIAL       # clean run but no trustworthy report → PARTIAL

    def test_hard_state_kept(self, tmp_path):
        # FAILED + a valid empty report: the report parses ([]), but a degraded run keeps its hard state
        from quarry_recon.phases import crawl
        p = tmp_path / "r.json"
        p.write_text("[]")
        r = _r(Status.FAILED)
        assert crawl._gitleaks_status(r, p) == [] and r.status == Status.FAILED


# ── smap -oJ adapter (T1.6) ───────────────────────────────────────────────────
class TestSmap:
    def _art(self, tmp_path, payload, raw=None):
        p = tmp_path / "s.json"
        p.write_bytes(raw) if raw is not None else p.write_text(json.dumps(payload))
        return p

    def _rec(self, ip="1.2.3.4", uh="h.example.com", ports=((80, "http"),)):
        return {"ip": ip, "user_hostname": uh, "hostnames": ["sh.com"],
                "ports": [{"port": p, "service": s} for p, s in ports]}

    def test_parse_valid(self, tmp_path):
        from quarry_recon.phases import probe
        recs, complete = probe._smap_records(self._art(tmp_path, [self._rec()]))
        assert recs == [("1.2.3.4", "h.example.com", ["sh.com"], [(80, "http")])] and complete

    def test_keeps_valid_drops_malformed(self, tmp_path):
        from quarry_recon.phases import probe
        recs, complete = probe._smap_records(self._art(tmp_path, [
            self._rec(),
            ["not-a-dict"],
            {"ip": "bad", "ports": []},                      # invalid IP
            {"ip": "5.6.7.8", "user_hostname": "b.example.com", "hostnames": [],
             "ports": [{"port": 22, "service": "ssh"}, {"port": 99999}, {"port": True}]},
        ]))
        assert not complete                                  # malformed rows/ports seen
        assert [r[0] for r in recs] == ["1.2.3.4", "5.6.7.8"]
        assert recs[1][3] == [(22, "ssh")]                   # out-of-range 99999 + bool port dropped

    @pytest.mark.parametrize("bad", [None])
    def test_unreadable_root_none(self, tmp_path, bad):
        from quarry_recon.phases import probe
        assert probe._smap_records(tmp_path / "nope.json") == (None, False)
        assert probe._smap_records(self._art(tmp_path, {"not": "list"})) == (None, False)
        assert probe._smap_records(self._art(tmp_path, None, raw=b"GARBAGE{")) == (None, False)


# ── nmap -oX adapter (T1.6) ───────────────────────────────────────────────────
class TestNmap:
    FIN = '<runstats><finished exit="success"/></runstats>'

    def _xml(self, tmp_path, hosts, fin=None):
        p = tmp_path / "n.xml"
        p.write_text(f'<?xml version="1.0"?><nmaprun>{hosts}{self.FIN if fin is None else fin}</nmaprun>')
        return p

    HOST = ('<host><address addr="1.2.3.4" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.20"/></port>'
            '<port protocol="tcp" portid="443"><state state="closed"/></port>'
            '<port protocol="tcp" portid="8080"><state state="open"/></port></ports></host>')

    def test_open_ports_complete(self, tmp_path):
        from quarry_recon.phases import probe
        svcs, complete = probe._nmap_services(self._xml(tmp_path, self.HOST))
        assert svcs == [("1.2.3.4", 80, "tcp", "http", "nginx", "1.20"), ("1.2.3.4", 8080, "tcp", "", "", "")]
        assert complete                                      # 443 closed skipped; clean finish

    def test_no_finished_marker_incomplete_keeps_rows(self, tmp_path):
        from quarry_recon.phases import probe
        svcs, complete = probe._nmap_services(self._xml(tmp_path, self.HOST, fin=""))
        assert len(svcs) == 2 and not complete               # rows kept, but completion uncertain → caller PARTIAL

    def test_errored_finish_incomplete(self, tmp_path):
        from quarry_recon.phases import probe
        _, complete = probe._nmap_services(self._xml(tmp_path, self.HOST,
                                                     fin='<runstats><finished exit="error"/></runstats>'))
        assert not complete

    @pytest.mark.parametrize("bad", ["<nmaprun><host", "<other/>"])
    def test_malformed_or_wrong_root_none(self, tmp_path, bad):
        from quarry_recon.phases import probe
        p = tmp_path / "b.xml"
        p.write_text(bad)
        assert probe._nmap_services(p) == (None, False)


class TestPublishBytesNeverDestroysWhatItCannotReplace:
    """`publish_bytes` is the atomic primitive every paid and evidential artifact goes through. If it
    can leave a destination empty on failure, "atomic" is a claim rather than a property.
    """

    def test_a_failed_write_leaves_the_ORIGINAL_in_place(self, tmp_path, monkeypatch):
        import hashlib
        import pathlib

        from quarry_recon import budget

        dest = tmp_path / "artifact.json"
        dest.write_bytes(b"the evidence we already hold")
        new = b"a replacement that never lands"

        import os

        def _fail(fd, *a, **k):
            os.close(fd)
            raise OSError("no space left on device")

        monkeypatch.setattr(os, "fdopen", _fail)
        ok = budget.publish_bytes(dest, new, digest=hashlib.sha256(new).hexdigest())
        assert ok is False
        assert dest.read_bytes() == b"the evidence we already hold", \
            "a destination must never be unlinked before its replacement exists"

    def test_wrong_bytes_at_the_name_are_SUPERSEDED(self, tmp_path):
        import hashlib

        from quarry_recon import budget

        dest = tmp_path / "artifact.json"
        dest.write_bytes(b"truncated")
        new = b"the whole thing"
        assert budget.publish_bytes(dest, new, digest=hashlib.sha256(new).hexdigest())
        assert dest.read_bytes() == new


class TestALedgerFailsClosedOnBytesItCannotDecode:
    """`unreadable` exists so a store we cannot trust blocks work instead of reading as empty. A raised
    UnicodeDecodeError bypasses that entirely and takes the lane down with it.
    """

    def test_an_undecodable_snapshot_is_UNREADABLE(self, tmp_path):
        from quarry_recon import budget

        state = tmp_path / "lane.json"
        state.write_bytes(b'{"lane": "a1d", "done": \xff\xfe}')
        led = budget.Ledger(state, lane="a1d")
        assert led.unreadable, "invalid bytes must mark the store unreadable, not raise"
        assert led.done == {}

    def test_an_undecodable_journal_is_UNREADABLE(self, tmp_path):
        from quarry_recon import budget

        state = tmp_path / "lane.json"
        state.write_text('{"lane": "a1d", "done": {}, "digests": {}}')
        state.with_name(state.name + ".journal").write_bytes(b"\xff\xfe not text\n")
        led = budget.Ledger(state, lane="a1d")
        assert led.unreadable, "an undecodable journal must mark the store unreadable, not raise"

    def test_ledger_writable_agrees_with_append(self, tmp_path):
        """The shared predicate must refuse everything `_append` refuses, or it promises a write the
        ledger will not perform."""
        from quarry_recon import budget

        state = tmp_path / "lane.json"
        state.write_bytes(b'{"lane": "a1d", "done": \xff}')
        led = budget.Ledger(state, lane="a1d")
        assert led.unreadable
        assert budget.ledger_writable(led) is False
        assert led.checkpoint() is False


class TestPublishBytesRefusesSymlinks:
    """An artifact tree holds attacker-adjacent names, so a planted link must never let a publish
    read, overwrite or certify a file outside it.
    """

    def test_staging_happens_inside_a_PRIVATE_directory(self, tmp_path, monkeypatch):
        """Another user cannot create, swap or unlink a name inside a 0700 directory we made, so the
        rename has nothing to race against."""
        import hashlib
        import os
        import pathlib

        from quarry_recon import budget

        seen = {}
        real_mkdir = os.mkdir

        def _spy(path, mode=0o777, *a, **k):
            seen["name"], seen["mode"] = str(path), mode
            return real_mkdir(path, mode, *a, **k)

        monkeypatch.setattr(os, "mkdir", _spy)
        art = tmp_path / "artifacts"
        art.mkdir()
        dest = art / "page.json"
        data = b"published"
        assert budget.publish_bytes(dest, data, digest=hashlib.sha256(data).hexdigest())
        assert seen["mode"] == 0o700, f"staging directory created {seen['mode']:o}"
        assert seen["name"].startswith(".quarry-stage-")
        assert list(art.glob(".quarry-stage-*")) == [], "the staging directory must not be left behind"
        assert dest.read_bytes() == data

    def test_the_staging_directory_is_opened_by_DESCRIPTOR_not_by_name(self, tmp_path, monkeypatch):
        """Reopening it by pathname would resolve through the parent again, which is the entry an
        attacker controls — so the second open must be relative to the parent descriptor."""
        import ast
        import inspect

        from quarry_recon import budget

        tree = ast.parse(inspect.getsource(budget.publish_bytes))
        opens = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, "attr", None) == "open"
                 and any(k.arg == "dir_fd" for k in n.keywords)]
        assert len(opens) == 2, "both the staging directory and the artifact open relative to an fd"

    def test_a_planted_staging_directory_is_refused(self, tmp_path, monkeypatch):
        """`mkdir` fails if the name exists, so a planted directory — or a link pretending to be one —
        stops the publish instead of being written into."""
        import hashlib

        from quarry_recon import budget

        outside = tmp_path / "outside"
        outside.mkdir()
        art = tmp_path / "artifacts"
        art.mkdir()
        monkeypatch.setattr(budget, "_token", lambda: "deadbeef")
        (art / ".quarry-stage-deadbeef").symlink_to(outside)

        dest = art / "page.json"
        data = b"published"
        assert budget.publish_bytes(dest, data, digest=hashlib.sha256(data).hexdigest()) is False
        assert list(outside.iterdir()) == [], "nothing may be written through a planted name"
        assert not dest.exists()

    def test_replacing_the_staging_DIRECTORY_cannot_redirect_the_publish(self, tmp_path, monkeypatch):
        """The staging directory's entry lives in a parent anyone with write access can rename. The
        rename resolves through a held descriptor instead, so swapping that entry redirects nothing."""
        import hashlib

        from quarry_recon import budget

        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"elsewhere")
        art = tmp_path / "artifacts"
        art.mkdir()
        dest = art / "page.json"
        data = b"published"
        monkeypatch.setattr(budget, "_token", lambda: "cafe1234")
        stage = art / ".quarry-stage-cafe1234"
        evil = tmp_path / "evil"
        evil.mkdir()
        (evil / "artifact").symlink_to(outside)

        real_digest = budget._fd_digest

        def _swap(fd):                              # between the write and the rename
            out = real_digest(fd)
            if stage.is_dir():
                stage.rename(tmp_path / "moved-away")
                evil.rename(stage)                  # the NAME now points at the attacker's directory
            return out

        monkeypatch.setattr(budget, "_fd_digest", _swap)
        assert budget.publish_bytes(dest, data, digest=hashlib.sha256(data).hexdigest()) is True
        assert not dest.is_symlink(), "the publish followed a replaced directory entry"
        assert dest.read_bytes() == data
        assert outside.read_bytes() == b"elsewhere"

    def test_a_planted_FIFO_at_the_destination_does_not_hang(self, tmp_path):
        """`O_RDONLY` on a FIFO blocks until someone writes to it. The publisher must not be stoppable
        by a name in its own artifact tree."""
        import hashlib
        import os
        import signal

        from quarry_recon import budget

        art = tmp_path / "artifacts"
        art.mkdir()
        dest = art / "page.json"
        os.mkfifo(dest)
        data = b"published"

        class _Blocked(BaseException):
            """NOT an OSError: `publish_bytes` catches those, and a swallowed alarm would let a
            blocking open pass as an ordinary failure."""

        def _die(*_a):
            raise _Blocked("publish_bytes blocked on a FIFO")

        signal.signal(signal.SIGALRM, _die)
        signal.alarm(2)
        try:
            budget.publish_bytes(dest, data, digest=hashlib.sha256(data).hexdigest())
        except _Blocked:
            raise AssertionError("publish_bytes blocked on a planted FIFO")
        finally:
            signal.alarm(0)

    def test_the_destination_is_never_digested_by_PATHNAME(self, tmp_path, monkeypatch):
        """A name checked and then reopened can be swapped in between, so the already-published check
        reads through the descriptor it opened and never hands the path to a digest helper."""
        import hashlib

        from quarry_recon import budget

        data = b"already here"
        dig = hashlib.sha256(data).hexdigest()
        dest = tmp_path / "page.json"
        dest.write_bytes(data)

        by_path = []
        monkeypatch.setattr(budget.events, "file_digest",
                            lambda p, *a, **k: (by_path.append(p), dig)[1])
        assert budget.publish_bytes(dest, data, digest=dig) is True
        assert by_path == [], f"the destination was digested by pathname: {by_path}"

    def test_a_planted_DESTINATION_link_is_never_certified(self, tmp_path):
        """`lstat`, not `exists()`: digesting the link's TARGET would report someone else's file as
        already published — and then the caller records ownership of a page it never wrote."""
        import hashlib

        from quarry_recon import budget

        data = b"published"
        dig = hashlib.sha256(data).hexdigest()
        outside = tmp_path / "outside.json"
        outside.write_bytes(data)                  # the target ALREADY holds the exact bytes
        art = tmp_path / "artifacts"
        art.mkdir()
        dest = art / "page.json"
        dest.symlink_to(outside)

        assert budget.publish_bytes(dest, data, digest=dig)
        assert not dest.is_symlink(), "the link must be replaced, never published through"
        assert dest.read_bytes() == data and outside.read_bytes() == data


class TestStagingIsProvenOursBeforeItIsUsed:
    """Between the `mkdir` and the open that pins it, the name still lives in a parent someone else
    may be able to write. The directory we end up holding has to prove it is the one we made.
    """

    def test_a_directory_swapped_in_after_the_mkdir_is_refused(self, tmp_path, monkeypatch):
        import hashlib
        import os

        from quarry_recon import budget

        art = tmp_path / "artifacts"
        art.mkdir()
        dest = art / "page.json"
        monkeypatch.setattr(budget, "_token", lambda: "beefcafe")
        stage = art / ".quarry-stage-beefcafe"
        evil = tmp_path / "evil"
        evil.mkdir(mode=0o777)

        real_mkdir = os.mkdir

        def _swap(path, mode=0o777, *a, **k):       # runs the swap the instant ours exists
            real_mkdir(path, mode, *a, **k)
            if stage.is_dir():
                stage.rmdir()
                evil.rename(stage)

        monkeypatch.setattr(os, "mkdir", _swap)
        data = b"published"
        assert budget.publish_bytes(dest, data, digest=hashlib.sha256(data).hexdigest()) is False
        assert not dest.exists(), "a swapped staging directory must not carry a publish"

    def test_a_pre_existing_directory_is_never_removed(self, tmp_path, monkeypatch):
        """`mkdir` fails on an existing name, and cleanup must not then delete whatever was there —
        it belongs to someone else."""
        import hashlib

        from quarry_recon import budget

        art = tmp_path / "artifacts"
        art.mkdir()
        monkeypatch.setattr(budget, "_token", lambda: "0badc0de")
        squatter = art / ".quarry-stage-0badc0de"
        squatter.mkdir()

        data = b"published"
        assert budget.publish_bytes(art / "page.json", data,
                                    digest=hashlib.sha256(data).hexdigest()) is False
        assert squatter.is_dir(), "cleanup removed a directory this call did not create"

    def test_cleanup_never_removes_a_REPLACEMENT_at_our_name(self, tmp_path, monkeypatch):
        """`created` proves this call made a directory, not that the name still holds it. If ours is
        renamed away and something else takes the name, the rmdir would be deleting a stranger's."""
        import hashlib
        import os

        from quarry_recon import budget

        art = tmp_path / "artifacts"
        art.mkdir()
        dest = art / "page.json"
        monkeypatch.setattr(budget, "_token", lambda: "feedface")
        stage = art / ".quarry-stage-feedface"
        replacement = tmp_path / "theirs"
        replacement.mkdir()

        real_replace = os.replace

        def _swap(src, dst, **kw):                  # after the artifact lands, before cleanup
            out = real_replace(src, dst, **kw)
            if stage.is_dir():
                stage.rename(tmp_path / "ours-moved")
                replacement.rename(stage)
            return out

        monkeypatch.setattr(os, "replace", _swap)
        data = b"published"
        assert budget.publish_bytes(dest, data, digest=hashlib.sha256(data).hexdigest()) is True
        assert stage.is_dir(), "cleanup removed a directory that had taken our name"
