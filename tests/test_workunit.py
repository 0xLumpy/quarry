"""C07 increment 3 — the work_unit scheme (the C10b resume key).

The load-bearing property: a work_unit is STABLE across runs for identical work, but changes whenever any
COVERAGE-AFFECTING input changes — so resume never skips a unit whose wordlist/rate/ports/parser changed.
Target identity alone is insufficient (Lumpy's correction). Encoded here before any caller wires it.
"""
import json

import pytest

from quarry_recon.events import file_digest, work_unit

pytestmark = pytest.mark.offline


class TestDeterminismAndSensitivity:
    def test_identical_envelope_same_unit(self):
        a = work_unit("probe.ffuf_vhost", inputs={"origin": "https://h"}, config={"wl": "raft"})
        b = work_unit("probe.ffuf_vhost", inputs={"origin": "https://h"}, config={"wl": "raft"})
        assert a == b and len(a) == 32       # review#10: 128-bit key (was 64-bit) — collision-safe across lanes

    def test_source_id_changes_unit(self):
        assert work_unit("a", inputs={"x": 1}) != work_unit("b", inputs={"x": 1})

    def test_semantic_input_changes_unit(self):
        assert work_unit("s", inputs={"origin": "https://a"}) != work_unit("s", inputs={"origin": "https://b"})

    def test_coverage_config_changes_unit(self):
        # a WIDER wordlist / different ports / recursion depth must produce a new unit (not skip on resume)
        base = work_unit("s", inputs={"o": "h"}, config={"wordlist": "small", "recursion": 0})
        assert base != work_unit("s", inputs={"o": "h"}, config={"wordlist": "big", "recursion": 0})
        assert base != work_unit("s", inputs={"o": "h"}, config={"wordlist": "small", "recursion": 2})

    def test_input_file_digest_changes_unit(self):
        base = work_unit("s", inputs={"o": "h"}, file_digests={"wl": "aaa"})
        assert base != work_unit("s", inputs={"o": "h"}, file_digests={"wl": "bbb"})

    def test_schema_version_changes_unit(self):
        assert work_unit("s", inputs={"o": "h"}, schema_version=1) != work_unit("s", inputs={"o": "h"}, schema_version=2)

    def test_key_order_does_not_matter(self):
        assert work_unit("s", inputs={"a": 1, "b": 2}) == work_unit("s", inputs={"b": 2, "a": 1})

    def test_envelope_version_folded(self):
        # review#10: the envelope version is part of the key — bumping it (a format change) invalidates old units
        import quarry_recon.events as ev
        a = work_unit("s", inputs={"o": "h"})
        ev._WORKUNIT_ENVELOPE_VERSION += 1
        try:
            assert a != work_unit("s", inputs={"o": "h"})
        finally:
            ev._WORKUNIT_ENVELOPE_VERSION -= 1


class TestNucleiTemplateFingerprint:
    """review#10: nuclei's resume key must fold the installed template SET — a templates update changes
    coverage, so a done chunk must not be skipped against a newer template set."""

    def test_missing_config_is_none_nonresumable(self, tmp_path, monkeypatch):
        # review#6: unreadable template state -> None (the caller then makes the unit non-resumable)
        from quarry_recon.phases import params
        monkeypatch.setenv("NUCLEI_CONFIG", str(tmp_path / "nope"))
        assert params._nuclei_templates_fp() is None

    def test_version_and_ignore_hash_both_folded(self, tmp_path, monkeypatch):
        # review#6: fold the COMPLETE effective state — version AND ignore-hash, not just the first field
        import json as _json
        from quarry_recon.phases import params
        cfgdir = tmp_path / "nuclei"; cfgdir.mkdir()
        monkeypatch.setenv("NUCLEI_CONFIG", str(cfgdir))
        cf = cfgdir / ".templates-config.json"
        cf.write_text(_json.dumps({"nuclei-templates-version": "v10.2.3", "nuclei-ignore-hash": "aaa"}))
        fp1 = params._nuclei_templates_fp()
        assert "v10.2.3" in fp1 and "aaa" in fp1
        # a changed .nuclei-ignore (same version) still flips the fingerprint — was previously ignored
        cf.write_text(_json.dumps({"nuclei-templates-version": "v10.2.3", "nuclei-ignore-hash": "bbb"}))
        assert params._nuclei_templates_fp() != fp1

    def test_unknown_template_state_is_non_resumable(self, tmp_path, monkeypatch, capsys):
        # review#6: with no template config, _nuclei_scan folds a per-run nonce so two runs over the SAME hosts
        # produce DIFFERENT scan work_units — resume never skips a chunk we cannot prove ran on the same set.
        from quarry_recon.phases import params
        from quarry_recon import events, settings
        from quarry_recon.runner import RunResult, Status
        from types import SimpleNamespace
        monkeypatch.setenv("NUCLEI_CONFIG", str(tmp_path / "nope"))          # -> _nuclei_templates_fp() is None
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 2 if k == "NUCLEI_CHUNK_HOSTS" else d)
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(params, "exec_tool",
                            lambda tool, cmd, timeout=None, **k: RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, None, 0))

        def _scan_wu(i):
            d = tmp_path / f"run{i}"
            class _R:
                dir = d
                def raw_path(self, ph, tl, nm):
                    p = d / "raw" / ph / tl / nm; p.parent.mkdir(parents=True, exist_ok=True); return p
            class _C:
                run = _R(); http_timeout = 60
                def write_list(self, nm, it):
                    p = d / "w" / nm; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("\n".join(it)); return p
            events.reset(); events.configure(d)
            c = _C()
            f = c.run.raw_path("params", "nuclei", "findings.jsonl")
            params._nuclei_scan(c, ["h0", "h1", "h2"], f, c.run.raw_path("params", "nuclei", "log"),
                                SimpleNamespace(http_rl=0))
            return json.loads(c.run.raw_path("params", "nuclei", "chunks.state.json").read_text())["work_unit"]

        assert _scan_wu(1) != _scan_wu(2)                   # fresh nonce each run -> non-resumable


class TestFileDigest:
    def test_same_bytes_same_digest(self, tmp_path):
        p = tmp_path / "wl.txt"; p.write_text("a\nb\nc\n")
        q = tmp_path / "wl2.txt"; q.write_text("a\nb\nc\n")
        assert file_digest(p) == file_digest(q) and len(file_digest(p)) == 64

    def test_changed_bytes_change_digest(self, tmp_path):
        p = tmp_path / "wl.txt"; p.write_text("a\nb\n")
        d1 = file_digest(p)
        p.write_text("a\nb\nc\n")                          # wordlist grew → different digest → different unit
        assert file_digest(p) != d1

    def test_missing_file_is_empty_digest(self, tmp_path):
        assert file_digest(tmp_path / "nope.txt") == ""

    def test_digest_feeds_work_unit(self, tmp_path):
        p = tmp_path / "wl.txt"; p.write_text("a\n")
        u1 = work_unit("probe.ffuf_vhost", inputs={"o": "h"}, file_digests={"wordlist": file_digest(p)})
        p.write_text("a\nb\nc\nd\n")                       # a completed origin with a WIDER wordlist ...
        u2 = work_unit("probe.ffuf_vhost", inputs={"o": "h"}, file_digests={"wordlist": file_digest(p)})
        assert u1 != u2                                    # ... must NOT be skipped on resume


class TestWorkUnitOnEvents:
    def test_start_finish_carry_work_unit(self):
        from quarry_recon import events
        events.reset()
        wu = work_unit("probe.ffuf_vhost", inputs={"origin": "https://h"})
        st = events.tool_start("probe.ffuf_vhost", work_unit=wu)
        fn = events.tool_finish("probe.ffuf_vhost", status="success", work_unit=wu)
        assert st["work_unit"] == wu and fn["work_unit"] == wu      # start + terminal share the resume key

    def test_none_work_unit_dropped(self):
        from quarry_recon import events
        events.reset()
        st = events.tool_start("vertical.subfinder")               # single-shot lane: no work_unit
        assert "work_unit" not in st                               # None-dropped (no fabricated field)
