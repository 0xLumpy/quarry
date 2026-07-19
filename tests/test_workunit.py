"""C07 increment 3 — the work_unit scheme (the C10b resume key).

The load-bearing property: a work_unit is STABLE across runs for identical work, but changes whenever any
COVERAGE-AFFECTING input changes — so resume never skips a unit whose wordlist/rate/ports/parser changed.
Target identity alone is insufficient (Lumpy's correction). Encoded here before any caller wires it.
"""
import pytest

from quarry_recon.events import file_digest, work_unit

pytestmark = pytest.mark.offline


class TestDeterminismAndSensitivity:
    def test_identical_envelope_same_unit(self):
        a = work_unit("probe.ffuf_vhost", inputs={"origin": "https://h"}, config={"wl": "raft"})
        b = work_unit("probe.ffuf_vhost", inputs={"origin": "https://h"}, config={"wl": "raft"})
        assert a == b and len(a) == 16

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
