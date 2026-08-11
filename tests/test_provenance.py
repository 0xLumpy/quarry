"""C09b provenance merge — a repeat observation UNIONs into the merged entity, never discards evidence.

The regression this guards: first-writer-wins dropped a later observation entirely (its sources, raw_ref,
and richer enrichment lost). Now the merged view unions list evidence, fills empty fields, keeps the first
non-empty scalar on conflict, and preserves every observation in the append-only log.
"""
import json

import pytest

from quarry_recon.store import Run, _merge_record

pytestmark = pytest.mark.offline


def _run(tmp_path):
    try:
        return Run.create(tmp_path, "t", run_id="fixed")
    except FileExistsError:
        return Run.open(tmp_path, "t", "fixed")


class TestMergeRules:
    def test_sources_unioned(self):
        m = _merge_record({"host": "h", "sources": ["a"]}, {"host": "h", "sources": ["b", "a"]})
        assert m["sources"] == ["a", "b"]

    def test_raw_ref_folded_into_raw_refs(self):
        m = _merge_record({"host": "h", "raw_ref": "r1"}, {"host": "h", "raw_ref": "r2"})
        assert m["raw_refs"] == ["r1", "r2"] and m["raw_ref"] == "r1"

    def test_empty_field_filled(self):
        m = _merge_record({"host": "h", "cname": ""}, {"host": "h", "cname": "t.example.com"})
        assert m["cname"] == "t.example.com"

    def test_conflicting_scalar_keeps_first(self):
        # first non-empty wins in the merged view; the conflicting value survives in the obs log (tested below)
        m = _merge_record({"host": "h", "title": "A"}, {"host": "h", "title": "B"})
        assert m["title"] == "A"

    def test_list_ips_unioned(self):
        m = _merge_record({"host": "h", "a": ["1.1.1.1"]}, {"host": "h", "a": ["2.2.2.2", "1.1.1.1"]})
        assert m["a"] == ["1.1.1.1", "2.2.2.2"]

    def test_scalar_promoted_to_list_on_union(self):
        m = _merge_record({"host": "h", "tags": "x"}, {"host": "h", "tags": ["y"]})
        assert m["tags"] == ["x", "y"]

    def test_earliest_first_seen_kept(self):
        m = _merge_record({"host": "h", "first_seen": "2026-01-02"}, {"host": "h", "first_seen": "2026-01-01"})
        assert m["first_seen"] == "2026-01-01"


class TestAddMergeThroughStore:
    def test_add_returns_true_only_for_new_key(self, tmp_path):
        run = _run(tmp_path)
        assert run.add("subdomain", {"host": "h.example.com", "sources": ["a"]}) is True
        assert run.add("subdomain", {"host": "h.example.com", "sources": ["b"]}) is False   # not new
        assert run.count("subdomain") == 1

    def test_provenance_merged_not_discarded(self, tmp_path):
        run = _run(tmp_path)
        run.add("subdomain", {"host": "h.example.com", "sources": ["subfinder"], "raw_ref": "r1"})
        run.add("subdomain", {"host": "h.example.com", "sources": ["crtsh"], "raw_ref": "r2", "cname": "c"})
        rec = run.read("subdomain")[0]
        assert set(rec["sources"]) == {"subfinder", "crtsh"}
        assert set(rec["raw_refs"]) == {"r1", "r2"}
        assert rec["cname"] == "c"                          # previously-absent field filled by 2nd observation

    def test_pure_duplicate_is_noop_no_growth(self, tmp_path):
        run = _run(tmp_path)
        run.add("subdomain", {"host": "h.example.com", "sources": ["a"]})
        lines_before = run._entity_file("subdomain").read_text().count("\n")
        run.add("subdomain", {"host": "h.example.com", "sources": ["a"]})   # adds nothing new
        assert run._entity_file("subdomain").read_text().count("\n") == lines_before

    def test_value_adding_observation_is_logged(self, tmp_path):
        run = _run(tmp_path)
        run.add("subdomain", {"host": "h.example.com", "sources": ["a"]})
        run.add("subdomain", {"host": "h.example.com", "sources": ["b"]})   # new evidence → logged
        obs = [json.loads(l) for l in run._entity_file("subdomain").read_text().splitlines()]
        assert len(obs) == 2                                # both observations kept in the immutable log

    def test_conflicting_scalar_preserved_in_log(self, tmp_path):
        # merged view keeps the first title, but the conflicting one is NOT lost — it's in the obs log
        run = _run(tmp_path)
        run.add("live", {"url": "https://h/", "title": "A"})
        run.add("live", {"url": "https://h/", "title": "B"})
        assert run.read("live")[0]["title"] == "A"
        titles = {json.loads(l).get("title") for l in run._entity_file("live").read_text().splitlines()}
        assert titles == {"A", "B"}

    def test_reopened_run_recovers_merged_state(self, tmp_path):
        r1 = _run(tmp_path)
        r1.add("subdomain", {"host": "h.example.com", "sources": ["a"], "raw_ref": "r1"})
        r1.add("subdomain", {"host": "h.example.com", "sources": ["b"], "raw_ref": "r2"})
        r2 = _run(tmp_path)                                 # fresh instance folds the log
        rec = r2.read("subdomain")[0]
        assert set(rec["sources"]) == {"a", "b"} and set(rec["raw_refs"]) == {"r1", "r2"}
        assert r2.count("subdomain") == 1
