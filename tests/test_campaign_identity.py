"""Cross-run entity identity — settle prerequisite A.

A campaign compares what two CHILD RUNS know, and entities are run-scoped: a second `Run.create` in the
same project starts empty. So the comparison needs three things from a finished run — the canonical
IDENTITY of each entity, a MONOTONIC merge, and a fingerprint over MATERIAL content only. These tests pin
the properties the supervisor will rely on, not the implementation that provides them.
"""
from __future__ import annotations

import json

import pytest

from quarry_recon import store


class TestMaterialContent:
    def test_run_scoped_bookkeeping_is_NOT_material(self):
        """Artifact paths and timestamps say WHERE and WHEN we looked, not what is true. If they counted,
        every child would look like progress and a fixed point could never be reached."""
        base = {"host": "a.acme.com", "sources": ["crtsh"], "a": ["1.2.3.4"],
                "raw_ref": "/runs/1/raw/x.json", "first_seen": "t0", "last_seen": "t1"}
        later = dict(base, raw_ref="/runs/2/raw/y.json", raw_refs=["/runs/2/raw/y.json"],
                     first_seen="t9", last_seen="t9")
        assert store.fingerprint("resolved", base) == store.fingerprint("resolved", later)
        assert not store.adds_material("resolved", base, later)
        assert set(store.RUN_SCOPED_FIELDS) == {"first_seen", "last_seen", "raw_ref", "raw_refs"}

    def test_list_ORDER_is_not_material(self):
        """Two runs can report the same IPs in a different order; that is not discovery."""
        one = {"host": "a.acme.com", "a": ["1.2.3.4", "5.6.7.8"], "sources": ["crtsh", "subfinder"]}
        other = {"host": "a.acme.com", "a": ["5.6.7.8", "1.2.3.4"], "sources": ["subfinder", "crtsh"]}
        assert store.fingerprint("resolved", one) == store.fingerprint("resolved", other)
        assert not store.adds_material("resolved", one, other)

    def test_a_new_SOURCE_is_material(self):
        """Provenance is not noise: a second, independent source for the same host is a fact."""
        base = {"host": "a.acme.com", "sources": ["crtsh"]}
        assert store.adds_material("subdomain", base, {"host": "a.acme.com", "sources": ["shodan"]})

    def test_ENRICHMENT_of_a_known_identity_is_material(self):
        """The case a count can never see: same identity, same total, new knowledge."""
        base = {"host": "a.acme.com", "sources": ["crtsh"]}
        assert store.adds_material("resolved", base, {"host": "a.acme.com", "a": ["1.2.3.4"]})


class TestProgressIsMonotonic:
    def test_an_OSCILLATING_scalar_counts_ONCE(self):
        """A title, a DNS answer or a rotating certificate can alternate for ever. The first swing is a
        fact the union did not hold; going back adds nothing, because the union holds both."""
        union = {"url": "https://a.acme.com/", "title": "A"}
        assert store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "B"})
        union = store.merge("live", union, {"url": "https://a.acme.com/", "title": "B"})
        assert not store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "A"})
        assert not store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "B"})
        # ...and a THIRD, genuinely new value still is progress
        assert store.adds_material("live", union, {"url": "https://a.acme.com/", "title": "C"})

    def test_merging_never_REMOVES_a_fact(self):
        union = {"host": "a.acme.com", "sources": ["crtsh"], "a": ["1.2.3.4"], "tech": ["nginx"]}
        merged = store.merge("resolved", union, {"host": "a.acme.com", "sources": ["shodan"]})
        assert set(merged["sources"]) == {"crtsh", "shodan"}
        assert merged["a"] == ["1.2.3.4"] and merged["tech"] == ["nginx"]

    def test_a_pure_duplicate_is_not_progress(self):
        rec = {"host": "a.acme.com", "sources": ["crtsh"], "a": ["1.2.3.4"]}
        assert not store.adds_material("resolved", rec, dict(rec))


class TestIdentityAcrossRuns:
    def test_the_canonical_key_is_the_cross_run_identity(self):
        """Case, trailing dots and URL shape are the store's business, and the campaign must use the same
        rule — otherwise `API.acme.com` and `api.acme.com` are two identities in the union."""
        assert store.canonical_key("subdomain", {"host": "API.Acme.com."}) == \
            store.canonical_key("subdomain", {"host": "api.acme.com"})
        # the URL rule normalises SCHEME + HOSTNAME only: path, query and userinfo are evidence and are
        # preserved exactly (`/API` != `/api`), and an explicit port stays part of the identity
        assert store.canonical_key("live", {"url": "HTTPS://A.Acme.COM./x"}) == \
            store.canonical_key("live", {"url": "https://a.acme.com/x"})
        assert store.canonical_key("live", {"url": "https://a.acme.com/API"}) != \
            store.canonical_key("live", {"url": "https://a.acme.com/api"})

    def test_a_FINISHED_run_reads_exactly_as_it_did_while_live(self, tmp_path):
        """The supervisor reads a child AFTER it ended; folding its log must reproduce the merged view the
        run itself had — same identities, same merged provenance."""
        run = store.Run.create(tmp_path, "t")
        run.add("subdomain", {"host": "a.acme.com", "sources": ["crtsh"], "raw_ref": "/x"})
        run.add("subdomain", {"host": "A.ACME.com", "sources": ["subfinder"], "raw_ref": "/y"})
        run.add("subdomain", {"host": "b.acme.com", "sources": ["crtsh"]})
        live = {k: v for k, v in ((store.canonical_key("subdomain", r), r) for r in run.read("subdomain"))}
        folded = store.fold_observations(run.normalized / "subdomain.jsonl")
        assert folded.status == "valid" and folded.trustworthy and folded.dropped == 0, folded
        assert set(folded.records) == set(live) == {"a.acme.com", "b.acme.com"}
        assert set(folded.records["a.acme.com"]["sources"]) == {"crtsh", "subfinder"}
        for key in live:
            assert store.fingerprint("subdomain", folded.records[key]) == \
                store.fingerprint("subdomain", live[key])

    def test_a_CORRUPT_line_costs_one_observation_and_is_COUNTED(self, tmp_path):
        f = tmp_path / "subdomain.jsonl"
        f.write_text(json.dumps({"host": "a.acme.com", "sources": ["x"]}) + "\n"
                     + "{not json\n" + "[]\n" + json.dumps({"no": "key"}) + "\n"
                     + json.dumps({"host": "b.acme.com"}) + "\n")
        folded = store.fold_observations(f)
        assert set(folded.records) == {"a.acme.com", "b.acme.com"}
        assert (folded.status, folded.dropped, folded.trustworthy) == ("degraded", 3, False), folded

    def test_ONE_invalid_byte_costs_ONE_row_not_the_log(self, tmp_path):
        """`read_text()` decoded the whole file before rows were isolated, so a single 0xff destroyed every
        valid observation before and after it."""
        f = tmp_path / "subdomain.jsonl"
        f.write_bytes(json.dumps({"host": "a.acme.com"}).encode() + b"\n"
                      + b'{"host":"\xff\xfe.acme.com"}\n'
                      + json.dumps({"host": "b.acme.com"}).encode() + b"\n")
        folded = store.fold_observations(f)
        assert set(folded.records) == {"a.acme.com", "b.acme.com"}, folded
        assert (folded.status, folded.dropped) == ("degraded", 1), folded

    def test_UNREADABLE_is_never_reported_as_EMPTY(self, tmp_path):
        """The distinction a campaign lives on: bootstrapping from a lost log would drop evidence silently,
        and a fixed point declared over it would claim finished work nobody could see."""
        absent = store.fold_observations(tmp_path / "nope.jsonl")
        assert (absent.status, absent.records, absent.trustworthy) == ("absent", {}, True)
        unusable = store.fold_observations(tmp_path)              # a directory, not a log
        assert unusable.status == "unusable" and not unusable.trustworthy, unusable
        assert unusable.reason and unusable.records == {}, unusable
        empty = tmp_path / "subdomain.jsonl"
        empty.write_text("")
        clean = store.fold_observations(empty)
        assert (clean.status, clean.records, clean.trustworthy) == ("valid", {}, True)   # a REAL empty

    @pytest.mark.parametrize("entity", sorted(store.ENTITY_KEYS))
    def test_every_entity_kind_has_an_identity_and_a_fingerprint(self, entity):
        """Every kind the store can hold must be comparable across runs — a kind the campaign cannot key
        is a kind whose discovery it would silently ignore."""
        field = store.ENTITY_KEYS[entity]
        rec = {field: "value-1", "sources": ["x"]}
        assert store.canonical_key(entity, rec)
        assert store.fingerprint(entity, rec) and len(store.fingerprint(entity, rec)) == 32
        assert not store.adds_material(entity, rec, dict(rec))
        assert store.adds_material(entity, rec, {field: "value-1", "sources": ["y"]})


class TestMaterialIsCanonicalAtEveryDepth:
    def test_a_NESTED_list_order_is_not_material(self):
        """The contract says list order is never material; a shallow pass left everything below the first
        dict order-sensitive, so identical records could fingerprint differently."""
        one = {"id": "x", "detail": [{"ports": [443, 80], "tags": ["a", "b"]}]}
        other = {"id": "x", "detail": [{"tags": ["b", "a"], "ports": [80, 443]}]}
        assert store.fingerprint("finding", one) == store.fingerprint("finding", other)
        assert not store.adds_material("finding", one, other)

    def test_a_nested_ADDITION_is_still_material(self):
        one = {"id": "x", "detail": [{"ports": [443]}]}
        other = {"id": "x", "detail": [{"ports": [443, 8443]}]}
        assert store.fingerprint("finding", one) != store.fingerprint("finding", other)
