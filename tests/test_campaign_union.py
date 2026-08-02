"""The campaign's cumulative store — settle prerequisite C.

Entities are RUN-SCOPED, so a supervisor that repeats runs needs somewhere for what earlier children
learned to live AND must seed every later child from it. These tests pin the invariants the supervisor will
rely on: absorbing only trustworthy evidence, monotonic progress, an idempotent bootstrap, and an inherited
entity that is never counted as the child's own discovery.
"""
from __future__ import annotations

import json

import pytest

from quarry_recon import campaign, store


def _finished(tmp_path, *entities, target="t"):
    run = store.Run.create(tmp_path, target)
    for kind, rec in entities:
        run.add(kind, rec)
    run.write_manifest(profile_summary={}, phases_run=["vertical"])
    return run


class TestAbsorbingAChild:
    def test_a_child_s_entities_become_the_union(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}),
                        ("subdomain", {"host": "b.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        result = union.absorb(run.dir)
        assert (result.new, result.enriched, result.progressed) == (2, 0, True), result
        assert set(union.records) == {("subdomain", "a.acme.com"), ("subdomain", "b.acme.com")}
        assert union.path.exists() and union.path.read_text().count("\n") == 2

    def test_absorbing_the_SAME_child_twice_adds_nothing(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        assert union.absorb(run.dir).new == 1
        again = union.absorb(run.dir)
        assert (again.new, again.enriched, again.progressed) == (0, 0, False), again

    def test_ENRICHMENT_of_a_known_identity_is_progress(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        second = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["shodan"]}))
        result = union.absorb(second.dir)
        assert (result.new, result.enriched, result.progressed) == (0, 1, True), result
        held = union.records[("subdomain", "a.acme.com")]
        assert set(held["sources"]) == {"crtsh", "shodan"}          # provenance UNIONed, never replaced

    def test_an_UNREADABLE_child_is_never_absorbed_as_empty(self, tmp_path):
        """The difference between "this child found nothing" and "we could not read what it found" is the
        difference between a fixed point and a lie."""
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        (run.normalized / "subdomain.jsonl").unlink()               # the manifest still says 1
        union = campaign.Union.for_campaign(tmp_path, "c1")
        result = union.absorb(run.dir, kinds=["subdomain"])
        assert result.unusable and "unusable" in result.unusable["subdomain"], result
        assert not result.progressed and union.records == {}, result

    def test_an_OSCILLATION_is_absorbed_once(self, tmp_path):
        union = campaign.Union.for_campaign(tmp_path, "c1")
        a = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "A"}))
        b = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "B"}))
        c = _finished(tmp_path, ("live", {"url": "https://a.acme.com/", "title": "A"}))
        assert union.absorb(a.dir).new == 1
        assert union.absorb(b.dir).enriched == 1                    # the first swing IS new knowledge
        assert not union.absorb(c.dir).progressed                   # ...going back adds nothing

    def test_the_union_SURVIVES_a_corrupt_row(self, tmp_path):
        union = campaign.Union.for_campaign(tmp_path, "c1")
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["x"]}))
        union.absorb(run.dir)
        with union.path.open("ab") as fh:
            fh.write(b"{not json\n[]\n" + json.dumps({"kind": "subdomain", "record": {"no": "key"}}).encode()
                     + b"\n")
        reopened = campaign.Union(union.path)
        assert set(reopened.records) == {("subdomain", "a.acme.com")}


class TestBootstrappingTheNextChild:
    def test_a_child_STARTS_from_what_the_campaign_knows(self, tmp_path):
        """The P0 this exists for: with acquisition closed, provider-found hosts would otherwise be absent
        from the next child's corpus and the campaign would call that a fixed point."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["shodan"],
                                                   "raw_ref": "/runs/1/raw/shodan.json"}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        assert child.values("subdomain") == []                      # run-scoped: it starts EMPTY
        assert union.bootstrap(child) == {"subdomain": 1}
        assert child.values("subdomain") == ["a.acme.com"]
        seeded = child.read("subdomain")[0]
        assert seeded["sources"] == ["shodan"], seeded              # provenance INTACT
        assert seeded["raw_ref"] == "/runs/1/raw/shodan.json", seeded
        assert seeded[campaign.INHERITED] is True, seeded

    def test_an_INHERITED_entity_is_not_the_child_s_discovery(self, tmp_path):
        """`add()`'s NEW-key answer is what phases count as production. An entity the campaign handed over
        must never answer yes, or every child would report the whole union as its own find."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        assert child.add("subdomain", {"host": "a.acme.com", "sources": ["httpx"]}) is False
        assert child.add("subdomain", {"host": "new.acme.com", "sources": ["httpx"]}) is True

    def test_bootstrapping_TWICE_writes_nothing_the_second_time(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        assert union.bootstrap(child) == {"subdomain": 1}
        before = (child.normalized / "subdomain.jsonl").read_text()
        assert union.bootstrap(child) == {}
        assert (child.normalized / "subdomain.jsonl").read_text() == before

    def test_an_inherited_record_FINGERPRINTS_like_its_origin(self, tmp_path):
        """`_inherited` is bookkeeping about how this run got the entity, never a fact about the world."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        origin = union.records[("subdomain", "a.acme.com")]
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        seeded = child.read("subdomain")[0]
        assert store.fingerprint("subdomain", seeded) == store.fingerprint("subdomain", origin)

    def test_a_bootstrapped_child_can_be_absorbed_back_without_inventing_progress(self, tmp_path):
        """The round trip the supervisor will do every cycle: seed, run, absorb. What was handed over must
        not come back as discovery."""
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        child.add("subdomain", {"host": "found.acme.com", "sources": ["httpx"]})
        child.write_manifest(profile_summary={}, phases_run=["vertical"])
        result = union.absorb(child.dir, kinds=["subdomain"])
        assert (result.new, result.progressed) == (1, True), result       # ONLY the new host
        assert result.enriched == 0, result
        assert set(k for _kind, k in union.records) == {"a.acme.com", "found.acme.com"}

    def test_a_child_that_found_NOTHING_new_shows_no_progress(self, tmp_path):
        first = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(first.dir)
        child = store.Run.create(tmp_path, "t")
        union.bootstrap(child)
        child.write_manifest(profile_summary={}, phases_run=["vertical"])
        result = union.absorb(child.dir, kinds=["subdomain"])
        assert not result.progressed and (result.new, result.enriched) == (0, 0), result


class TestTheUnionIsDurable:
    def test_it_reloads_exactly(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}),
                        ("live", {"url": "https://a.acme.com/", "title": "T"}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(run.dir)
        reopened = campaign.Union(union.path)
        assert set(reopened.records) == set(union.records)
        for slot, rec in union.records.items():
            assert store.fingerprint(slot[0], reopened.records[slot]) == store.fingerprint(slot[0], rec)

    def test_every_row_carries_its_kind_identity_and_fingerprint(self, tmp_path):
        run = _finished(tmp_path, ("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]}))
        union = campaign.Union.for_campaign(tmp_path, "c1")
        union.absorb(run.dir)
        row = json.loads(union.path.read_text().splitlines()[0])
        assert row["kind"] == "subdomain" and row["id"] == "a.acme.com"
        assert row["fp"] == store.fingerprint("subdomain", row["record"])
