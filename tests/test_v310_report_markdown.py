from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from quarry_recon import normalize, store, triage
from quarry_recon.phases import origin
from quarry_recon.config import ScopeMatcher


pytestmark = pytest.mark.offline


def _run(tmp_path, rows):
    run = store.Run.create(tmp_path / "project", "report.example")
    for entity, record in rows:
        run.add(entity, record)
    return run


@pytest.mark.parametrize("payload,state,compat", [
    ({"url": "https://a.example/"}, "unknown", None),
    ({"url": "https://a.example/", "cdn": None}, "unknown", None),
    ({"url": "https://a.example/", "cdn": False}, "not_detected", False),
    ({"url": "https://a.example/", "cdn": True}, "detected", True),
    ({"url": "https://a.example/", "cdn": "cloudflare"}, "unknown", None),
])
def test_httpx_cdn_absence_is_not_laundered_into_false(payload, state, compat):
    [row] = normalize.httpx_json(json.dumps(payload), "fixture", "raw/httpx.jsonl")
    assert row["cdn_state"] == state
    assert row["cdn"] is compat
    assert normalize.cdn_state(row) == state


def test_legacy_inserted_false_without_explicit_state_remains_unknown():
    assert normalize.cdn_state({"url": "https://legacy.example/", "cdn": False}) == "unknown"
    assert normalize.cdn_state({"url": "https://legacy.example/", "cdn": True}) == "detected"


@pytest.mark.parametrize("first,second", [
    ({"cdn": False, "cdn_state": "not_detected"}, {"cdn": True, "cdn_state": "detected"}),
    ({"cdn": True, "cdn_state": "detected"}, {"cdn": False, "cdn_state": "not_detected"}),
    ({"cdn": None, "cdn_state": "unknown"}, {"cdn": True, "cdn_state": "detected"}),
])
def test_merged_positive_cdn_evidence_dominates_order_and_weaker_states(first, second):
    base = {"url": "https://merge.example/", **first}
    incoming = {"url": "https://merge.example/", **second}
    assert normalize.cdn_state(store.merge("live", base, incoming)) == "detected"


def test_invalid_merged_cdn_state_cannot_preserve_a_negative_claim():
    assert normalize.cdn_state({
        "cdn": False, "cdn_state": "not_detected",
        "_alt": {"cdn_state": ["provider-invented"]},
    }) == "unknown"


@pytest.mark.parametrize("row", [
    {"cdn": True, "cdn_state": "detected",
     "_alt": {"cdn_state": ["provider-invented"]}},
    {"cdn": True, "cdn_state": "detected", "_alt": {"cdn": [1]}},
    {"cdn": 1, "cdn_state": "detected"},
])
def test_positive_cdn_evidence_cannot_launder_malformed_merged_values(row):
    assert normalize.cdn_state(row) == "unknown"


@pytest.mark.parametrize("marker", [0, 1, 0.0, 1.0])
@pytest.mark.parametrize("location", ["top", "alternate"])
def test_numeric_boolean_lookalikes_cannot_preserve_a_negative_cdn_claim(marker, location):
    row = {"cdn": False, "cdn_state": "not_detected"}
    if location == "top":
        row["cdn"] = marker
    else:
        row["_alt"] = {"cdn": [marker]}
    assert normalize.cdn_state(row) == "unknown"


@pytest.mark.parametrize("url,host", [
    ("https://faß.de/x", "xn--fa-hia.de"),
    ("https://XN--FA-HIA.DE./x", "xn--fa-hia.de"),
    ("https://[2001:0db8::1]:8443/x", "2001:db8::1"),
    ("https://%65xample.com/x", ""),
    ("https://example%2ecom/x", ""),
])
def test_url_authority_uses_the_scope_idna_policy_and_refuses_encoded_ambiguity(url, host):
    assert normalize.host_of_url(url) == host


def test_report_never_infers_no_waf_or_origin_from_negative_or_absent_cdn(tmp_path):
    run = _run(tmp_path, [
        ("live", {"url": "https://negative.example/", "cdn": False, "cdn_state": "not_detected"}),
        ("live", {"url": "https://unknown.example/", "cdn": None, "cdn_state": "unknown"}),
        ("live", {"url": "https://cdn.example/", "cdn": True, "cdn_state": "detected",
                  "cdn_name": "fixture-cdn"}),
    ])
    digest = triage.digest_json(run, ScopeMatcher([], [], [], False))
    rows = {item["value"]: item for item in digest["queues"]["origin"]}
    assert rows["https://negative.example/"]["tags"] == ["direct-service-candidate", "cdn:not_detected"]
    assert "WAF state not inferred from the CDN detector" in rows["https://negative.example/"]["why"]
    assert rows["https://unknown.example/"]["tags"] == ["cdn:unknown"]
    assert "no direct-origin or WAF inference" in rows["https://unknown.example/"]["why"]
    assert rows["https://cdn.example/"]["tags"] == ["cdn:detected", "fixture-cdn"]
    blob = json.dumps(digest)
    assert "no-waf" not in blob and "likely no WAF" not in blob


def test_hotlist_qualifies_detector_state_when_positive_waf_evidence_exists(tmp_path):
    run = _run(tmp_path, [
        ("live", {"url": "https://waf.example/", "cdn": False,
                  "cdn_state": "not_detected"}),
        ("tech", {"id": "waf.example|WAF:fixture", "host": "waf.example",
                  "tech": "WAF:fixture",
                  "sources": ["nuclei-waf"]}),
    ])
    rendered = triage.build(run, ScopeMatcher([], [], [], False))
    assert "WAF remains unknown" not in rendered
    assert "WAF is not inferred from" in rendered


def test_origin_correlation_uses_only_explicit_detector_negative_twins(tmp_path, monkeypatch):
    run = _run(tmp_path, [
        ("live", {"url": "https://front.example/", "host": "front.example", "cdn": True,
                  "cdn_state": "detected", "favicon": 7, "a": ["203.0.113.1"]}),
        ("live", {"url": "https://negative.example/", "host": "negative.example", "cdn": False,
                  "cdn_state": "not_detected", "favicon": 7, "a": ["203.0.113.2"]}),
        ("live", {"url": "https://unknown.example/", "host": "unknown.example", "cdn": None,
                  "cdn_state": "unknown", "favicon": 7, "a": ["203.0.113.3"]}),
    ])
    gaps = []
    monkeypatch.setattr(origin.events, "coverage_partial", lambda *args, **kwargs: gaps.append(kwargs))
    ctx = SimpleNamespace(
        run=run, scope=SimpleNamespace(passive_only=False), echo=lambda _message: None,
    )
    origin.run(ctx)
    rows = [row for row in run.read("review") if row.get("klass") == "origin-ip"]
    assert [(row["matched_host"], row["origin_ip"]) for row in rows] == [
        ("negative.example", "203.0.113.2"),
    ]
    assert gaps and "unknown CDN classification" in gaps[0]["reason"]


def test_private_json_is_exact_while_markdown_is_inert_and_visible(tmp_path):
    hostile = "# heading\n![remote](https://attacker.invalid/x)<img src=x>```\x1b[31m\u202Eend"
    run = _run(tmp_path, [("finding", {
        "id": "f1", "template": hostile, "matched": hostile, "severity": "high",
        "sources": [hostile],
    })])
    scope = ScopeMatcher([], [], [], False)

    digest = triage.digest_json(run, scope)
    [item] = digest["queues"]["scanner"]
    assert item["value"] == hostile
    assert json.loads(json.dumps(digest, ensure_ascii=False))["queues"]["scanner"][0]["value"] == hostile
    assert triage.digest_json(run, scope) == digest

    markdown = triage.build(run, scope)
    assert hostile not in markdown
    assert "\x1b" not in markdown and "\u202E" not in markdown
    assert "<img" not in markdown and "![remote]" not in markdown and "```" not in markdown
    assert "\\u000A" in markdown and "\\u001B" in markdown and "\\u202E" in markdown
    assert "\\# heading" in markdown
    assert "\\!\\[remote\\]\\(https\\:\\/\\/attacker\\.invalid\\/x\\)" in markdown
    assert "&lt;img src\\=x&gt;" in markdown


def test_markdown_encoder_covers_all_commonmark_and_control_introducers():
    raw = "# * _ ` [x](u) ![i](u) - list + item 1. one <b> | >\\\n\r\t\x00\u200b\u2067"
    encoded = triage.markdown_value(raw)
    for active in ("<b>", "![i]", "\n", "\r", "\t", "\x00", "\u200b", "\u2067"):
        assert active not in encoded
    assert "\\- list" in encoded and "\\+ item" in encoded and "1\\. one" in encoded
    assert "\\`" in encoded
    assert "\\u000A" in encoded and "\\u000D" in encoded and "\\u0009" in encoded
    assert "\\u0000" in encoded and "\\u200B" in encoded and "\\u2067" in encoded


@pytest.mark.parametrize("control", ["\u0085", "\u009b", "\u2028", "\u2029"])
def test_markdown_encodes_unicode_terminal_and_line_controls(control):
    encoded = triage.markdown_value(f"before{control}after")
    assert control not in encoded
    assert f"\\u{ord(control):04X}" in encoded


def test_private_queue_ids_hash_the_exact_typed_value_without_target_syntax():
    integer = triage._item("fixture", 1, "why", "low", [], "normalized/review.jsonl", [])
    text = triage._item("fixture", "1", "why", "low", [], "normalized/review.jsonl", [])
    hostile = triage._item(
        "fixture", "# [target](https://attacker.invalid)", "why", "low", [],
        "normalized/review.jsonl", [],
    )

    assert integer["id"] != text["id"]
    assert integer["id"] == triage._item(
        "fixture", 1, "why", "low", [], "normalized/review.jsonl", [],
    )["id"]
    assert integer["id"].startswith("fixture:sha256:") and len(integer["id"]) == 79
    assert "target" not in hostile["id"] and "attacker" not in hostile["id"]
