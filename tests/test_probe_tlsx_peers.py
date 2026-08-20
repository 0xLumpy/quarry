"""Exact TLS target peers are derived from this run's resolved evidence."""

import pytest

from quarry_recon.phases.probe import _tlsx_approved_peers


pytestmark = pytest.mark.offline


def test_tlsx_peers_use_only_submitted_hosts_a_and_aaaa_records():
    peers = _tlsx_approved_peers([
        {"host": "a.example.test", "a": ["8.8.8.8"],
         "aaaa": ["2001:4860:4860::8888"]},
        {"host": "b.example.test", "a": ["1.1.1.1"]},
        {"host": "outside.example", "a": ["9.9.9.9"]},
        {"host": "a.example.test", "a": ["8.8.8.8"]},
    ], ("a.example.test", "b.example.test"))

    assert peers == ("1.1.1.1", "8.8.8.8", "2001:4860:4860::8888")


def test_tlsx_peers_refuse_invalid_current_resolution_answers():
    with pytest.raises(ValueError):
        _tlsx_approved_peers([
            {"host": "a.example.test", "a": ["not-an-address"]},
        ], ("a.example.test",))

    with pytest.raises(ValueError, match="lacks exact resolved peers"):
        _tlsx_approved_peers([
            {"host": "a.example.test", "a": ["8.8.8.8"]},
        ], ("a.example.test", "b.example.test"))
