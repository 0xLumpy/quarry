"""netguard IP classification — the contact-by-default self-attack guard (batch 1).

Offensive posture: only the SCAN BOX itself (loopback/link-local/cloud-metadata/own interfaces) is ever
denied contact; PRIVATE space is contacted by default (a lead), blocked only under BLOCK_PRIVATE_TARGETS;
public is always contactable. These are pure classifiers — no resolution, so no network.
"""
import pytest

from quarry_recon import netguard

pytestmark = pytest.mark.offline


class TestSelfAttack:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "127.5.5.5", "::1", "::ffff:127.0.0.1",       # loopback (+ IPv4-mapped)
        "169.254.0.1", "fe80::1",                                  # link-local
        "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",  # cloud metadata
    ])
    def test_scan_box_and_metadata_are_self_attack(self, ip):
        assert netguard.is_self_attack_ip(ip)

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "192.168.1.10", "10.0.0.5"])
    def test_public_and_private_are_not_self_attack(self, ip):
        assert not netguard.is_self_attack_ip(ip)

    def test_unparseable_fails_closed(self):
        assert netguard.is_self_attack_ip("not-an-ip")


class TestPrivate:
    @pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.0.1", "172.16.0.1", "100.64.0.1", "fd12::1"])
    def test_private_ranges(self, ip):
        assert netguard.is_private_ip(ip)

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "127.0.0.1"])
    def test_public_and_loopback_not_private(self, ip):
        assert not netguard.is_private_ip(ip)


class TestContactable:
    def test_public_always_contactable(self):
        assert netguard.is_contactable_ip("8.8.8.8")

    def test_private_contacted_by_default(self):
        assert netguard.is_contactable_ip("10.0.0.5")

    def test_private_withheld_under_block(self):
        assert not netguard.is_contactable_ip("10.0.0.5", block_private=True)
        # ...but public still contactable even under block_private
        assert netguard.is_contactable_ip("8.8.8.8", block_private=True)

    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254"])
    def test_scan_box_never_contactable(self, ip):
        assert not netguard.is_contactable_ip(ip)
        assert not netguard.is_contactable_ip(ip, block_private=True)


class TestIntel:
    def test_records_private_and_self_not_public(self):
        # intel = every non-public answer (recorded regardless of the contact decision)
        assert netguard.intel_ips(["8.8.8.8", "10.0.0.1", "127.0.0.1", "1.1.1.1"]) == ["10.0.0.1", "127.0.0.1"]


class TestSelfDenyList:
    def test_includes_loopback_metadata_and_mapped_forms(self):
        deny = netguard.self_deny_list()
        assert "127.0.0.0/8" in deny and "169.254.169.254" in deny
