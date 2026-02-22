"""Tests for access control logic."""

import pytest
from localnet_access.acl import AccessControl, Policy, parse_acl_rule


class TestParseAclRule:
    def test_bare_ipv4(self):
        net = parse_acl_rule("192.168.0.10")
        assert str(net) == "192.168.0.10/32"

    def test_cidr_subnet(self):
        net = parse_acl_rule("192.168.0.0/24")
        assert str(net) == "192.168.0.0/24"

    def test_strips_whitespace(self):
        net = parse_acl_rule("  10.0.0.1  ")
        assert str(net) == "10.0.0.1/32"

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_acl_rule("not-an-ip")


class TestAccessControlPolicy:
    def test_no_rules_is_allow_all(self):
        acl = AccessControl()
        assert acl.policy == Policy.ALLOW_ALL
        assert not acl.is_restricted

    def test_allow_rules_only_is_whitelist(self):
        acl = AccessControl(allow_rules=[parse_acl_rule("192.168.0.1")])
        assert acl.policy == Policy.WHITELIST
        assert acl.is_restricted

    def test_deny_rules_only_is_blacklist(self):
        acl = AccessControl(deny_rules=[parse_acl_rule("192.168.0.1")])
        assert acl.policy == Policy.BLACKLIST
        assert acl.is_restricted

    def test_both_rules_is_whitelist(self):
        acl = AccessControl(
            allow_rules=[parse_acl_rule("192.168.0.0/24")],
            deny_rules=[parse_acl_rule("192.168.0.99")],
        )
        assert acl.policy == Policy.WHITELIST


class TestAccessControlIsAllowed:
    def test_open_allows_everyone(self):
        acl = AccessControl()
        assert acl.is_allowed("1.2.3.4")
        assert acl.is_allowed("192.168.0.1")

    def test_whitelist_allows_listed_ip(self):
        acl = AccessControl(allow_rules=[parse_acl_rule("192.168.0.10")])
        assert acl.is_allowed("192.168.0.10")

    def test_whitelist_blocks_unlisted_ip(self):
        acl = AccessControl(allow_rules=[parse_acl_rule("192.168.0.10")])
        assert not acl.is_allowed("192.168.0.11")
        assert not acl.is_allowed("10.0.0.1")

    def test_whitelist_subnet_allows_member(self):
        acl = AccessControl(allow_rules=[parse_acl_rule("192.168.0.0/24")])
        assert acl.is_allowed("192.168.0.1")
        assert acl.is_allowed("192.168.0.254")

    def test_whitelist_subnet_blocks_non_member(self):
        acl = AccessControl(allow_rules=[parse_acl_rule("192.168.0.0/24")])
        assert not acl.is_allowed("192.168.1.1")
        assert not acl.is_allowed("10.0.0.1")

    def test_blacklist_blocks_listed_ip(self):
        acl = AccessControl(deny_rules=[parse_acl_rule("192.168.0.99")])
        assert not acl.is_allowed("192.168.0.99")

    def test_blacklist_allows_unlisted_ip(self):
        acl = AccessControl(deny_rules=[parse_acl_rule("192.168.0.99")])
        assert acl.is_allowed("192.168.0.1")
        assert acl.is_allowed("10.0.0.1")

    def test_allow_and_deny_combined(self):
        # Allow the whole subnet but deny one specific IP
        acl = AccessControl(
            allow_rules=[parse_acl_rule("192.168.0.0/24")],
            deny_rules=[parse_acl_rule("192.168.0.99")],
        )
        assert acl.is_allowed("192.168.0.1")
        assert not acl.is_allowed("192.168.0.99")   # denied explicitly
        assert not acl.is_allowed("10.0.0.1")        # not in allow list

    def test_multiple_allow_rules(self):
        acl = AccessControl(allow_rules=[
            parse_acl_rule("192.168.0.10"),
            parse_acl_rule("10.0.0.5"),
        ])
        assert acl.is_allowed("192.168.0.10")
        assert acl.is_allowed("10.0.0.5")
        assert not acl.is_allowed("192.168.0.11")

    def test_multiple_deny_rules(self):
        acl = AccessControl(deny_rules=[
            parse_acl_rule("192.168.0.50"),
            parse_acl_rule("192.168.0.51"),
        ])
        assert not acl.is_allowed("192.168.0.50")
        assert not acl.is_allowed("192.168.0.51")
        assert acl.is_allowed("192.168.0.1")

    def test_invalid_ip_is_denied(self):
        acl = AccessControl()
        assert not acl.is_allowed("not-an-ip")
        assert not acl.is_allowed("")


class TestDescribeRules:
    def test_empty(self):
        assert AccessControl().describe_rules() == []

    def test_allow_rules(self):
        acl = AccessControl(allow_rules=[parse_acl_rule("192.168.0.0/24")])
        assert acl.describe_rules() == ["allow 192.168.0.0/24"]

    def test_deny_rules(self):
        acl = AccessControl(deny_rules=[parse_acl_rule("10.0.0.1")])
        assert acl.describe_rules() == ["deny  10.0.0.1/32"]

    def test_mixed_rules_order(self):
        acl = AccessControl(
            allow_rules=[parse_acl_rule("192.168.0.0/24")],
            deny_rules=[parse_acl_rule("192.168.0.99")],
        )
        rules = acl.describe_rules()
        assert rules[0].startswith("allow")
        assert rules[1].startswith("deny")
