from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from localnet_access.Policy.PolicyAcl import PolicyAcl as Policy
@dataclass
class AccessControl:
    """Evaluate whether a connecting IP should be allowed or denied.

    Modes:
      - No rules        -> allow everyone
      - --allow rules   -> whitelist: only listed IPs/subnets pass
      - --deny rules    -> blacklist: everyone except listed IPs/subnets pass
      - Both            -> allow rules checked first; if matched, allow.
                           deny rules checked second; if matched, deny.
                           Otherwise allow.
    """

    allow_rules: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    deny_rules: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )

    @property
    def policy(self) -> Policy:
        if self.allow_rules and self.deny_rules:
            return Policy.WHITELIST
        if self.allow_rules:
            return Policy.WHITELIST
        if self.deny_rules:
            return Policy.BLACKLIST
        return Policy.ALLOW_ALL

    @property
    def is_restricted(self) -> bool:
        return self.policy != Policy.ALLOW_ALL

    def is_allowed(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False

        if self.policy == Policy.ALLOW_ALL:
            return True

        if self.allow_rules:
            in_allow = any(ip in net for net in self.allow_rules)
            if self.deny_rules:
                in_deny = any(ip in net for net in self.deny_rules)
                return in_allow and not in_deny
            return in_allow

        in_deny = any(ip in net for net in self.deny_rules)
        return not in_deny

    def describe_rules(self) -> list[str]:
        
        lines: list[str] = []
        for net in self.allow_rules:
            lines.append(f"allow {net}")
        for net in self.deny_rules:
            lines.append(f"deny  {net}")
        return lines


def parse_acl_rule(raw: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse '192.168.0.10' or '192.168.0.0/24' into a network object.

    A bare IP like '192.168.0.10' becomes a /32 (single host).
    """
    raw = raw.strip()
    return ipaddress.ip_network(raw, strict=False)
