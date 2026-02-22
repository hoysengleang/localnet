"""Tests for network utility functions."""

import pytest
from localnet_access.network import parse_target


class TestParseTarget:
    def test_port_only(self):
        host, port = parse_target("3000")
        assert host == "127.0.0.1"
        assert port == 3000

    def test_localhost_colon_port(self):
        host, port = parse_target("localhost:8080")
        assert host == "localhost"
        assert port == 8080

    def test_ip_colon_port(self):
        host, port = parse_target("192.168.0.1:5000")
        assert host == "192.168.0.1"
        assert port == 5000

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError):
            parse_target("notaport")
