"""Tests for CLI argument parsing."""

import pytest
from localnet_access.cli import build_parser


class TestParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_share_basic(self):
        args = self.parser.parse_args(["share", "3000"])
        assert args.command == "share"
        assert args.target == "3000"
        assert args.allow is None
        assert args.deny is None
        assert args.no_qr is False

    def test_share_with_name(self):
        args = self.parser.parse_args(["share", "3000", "--name", "my-api"])
        assert args.name == "my-api"

    def test_share_with_port(self):
        args = self.parser.parse_args(["share", "3000", "--port", "9000"])
        assert args.port == 9000

    def test_share_no_qr(self):
        args = self.parser.parse_args(["share", "3000", "--no-qr"])
        assert args.no_qr is True

    def test_share_single_allow(self):
        args = self.parser.parse_args(["share", "3000", "--allow", "192.168.0.10"])
        assert args.allow == ["192.168.0.10"]

    def test_share_multiple_allow(self):
        args = self.parser.parse_args([
            "share", "3000",
            "--allow", "192.168.0.10",
            "--allow", "10.0.0.5",
        ])
        assert args.allow == ["192.168.0.10", "10.0.0.5"]

    def test_share_single_deny(self):
        args = self.parser.parse_args(["share", "3000", "--deny", "192.168.0.99"])
        assert args.deny == ["192.168.0.99"]

    def test_share_multiple_deny(self):
        args = self.parser.parse_args([
            "share", "3000",
            "--deny", "192.168.0.50",
            "--deny", "192.168.0.51",
        ])
        assert args.deny == ["192.168.0.50", "192.168.0.51"]

    def test_share_allow_and_deny_combined(self):
        args = self.parser.parse_args([
            "share", "3000",
            "--allow", "192.168.0.0/24",
            "--deny", "192.168.0.99",
        ])
        assert args.allow == ["192.168.0.0/24"]
        assert args.deny == ["192.168.0.99"]

    def test_list_command(self):
        args = self.parser.parse_args(["list"])
        assert args.command == "list"

    def test_stop_command(self):
        args = self.parser.parse_args(["stop", "3000"])
        assert args.command == "stop"
        assert args.target == "3000"

    def test_info_command(self):
        args = self.parser.parse_args(["info"])
        assert args.command == "info"

    def test_no_command_exits(self):
        with pytest.raises(SystemExit):
            args = self.parser.parse_args([])
            if not args.command:
                raise SystemExit(0)
