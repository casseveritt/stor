"""Phase 33: setup_deploy.py generates Caddyfile and systemd service."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PYTHON = sys.executable
ROOT = Path(__file__).parent.parent


@pytest.fixture
def node_config(tmp_path):
    store = tmp_path / "node"
    r = subprocess.run(
        [PYTHON, str(ROOT / "tools/init_node.py"),
         "--store", str(store),
         "--address", "https://example.hopto.org",
         "--key-stdin"],
        input="test-passphrase\n",
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    return store / "node_config.json"


def _run(node_config, extra=(), out_dir=None):
    if out_dir is None:
        out_dir = node_config.parent / "deploy"
    r = subprocess.run(
        [PYTHON, str(ROOT / "tools/setup_deploy.py"),
         "--config", str(node_config),
         "--port", "8765",
         "--out", str(out_dir),
         *extra],
        capture_output=True, text=True,
    )
    return r, out_dir


class TestSetupDeploy:
    def test_generates_caddyfile(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        assert r.returncode == 0, r.stderr
        assert (out_dir / "Caddyfile").exists()

    def test_generates_service_file(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        assert (out_dir / "contacc.service").exists()

    def test_caddyfile_contains_domain(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        content = (out_dir / "Caddyfile").read_text()
        assert "example.hopto.org" in content

    def test_caddyfile_contains_port(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        content = (out_dir / "Caddyfile").read_text()
        assert "8765" in content

    def test_service_contains_config_path(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        content = (out_dir / "contacc.service").read_text()
        assert str(node_config) in content

    def test_service_contains_port(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        content = (out_dir / "contacc.service").read_text()
        assert "--port 8765" in content

    def test_service_binds_localhost(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        content = (out_dir / "contacc.service").read_text()
        assert "127.0.0.1" in content

    def test_service_references_secrets_file(self, node_config, tmp_path):
        r, out_dir = _run(node_config, out_dir=tmp_path / "deploy")
        content = (out_dir / "contacc.service").read_text()
        assert "EnvironmentFile=" in content
        assert "secrets" in content

    def test_node_address_override_updates_config(self, node_config, tmp_path):
        _run(node_config, extra=["--node-address", "https://new.example.com"],
             out_dir=tmp_path / "deploy")
        config = json.loads(node_config.read_text())
        assert config["node_address"] == "https://new.example.com"

    def test_node_address_override_appears_in_caddyfile(self, node_config, tmp_path):
        r, out_dir = _run(node_config, extra=["--node-address", "https://custom.example.com"],
                          out_dir=tmp_path / "deploy")
        content = (out_dir / "Caddyfile").read_text()
        assert "custom.example.com" in content

    def test_nonhttps_address_warns(self, node_config, tmp_path):
        r, out_dir = _run(node_config, extra=["--node-address", "http://plain.example.com"],
                          out_dir=tmp_path / "deploy")
        assert "Warning" in r.stderr

    def test_missing_config_fails(self, tmp_path):
        r, _ = _run(tmp_path / "nonexistent.json", out_dir=tmp_path / "deploy")
        assert r.returncode != 0

    def test_instructions_printed(self, node_config, tmp_path):
        r, _ = _run(node_config, out_dir=tmp_path / "deploy")
        assert "Caddy" in r.stdout
        assert "systemctl" in r.stdout

    def test_https_port_443_no_port_in_caddyfile_address(self, node_config, tmp_path):
        r, out_dir = _run(node_config, extra=["--https-port", "443"],
                          out_dir=tmp_path / "deploy")
        content = (out_dir / "Caddyfile").read_text()
        # site address should be just the domain, no :443
        first_line = content.split("\n")[0]
        assert ":443" not in first_line

    def test_https_port_8443_in_caddyfile_address(self, node_config, tmp_path):
        r, out_dir = _run(node_config, extra=["--https-port", "8443"],
                          out_dir=tmp_path / "deploy")
        content = (out_dir / "Caddyfile").read_text()
        assert ":8443" in content.split("\n")[0]

    def test_https_port_in_instructions(self, node_config, tmp_path):
        r, _ = _run(node_config, extra=["--https-port", "8443"],
                    out_dir=tmp_path / "deploy")
        assert "8443" in r.stdout
