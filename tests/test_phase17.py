"""Phase 17: Deployment — env-var passphrase, health endpoint, deploy files."""
import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent


# ── health endpoint ────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_no_auth_required(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_response_shape(self, client):
        data = client.get("/health").json()
        assert data.get("status") == "ok"

    def test_node_endpoint_public(self, client):
        r = client.get("/node")
        assert r.status_code == 200
        data = r.json()
        assert "node" in data
        assert "public_key" in data


# ── CONTACC_PASSPHRASE env var ─────────────────────────────────────────────────

class TestEnvPassphrase:
    def test_env_passphrase_used_when_set(self, monkeypatch):
        from server.main import _get_passphrase
        monkeypatch.setenv("CONTACC_PASSPHRASE", "secret-from-env")
        assert _get_passphrase(key_stdin=False) == "secret-from-env"

    def test_env_passphrase_overrides_stdin_flag(self, monkeypatch):
        from server.main import _get_passphrase
        monkeypatch.setenv("CONTACC_PASSPHRASE", "env-wins")
        # key_stdin=True should still return env var value
        assert _get_passphrase(key_stdin=True) == "env-wins"

    def test_no_env_var_falls_through(self, monkeypatch):
        from server.main import _get_passphrase
        monkeypatch.delenv("CONTACC_PASSPHRASE", raising=False)
        # Can't test interactive prompt; just verify it doesn't crash when
        # env is absent and we mock stdin
        import io
        monkeypatch.setattr("sys.stdin", io.StringIO("stdin-pass\n"))
        assert _get_passphrase(key_stdin=True) == "stdin-pass"


# ── deploy files exist and are well-formed ────────────────────────────────────

class TestDeployFiles:
    def test_service_file_exists(self):
        assert (REPO_ROOT / "deploy" / "contacc.service").exists()

    def test_service_file_has_required_sections(self):
        content = (REPO_ROOT / "deploy" / "contacc.service").read_text()
        for section in ("[Unit]", "[Service]", "[Install]"):
            assert section in content

    def test_service_file_references_env_file(self):
        content = (REPO_ROOT / "deploy" / "contacc.service").read_text()
        assert "EnvironmentFile" in content

    def test_env_example_exists(self):
        assert (REPO_ROOT / "deploy" / "env.example").exists()

    def test_env_example_has_passphrase_key(self):
        content = (REPO_ROOT / "deploy" / "env.example").read_text()
        assert "CONTACC_PASSPHRASE" in content

    def test_nginx_conf_exists(self):
        assert (REPO_ROOT / "deploy" / "nginx.conf.example").exists()

    def test_nginx_conf_has_proxy_pass(self):
        content = (REPO_ROOT / "deploy" / "nginx.conf.example").read_text()
        assert "proxy_pass" in content

    def test_setup_script_exists(self):
        assert (REPO_ROOT / "deploy" / "setup.sh").exists()

    def test_setup_script_is_executable(self):
        path = REPO_ROOT / "deploy" / "setup.sh"
        assert os.access(path, os.X_OK)
