"""Phase 32: SSO configuration tooling — init_node --google flags and configure_sso.py."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PYTHON = sys.executable
ROOT = Path(__file__).parent.parent


# ── init_node with SSO flags ──────────────────────────────────────────────────

class TestInitNodeSSO:
    def test_init_with_google_flags(self, tmp_path):
        store = tmp_path / "sso_node"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_node.py"),
             "--store", str(store),
             "--address", "https://test.example.com",
             "--google-client-id", "test-client-id",
             "--google-client-secret", "test-secret",
             "--key-stdin"],
            input="test-passphrase\n",
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        config = json.loads((store / "node_config.json").read_text())
        assert config["sso_google_client_id"] == "test-client-id"
        assert config["sso_google_client_secret"] == "test-secret"

    def test_init_reports_sso_configured(self, tmp_path):
        store = tmp_path / "sso_node2"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_node.py"),
             "--store", str(store),
             "--address", "https://test.example.com",
             "--google-client-id", "my-id",
             "--google-client-secret", "my-secret",
             "--key-stdin"],
            input="test-passphrase\n",
            capture_output=True, text=True,
        )
        assert "Google SSO: configured" in r.stdout

    def test_init_without_sso_flags_omits_keys(self, tmp_path):
        store = tmp_path / "no_sso_node"
        subprocess.run(
            [PYTHON, str(ROOT / "tools/init_node.py"),
             "--store", str(store),
             "--address", "https://test.example.com",
             "--key-stdin"],
            input="test-passphrase\n",
            capture_output=True, text=True,
        )
        config = json.loads((store / "node_config.json").read_text())
        assert config.get("sso_google_client_id") is None
        assert config.get("sso_google_client_secret") is None

    def test_init_google_env_vars(self, tmp_path, monkeypatch):
        store = tmp_path / "env_sso_node"
        monkeypatch.setenv("CONTAC_GOOGLE_CLIENT_ID", "env-client-id")
        monkeypatch.setenv("CONTAC_GOOGLE_CLIENT_SECRET", "env-secret")
        import os
        env = {**os.environ,
               "CONTAC_GOOGLE_CLIENT_ID": "env-client-id",
               "CONTAC_GOOGLE_CLIENT_SECRET": "env-secret"}
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_node.py"),
             "--store", str(store),
             "--address", "https://test.example.com",
             "--key-stdin"],
            input="test-passphrase\n",
            capture_output=True, text=True,
            env=env,
        )
        assert r.returncode == 0, r.stderr
        config = json.loads((store / "node_config.json").read_text())
        assert config["sso_google_client_id"] == "env-client-id"
        assert config["sso_google_client_secret"] == "env-secret"


# ── configure_sso.py ──────────────────────────────────────────────────────────

class TestConfigureSSO:
    @pytest.fixture
    def node_config(self, tmp_path):
        store = tmp_path / "configure_test"
        subprocess.run(
            [PYTHON, str(ROOT / "tools/init_node.py"),
             "--store", str(store),
             "--address", "https://test.example.com",
             "--key-stdin"],
            input="test-passphrase\n",
            capture_output=True, text=True,
        )
        return store / "node_config.json"

    def test_configure_adds_credentials(self, node_config):
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(node_config),
             "--google-client-id", "new-id",
             "--google-client-secret", "new-secret"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        config = json.loads(node_config.read_text())
        assert config["sso_google_client_id"] == "new-id"
        assert config["sso_google_client_secret"] == "new-secret"

    def test_configure_reports_success(self, node_config):
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(node_config),
             "--google-client-id", "my-id",
             "--google-client-secret", "my-secret"],
            capture_output=True, text=True,
        )
        assert "Google SSO configured" in r.stdout

    def test_configure_clear(self, node_config):
        # first set credentials
        subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(node_config),
             "--google-client-id", "id",
             "--google-client-secret", "secret"],
            capture_output=True, text=True,
        )
        # then clear them
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(node_config),
             "--clear"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        config = json.loads(node_config.read_text())
        assert config.get("sso_google_client_id") is None
        assert config.get("sso_google_client_secret") is None

    def test_configure_missing_args_fails(self, node_config):
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(node_config)],
            capture_output=True, text=True,
        )
        assert r.returncode != 0

    def test_configure_nonexistent_config_fails(self, tmp_path):
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(tmp_path / "does_not_exist.json"),
             "--google-client-id", "x",
             "--google-client-secret", "y"],
            capture_output=True, text=True,
        )
        assert r.returncode != 0

    def test_configure_env_vars(self, node_config):
        import os
        env = {**os.environ,
               "CONTAC_GOOGLE_CLIENT_ID": "env-id",
               "CONTAC_GOOGLE_CLIENT_SECRET": "env-secret"}
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/configure_sso.py"),
             "--config", str(node_config)],
            capture_output=True, text=True,
            env=env,
        )
        assert r.returncode == 0, r.stderr
        config = json.loads(node_config.read_text())
        assert config["sso_google_client_id"] == "env-id"
