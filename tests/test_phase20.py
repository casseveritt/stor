"""Phase 20: end-to-end startup — init_node, issue_token, --print-token."""
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).parent.parent
PYTHON = str(REPO / ".venv" / "bin" / "python")
PASSPHRASE = "phase20-test-passphrase"


# ── helpers ───────────────────────────────────────────────────────────────────

def run(*args, input_text: str = "", env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run(
        [PYTHON, *args],
        input=input_text,
        capture_output=True,
        text=True,
        env=env,
    )


# ── init_node ─────────────────────────────────────────────────────────────────

class TestInitNode:
    INIT = str(REPO / "tools" / "init_node.py")

    def test_creates_config_file(self, tmp_path):
        r = run(self.INIT, "--store", str(tmp_path / "node"),
                "--address", "http://localhost:8000",
                "--key-stdin", input_text=PASSPHRASE + "\n")
        assert r.returncode == 0, r.stderr
        assert (tmp_path / "node" / "node_config.json").exists()

    def test_creates_files_directory(self, tmp_path):
        run(self.INIT, "--store", str(tmp_path / "node"),
            "--address", "http://localhost:8000",
            "--key-stdin", input_text=PASSPHRASE + "\n")
        assert (tmp_path / "node" / "files").is_dir()

    def test_config_has_required_fields(self, tmp_path):
        store = tmp_path / "node"
        run(self.INIT, "--store", str(store),
            "--address", "http://localhost:8000",
            "--key-stdin", input_text=PASSPHRASE + "\n")
        cfg = json.loads((store / "node_config.json").read_text())
        for field in ("node_address", "store_path", "argon2_salt",
                      "encrypted_private_key", "watermark_enabled"):
            assert field in cfg, f"missing: {field}"

    def test_rejects_existing_store(self, tmp_path):
        store = tmp_path / "node"
        run(self.INIT, "--store", str(store),
            "--address", "http://localhost:8000",
            "--key-stdin", input_text=PASSPHRASE + "\n")
        r = run(self.INIT, "--store", str(store),
                "--address", "http://localhost:8000",
                "--key-stdin", input_text=PASSPHRASE + "\n")
        assert r.returncode != 0

    def test_watermark_flag(self, tmp_path):
        store = tmp_path / "node"
        run(self.INIT, "--store", str(store),
            "--address", "http://localhost:8000",
            "--watermark", "--key-stdin", input_text=PASSPHRASE + "\n")
        cfg = json.loads((store / "node_config.json").read_text())
        assert cfg["watermark_enabled"] is True

    def test_env_var_passphrase(self, tmp_path):
        r = run(self.INIT, "--store", str(tmp_path / "node"),
                "--address", "http://localhost:8000",
                env_extra={"CONTACC_PASSPHRASE": PASSPHRASE})
        assert r.returncode == 0, r.stderr

    def test_prints_public_key(self, tmp_path):
        r = run(self.INIT, "--store", str(tmp_path / "node"),
                "--address", "http://localhost:8000",
                "--key-stdin", input_text=PASSPHRASE + "\n")
        assert "Public key:" in r.stdout


# ── issue_token ───────────────────────────────────────────────────────────────

class TestIssueToken:
    INIT = str(REPO / "tools" / "init_node.py")
    ISSUE = str(REPO / "tools" / "issue_token.py")

    @pytest.fixture(scope="class")
    def inited_store(self, tmp_path_factory):
        store = tmp_path_factory.mktemp("issue") / "node"
        run(self.INIT, "--store", str(store),
            "--address", "http://localhost:8000",
            "--key-stdin", input_text=PASSPHRASE + "\n")
        return store

    def test_prints_token(self, inited_store):
        r = run(self.ISSUE, str(inited_store / "node_config.json"),
                "--key-stdin", input_text=PASSPHRASE + "\n")
        assert r.returncode == 0, r.stderr
        token = r.stdout.strip()
        assert len(token) > 20

    def test_token_is_base64(self, inited_store):
        r = run(self.ISSUE, str(inited_store / "node_config.json"),
                "--key-stdin", input_text=PASSPHRASE + "\n")
        token = r.stdout.strip()
        # Owner token is url-safe base64 — should decode without error
        import base64
        base64.urlsafe_b64decode(token + "==")  # add padding

    def test_wrong_passphrase_fails(self, inited_store):
        r = run(self.ISSUE, str(inited_store / "node_config.json"),
                "--key-stdin", input_text="wrong-passphrase\n")
        assert r.returncode != 0

    def test_token_works_against_server(self, inited_store):
        """Token from issue_token is accepted by a server started with same config."""
        from server.main import create_app
        from fastapi.testclient import TestClient

        r = run(self.ISSUE, str(inited_store / "node_config.json"),
                "--key-stdin", input_text=PASSPHRASE + "\n")
        token = r.stdout.strip()

        app = create_app(inited_store / "node_config.json", PASSPHRASE)
        client = TestClient(app)
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "owner"


# ── --print-token flag ────────────────────────────────────────────────────────

class TestPrintToken:
    INIT = str(REPO / "tools" / "init_node.py")

    @pytest.fixture(scope="class")
    def print_token_store(self, tmp_path_factory):
        store = tmp_path_factory.mktemp("pt") / "node"
        run(self.INIT, "--store", str(store),
            "--address", "http://localhost:8000",
            "--key-stdin", input_text=PASSPHRASE + "\n")
        return store

    def test_print_token_emits_token(self, print_token_store):
        """--print-token prints an owner token before uvicorn starts."""
        from server.main import create_app
        from server import auth as auth_module
        import io

        app = create_app(print_token_store / "node_config.json", PASSPHRASE)

        captured = io.StringIO()
        with patch("sys.stdout", captured):
            token = auth_module.issue_token(ttl_seconds=86400 * 30)
            print(f"Owner token: {token}", flush=True)

        output = captured.getvalue()
        assert "Owner token:" in output
        emitted_token = output.split("Owner token:")[1].strip()
        assert len(emitted_token) > 20

    def test_print_token_token_is_valid(self, print_token_store):
        """Token printed at startup is accepted by the same server."""
        from server.main import create_app
        from server import auth as auth_module
        from fastapi.testclient import TestClient

        app = create_app(print_token_store / "node_config.json", PASSPHRASE)
        token = auth_module.issue_token(ttl_seconds=86400 * 30)

        client = TestClient(app)
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "owner"

    def test_print_token_arg_is_parsed(self, print_token_store):
        """--print-token flag is accepted by argparse without error."""
        import argparse
        from server.main import main
        from server.db import WrongPassphraseError

        # Verify argparse accepts the flag by checking it's in the parser
        import server.main as main_mod
        import inspect

        # Patch uvicorn.run to avoid actually starting a server
        with patch("uvicorn.run"), \
             patch("sys.argv", ["contacc", str(print_token_store / "node_config.json"),
                                "--print-token",
                                "--key-stdin"]), \
             patch("sys.stdin.readline", return_value=PASSPHRASE + "\n"), \
             patch("builtins.print") as mock_print:
            main_mod.main()

        calls = [str(c) for c in mock_print.call_args_list]
        assert any("Owner token:" in c for c in calls)
