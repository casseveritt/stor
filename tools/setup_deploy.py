#!/usr/bin/env python3
"""Generate deployment artifacts for a contac node.

Reads node_config.json and produces:
  - Caddyfile       — reverse-proxy config for Caddy (HTTPS + TLS termination)
  - contac.service  — systemd user service unit

Usage:
    python tools/setup_deploy.py --config /path/to/node_config.json [--port 8765] [--out deploy/]
"""
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.config import NodeConfig


CADDYFILE_TEMPLATE = """\
{domain} {{
    reverse_proxy localhost:{port}
    encode gzip
    log {{
        output stderr
        level WARN
    }}
}}
"""

SERVICE_TEMPLATE = """\
[Unit]
Description=contac personal data node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={repo_dir}
ExecStart={python} -m server.main {config_path} --host 127.0.0.1 --port {port}
EnvironmentFile={secrets_file}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""

INSTRUCTIONS_TEMPLATE = """\
─────────────────────────────────────────────────────────────────────
contac deployment setup for {node_address}
─────────────────────────────────────────────────────────────────────

1. Install Caddy (if not already installed):

   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \\
       | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \\
       | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt update && sudo apt install caddy

2. Install the Caddyfile:

   sudo cp {out_dir}/Caddyfile /etc/caddy/Caddyfile
   sudo systemctl reload caddy
   # Caddy will auto-obtain a Let's Encrypt certificate for {domain}

3. Create the secrets file (stores passphrase — keep this private):

   mkdir -p {secrets_dir}
   touch {secrets_file}
   chmod 600 {secrets_file}
   echo "CONTAC_PASSPHRASE=your-passphrase-here" >> {secrets_file}

4. Install the systemd service:

   mkdir -p ~/.config/systemd/user
   cp {out_dir}/contac.service ~/.config/systemd/user/contac.service
   systemctl --user daemon-reload
   systemctl --user enable contac
   systemctl --user start contac

5. Allow the service to run after logout (linger):

   loginctl enable-linger {username}

6. Check status:

   systemctl --user status contac
   journalctl --user -u contac -f

─────────────────────────────────────────────────────────────────────
Node will be available at: {node_address}
─────────────────────────────────────────────────────────────────────
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate contac deployment artifacts")
    parser.add_argument("--config", required=True, help="Path to node_config.json")
    parser.add_argument("--port", type=int, default=8765, help="Local bind port (default: 8765)")
    parser.add_argument("--out", default="deploy", help="Output directory (default: deploy/)")
    parser.add_argument("--node-address", default="",
                        help="Override and persist node_address in config (e.g. https://starkville.hopto.org)")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    if not config_path.exists():
        print(f"Error: {config_path} not found", file=sys.stderr)
        sys.exit(1)

    config = NodeConfig.load(config_path)

    if args.node_address:
        config.node_address = args.node_address.rstrip("/")
        config.save(config_path)
        print(f"Updated node_address → {config.node_address}")

    parsed = urlparse(config.node_address)
    domain = parsed.hostname
    if not domain:
        print(f"Error: could not parse domain from node_address={config.node_address!r}", file=sys.stderr)
        sys.exit(1)

    if domain in ("localhost", "127.0.0.1", "0.0.0.0") or not parsed.scheme.startswith("https"):
        print(f"Warning: node_address is {config.node_address!r}", file=sys.stderr)
        print("  For production, use: --node-address https://your-domain.com", file=sys.stderr)
        print("  Continuing with current value...\n", file=sys.stderr)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    repo_dir = Path(__file__).parent.parent.resolve()
    python = repo_dir / ".venv" / "bin" / "python"
    username = os.environ.get("USER", os.environ.get("LOGNAME", ""))
    home = Path.home()
    secrets_dir = home / ".config" / "contac"
    secrets_file = secrets_dir / "secrets"

    caddyfile = CADDYFILE_TEMPLATE.format(domain=domain, port=args.port)
    (out_dir / "Caddyfile").write_text(caddyfile)

    service = SERVICE_TEMPLATE.format(
        repo_dir=repo_dir,
        python=python,
        config_path=config_path,
        port=args.port,
        secrets_file=secrets_file,
    )
    (out_dir / "contac.service").write_text(service)

    instructions = INSTRUCTIONS_TEMPLATE.format(
        node_address=config.node_address,
        domain=domain,
        out_dir=out_dir,
        secrets_dir=secrets_dir,
        secrets_file=secrets_file,
        username=username,
    )
    print(instructions)


if __name__ == "__main__":
    main()
