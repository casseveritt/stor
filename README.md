# contac

Personal content-addressed data store and aggregator. Own your data; share intentionally.

## Quick start (Docker)

### Prerequisites

- Docker with Compose v2 (`docker compose version`)
- A domain name pointed at your server
- Ports 80, 443, 8443, and 9876 open in your firewall
- [Google OAuth2 credentials](https://console.cloud.google.com/) with redirect URI:
  `https://your.domain.example:9876/auth/callback`

### First-time setup

```bash
git clone <repo-url> contac && cd contac
bash deploy/docker-setup.sh
```

The script prompts for your domain, Google OAuth credentials, and a passphrase (used to encrypt the database), then initializes the node and starts all services.

Once done, open `https://your.domain.example:9876` and sign in with Google.

### Day-to-day

```bash
docker compose logs -f          # tail logs
docker compose restart server   # restart server
docker compose down             # stop everything
docker compose up -d            # start everything
```

### Backup

All persistent data lives in `./data/`. Back it up and it all comes with you:

```bash
tar -czf contac-backup-$(date +%Y%m%d).tar.gz data/ .env
```

To restore on a new host: clone the repo, restore `data/` and `.env`, then `docker compose up -d`.

## Architecture

- **Server node** (`server/`) — FastAPI + SQLCipher encrypted database + AES-256-GCM asset encryption. Ed25519 node identity. Google OAuth/OIDC SSO. Runs on port 8765 (external: 8443 via Caddy).
- **Client aggregator** (`client/`) — FastAPI proxy that aggregates content from one or more server nodes. Runs on port 9865 (external: 9876 via Caddy).
- **Caddy** — reverse proxy with automatic TLS.

## Native / development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Initialize server
python tools/init_node.py --store ~/contac-node --address https://your.domain:8443

# Initialize client
python tools/init_client.py --config ~/contac-client/client_config.json \
    --own-server https://your.domain:8443

# Run server
CONTAC_PASSPHRASE=... python -m server.main ~/contac-node/node_config.json --port 8765

# Run client
python -m client.main ~/contac-client/client_config.json --port 9865
```
