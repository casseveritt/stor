# contacc

Personal content-addressed data store and aggregator. Own your data; share intentionally.

## Port convention

Each contacc instance uses 4 ports based on a **base port** (default 8443):

| Port        | Role                         |
|-------------|------------------------------|
| base        | Caddy → server (external)    |
| base + 1    | Caddy → client (external)    |
| base + 1000 | server process (internal)    |
| base + 1001 | client process (internal)    |

Default: base=8443 → external 8443/8444, internal 9443/9444.
Multiple instances on the same host pick non-overlapping base values.

The global registry runs separately at port **8421** (internal 9532).

## Quick start (Docker)

### 1. Prerequisites

- Docker with Compose v2: `docker compose version`
- A domain name with DNS pointed at your server's IP
- The following ports open in your firewall / forwarded by your router:
  - **80** and **443** — Caddy ACME TLS certificate issuance
  - **8443** — contacc server
  - **8444** — contacc client UI

### 2. Set up Google OAuth2

contacc uses Google SSO for owner authentication. You need OAuth2 credentials from the [Google Cloud Console](https://console.cloud.google.com/).

1. Create a project (or use an existing one)
2. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
3. Application type: **Web application**
4. Under **Authorized redirect URIs**, add:
   ```
   https://your.domain.example:8443/auth/callback
   ```
   > This is the **server** port (8443), not the client port. Google redirects here after login;
   > the server then forwards the browser to the client.
5. Copy the **Client ID** and **Client Secret** — you'll need them in the next step.

### 3. Run the setup script

```bash
git clone https://github.com/casseveritt/stor contacc
cd contacc
bash deploy/docker-setup.sh
```

The script will prompt for:
- **Domain name** — e.g. `your.domain.example`
- **Google OAuth2 Client ID and Secret** — from step 2
- **Owner identity** — your Google account in the form `google:you@gmail.com`
- **Passphrase** — used to encrypt the server's database and private key; keep this safe

It then builds the Docker image, initializes the server node and client config, and starts all services.

### 4. First login

Open `https://your.domain.example:8444` in your browser and click **Sign in with Google**.

### Day-to-day operations

```bash
docker compose logs -f              # tail all logs
docker compose logs -f server       # server logs only
docker compose restart server       # restart one service
docker compose down                 # stop everything
docker compose up -d                # start everything
```

### Backup and restore

All persistent data lives in `$CONTACC_DATA_DIR` and credentials in `.env`. Back them up together:

```bash
source .env
tar -czf contacc-backup-$(date +%Y%m%d).tar.gz "$CONTACC_DATA_DIR" .env
```

**To restore on a new host:**

```bash
git clone https://github.com/casseveritt/stor contacc
cd contacc
# restore your backup (extracts data dir and .env)
tar -xzf contacc-backup-YYYYMMDD.tar.gz
# start — init is skipped automatically because the data dir already exists
docker compose up -d
```

> Your node's Ed25519 private key lives inside `data/server/node_config.json` (encrypted with
> your passphrase). This key IS your identity — it's what proves ownership of your registry
> handle. Keep your backup safe.

## Cloud deployment (AWS / GCP / etc.)

The setup is the same as self-hosted, but persistent storage needs explicit attention. Cloud instance root volumes are often treated as ephemeral — terminated instances lose their data.

**Recommended pattern on AWS:**

1. Create an EBS volume sized for your data and attach it to the instance
2. Format and mount it (once, on first use):
   ```bash
   sudo mkfs.ext4 /dev/xvdf
   sudo mkdir /mnt/contacc
   sudo mount /dev/xvdf /mnt/contacc
   sudo chown $USER /mnt/contacc
   # add to /etc/fstab for automatic remount on reboot
   echo '/dev/xvdf /mnt/contacc ext4 defaults 0 2' | sudo tee -a /etc/fstab
   ```
3. Set `CONTACC_DATA_DIR=/mnt/contacc` when running the setup script

This separates the instance lifecycle from the data lifecycle: you can stop, resize, or replace the EC2 instance and reattach the EBS volume to pick up exactly where you left off. The backup runbook (`tar $CONTACC_DATA_DIR .env`) still works the same way, and EBS snapshots give you an additional cloud-native backup option.

GCP and Azure have equivalent persistent disk offerings; the pattern is the same — mount the disk, point `CONTACC_DATA_DIR` at the mount.

## Registry

contacc nodes register a human-readable handle in a shared registry at
`https://starkville.hopto.org:8421`. This lets contacts find your current server URL by handle
even if you move hosts.

```bash
# Register your handle (run once after setup)
CONTACC_PASSPHRASE=... python tools/register_node.py \
    data/server/node_config.json \
    --handle yourname \
    --client-url https://your.domain.example:8444

# Look up any handle
curl https://starkville.hopto.org:8421/lookup/yourname

# Update after moving servers (re-run with --update)
CONTACC_PASSPHRASE=... python tools/register_node.py \
    data/server/node_config.json \
    --handle yourname \
    --client-url https://your.domain.example:8444 \
    --update
```

Only the Ed25519 key that originally registered a handle can update it — the registry never
stores or sees your passphrase.

## Architecture

| Component | Directory | Internal port | External port | Description |
|-----------|-----------|--------------|--------------|-------------|
| Server node | `server/` | 9443 | 8443 | FastAPI + SQLCipher DB + AES-256-GCM assets. Ed25519 identity. Google SSO. |
| Client aggregator | `client/` | 9444 | 8444 | FastAPI proxy; aggregates content from one or more server nodes. |
| Registry | `registry/` | 9532 | 8421 | Global username → server/client URL directory with TTL-based caching. |
| Caddy | — | — | 80, 443, 8443, 8444 | Reverse proxy with automatic TLS. |

## Authentication flow

Login uses Google OAuth2 with the server acting as the OAuth client (not the browser-facing UI):

1. You visit the **client** (port 8444) and click "Sign in with Google"
2. The client redirects your browser to Google with a callback URL pointing at the **server** (`https://your.domain:8443/auth/callback`)
3. Google authenticates you and redirects back to the server with a short-lived auth code
4. The server exchanges the code for a Google ID token, verifies your identity against `sso_owner_identity` in `node_config.json`
5. If it matches, the server issues a 30-day owner JWT and redirects your browser to the client with the token in the URL fragment (`/#token=...`)
6. The client stores the token in the browser and sends it as a `Bearer` header on all subsequent API calls to the server

The callback URI must be registered in the Google Cloud Console and must exactly match what the server constructs at runtime. The `CONTACC_NODE_ADDRESS` env var ensures this is always the correct public `https://` URL even though the server internally receives requests over plain `http://` from Caddy.

## Data storage

All persistent data uses **bind-mount volumes** — plain host directories, not Docker-managed volumes. The root of these directories is set by `CONTACC_DATA_DIR` in `.env` (e.g. `/opt/contacc`), which keeps data entirely outside the repo:

| Host path | Container path | Contents |
|-----------|---------------|----------|
| `$CONTACC_DATA_DIR/server/` | `/data` | Encrypted SQLCipher DB, asset files, `node_config.json` |
| `$CONTACC_DATA_DIR/client/` | `/data` | `client_config.json` |
| `$CONTACC_DATA_DIR/registry/` | `/data` | `registry.db` (plain SQLite) |
| `$CONTACC_DATA_DIR/caddy/` | `/data` | TLS certificates (managed by Caddy) |

Because the data is on the host filesystem you can inspect, back up, or restore it directly without Docker commands. This is what makes the backup runbook simple — `tar $CONTACC_DATA_DIR .env` captures everything.

## Environment variables

The `.env` file at the repo root is loaded by Docker Compose and feeds credentials and runtime config into containers:

| Variable | Used by | Purpose |
|----------|---------|---------|
| `CONTACC_DOMAIN` | Caddy, server, client | Domain name for TLS certificate and public URLs |
| `CONTACC_PASSPHRASE` | server | Decrypts the Ed25519 private key and derives DB/file encryption keys at startup; not stored after boot |
| `CONTACC_GOOGLE_CLIENT_ID` | server | Google OAuth2 client ID |
| `CONTACC_GOOGLE_CLIENT_SECRET` | server | Google OAuth2 client secret |
| `CONTACC_OWNER_IDENTITY` | server (init only) | Google identity that receives owner privileges, e.g. `google:you@gmail.com` |
| `CONTACC_NODE_ADDRESS` | server | Overrides `node_address` in `node_config.json`; used to build the OAuth callback URI so it's always the correct public `https://` URL |
| `CONTACC_CLIENT_URL` | client | Overrides `request.base_url`; ensures the OAuth `return_to` URL is `https://` not the internal `http://` address seen behind Caddy |

`CONTACC_NODE_ADDRESS` and `CONTACC_CLIENT_URL` exist because Caddy terminates TLS — the app containers only ever see plain `http://` requests, so they can't infer the correct public URL on their own. Setting these in `.env` also means changing your domain only requires updating `.env` and restarting, with no changes to the data volume.

## Native / development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Initialize server node
python tools/init_node.py --store ~/contacc-node --address https://your.domain:8443 \
    --google-client-id <id> --google-client-secret <secret>

# Configure owner identity
python tools/configure_sso.py --config ~/contacc-node/node_config.json \
    --owner-identity google:you@gmail.com

# Initialize client
python tools/init_client.py --config ~/contacc-client/client_config.json \
    --own-server https://your.domain:8443

# Run server (reads CONTACC_PASSPHRASE from environment)
CONTACC_PASSPHRASE=... python -m server.main ~/contacc-node/node_config.json --port 9443

# Run client
python -m client.main ~/contacc-client/client_config.json --port 9444
```
