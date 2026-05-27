# contacc

Personal content-addressed data store and aggregator. Own your data; share intentionally.

## Running your own server

### What you need

- A Raspberry Pi (or any Linux server) running 24/7
- **Docker** — install with `curl -fsSL https://get.docker.com | sh`
- **A domain name** pointed at your server's public IP. Free options:
  - [DuckDNS](https://www.duckdns.org) — free dynamic DNS, works well on Pi
  - Any registrar if you have a static IP
- **Ports open** in your router/firewall: **80** (TLS cert issuance), **8443** (server), **8444** (client UI)
- **Google OAuth2 credentials** — see below

### 1. Get Google OAuth2 credentials

contacc uses Google Sign-In for owner authentication.

1. Go to [console.cloud.google.com](https://console.cloud.google.com) → **APIs & Services → Credentials**
2. **Create Credentials → OAuth 2.0 Client ID**, application type: **Web application**
3. Under **Authorized redirect URIs**, add exactly:
   ```
   https://your.domain.example:8443/auth/callback
   ```
4. Copy the **Client ID** and **Client Secret**

### 2. Clone and run setup

```bash
git clone https://github.com/casseveritt/stor contacc
cd contacc
bash setup.sh
```

The script prompts for your domain, Google credentials, Google account email, and a passphrase (used to encrypt your data at rest). It then builds the Docker image, initializes your node, and starts everything.

### 3. Log in

Open `https://your.domain.example:8444` and click **Sign in with Google**.

That's it.

---

### Day-to-day operations

```bash
docker compose logs -f          # tail all logs
docker compose restart server   # restart one service
docker compose down             # stop everything
docker compose up -d            # start everything
```

### Backup and restore

```bash
# Back up (run from the contacc repo directory)
source .env
tar -czf contacc-backup-$(date +%Y%m%d).tar.gz "$CONTACC_DATA_DIR" .env

# Restore on a new host
git clone https://github.com/casseveritt/stor contacc && cd contacc
tar -xzf contacc-backup-YYYYMMDD.tar.gz
docker compose up -d
```

> Your node's Ed25519 private key lives inside `$CONTACC_DATA_DIR/server/node_config.json`,
> encrypted with your passphrase. This key is your identity — keep your backup safe.

### Registering a username (optional)

The shared registry at `starkville.hopto.org:8421` maps human-readable handles to server URLs,
so contacts can find you by name even if you change hosts.

```bash
# Register (run once after setup, requires Python and httpx in your venv)
CONTACC_PASSPHRASE=... python tools/register_node.py \
    "$CONTACC_DATA_DIR/server/node_config.json" \
    --handle yourname \
    --client-url https://your.domain.example:8444

# Update after moving to a new domain
CONTACC_PASSPHRASE=... python tools/register_node.py \
    "$CONTACC_DATA_DIR/server/node_config.json" \
    --handle yourname --client-url https://new.domain:8444 --update
```

Only the Ed25519 key that originally registered a handle can update it.

---

## Architecture

| Component | Directory | Internal port | External port | Description |
|-----------|-----------|--------------|--------------|-------------|
| Server node | `server/` | 9443 | 8443 | FastAPI + SQLCipher DB + AES-256-GCM assets. Ed25519 identity. Google SSO. |
| Client UI | `client/` | 9444 | 8444 | FastAPI + browser UI; aggregates content from one or more server nodes. |
| Registry | `registry/` | 9532 | 8421 | Shared username → server/client URL directory. Not run by most users. |
| Caddy | — | — | 80, 8443, 8444 | Reverse proxy with automatic TLS. |

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

All persistent data uses **bind-mount volumes** — plain host directories, not Docker-managed volumes. The root is set by `CONTACC_DATA_DIR` in `.env` (default `~/contacc`), keeping data entirely outside the repo:

| Host path | Container path | Contents |
|-----------|---------------|----------|
| `$CONTACC_DATA_DIR/server/` | `/data` | Encrypted SQLCipher DB, asset files, `node_config.json` |
| `$CONTACC_DATA_DIR/client/` | `/data` | `client_config.json` |
| `$CONTACC_DATA_DIR/caddy/` | `/data` | TLS certificates (managed by Caddy) |

You can inspect, back up, or restore data directly without any Docker commands.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `CONTACC_DATA_DIR` | Where persistent data lives on the host (default `~/contacc`) |
| `CONTACC_DOMAIN` | Domain name for TLS certificates and public URLs |
| `CONTACC_PASSPHRASE` | Decrypts the Ed25519 private key and derives DB/file encryption keys at startup |
| `CONTACC_GOOGLE_CLIENT_ID` | Google OAuth2 client ID |
| `CONTACC_GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret |
| `CONTACC_OWNER_IDENTITY` | Google identity of the owner, e.g. `google:you@gmail.com` |
| `CONTACC_NODE_ADDRESS` | Overrides `node_address` in config; ensures the OAuth callback URI is the correct public `https://` URL |
| `CONTACC_CLIENT_URL` | Ensures the OAuth `return_to` URL is `https://` not the internal `http://` seen behind Caddy |
| `CONTACC_CADDYFILE` | Path to Caddyfile (default `./deploy/Caddyfile`; set to `./deploy/Caddyfile.registry` for registry operators) |
| `COMPOSE_PROFILES` | Set to `registry` to also start the registry service |

## Cloud deployment (AWS / GCP / etc.)

The setup is the same as self-hosted, but persistent storage needs explicit attention — cloud instance root volumes are often treated as ephemeral.

**Recommended pattern on AWS:**

1. Attach an EBS volume and mount it:
   ```bash
   sudo mkfs.ext4 /dev/xvdf
   sudo mkdir /mnt/contacc && sudo mount /dev/xvdf /mnt/contacc
   sudo chown $USER /mnt/contacc
   echo '/dev/xvdf /mnt/contacc ext4 defaults 0 2' | sudo tee -a /etc/fstab
   ```
2. Set `CONTACC_DATA_DIR=/mnt/contacc` when running `setup.sh`

You can then stop, resize, or replace the EC2 instance and reattach the volume to resume exactly where you left off. GCP and Azure have equivalent persistent disk offerings.

## Port convention

Each contacc instance uses 4 ports based on a **base port** (default 8443):

| Port        | Role                      |
|-------------|---------------------------|
| base        | Caddy → server (external) |
| base + 1    | Caddy → client (external) |
| base + 1000 | server process (internal) |
| base + 1001 | client process (internal) |

Multiple instances on the same host pick non-overlapping base values.

## Native / development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python tools/init_node.py --store ~/contacc-node --address https://your.domain:8443 \
    --google-client-id <id> --google-client-secret <secret>
python tools/configure_sso.py --config ~/contacc-node/node_config.json \
    --owner-identity google:you@gmail.com
python tools/init_client.py --config ~/contacc-client/client_config.json \
    --own-server https://your.domain:8443

CONTACC_PASSPHRASE=... python -m server.main ~/contacc-node/node_config.json --port 9443
python -m client.main ~/contacc-client/client_config.json --port 9444
```
