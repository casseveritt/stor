# contacc

Personal content-addressed data store and social feed. Own your data; share intentionally.

## Running your own node

### What you need

- A Raspberry Pi (or any Linux server) running 24/7
- **Docker** — `curl -fsSL https://get.docker.com | sh`
- **A domain name** pointed at your server's public IP
  - [DuckDNS](https://www.duckdns.org) is free and works well on a Pi
- **Ports open** in your router: **80** (TLS), **8443–8472** (node APIs), **6443–6472** (web UIs)
- Access to a **registry** — the registry operator gives you a setup token and a web URL

No Google Cloud Console setup required. Google OAuth is handled by the registry.

### Setup

```bash
git clone https://github.com/casseveritt/stor
cd stor
cp .env.example .env          # edit CONTACC_DOMAIN and CONTACC_DATA_DIR
docker compose up -d --build
```

Open the web UI URL your registry operator gave you (e.g. `https://your.domain:6443`), enter
your setup token, fill in your name, handle, and a passphrase, and click **Create Identity**.

That's it. Your node is registered, Tang unlock is configured, and your identity key is
escrowed — all automatically.

### Day-to-day operations

```bash
docker compose logs -f                    # tail all logs
docker compose restart stor-node-0-1      # restart one container
docker compose up -d                      # start everything
docker compose down                       # stop everything
```

### Backup and restore

Use the **Backup** button in the web UI (Settings) to download a zip containing all your
posts, assets, and configuration. To restore, use the **Restore Backup** tab in the setup
wizard on a fresh node.

---

## Architecture

Each node slot runs as a single container:

| Container | Internal ports | Role |
|-----------|---------------|------|
| `node-N` | 28443+N (me), 18443+N (them) | Single process running both the me (biographer) server and the them (aggregator) client. Encrypted SQLCipher DB + AES-256-GCM files. |
| `registry` | 8421 | Shared handle→URL directory. Run by the host operator. |
| `caddy` | — | TLS termination + static file serving. Routes 8443+N → node-N, 6443+N → static web UI + proxy. |

The me and them components run as two uvicorn servers on the same asyncio event loop
inside `node-N`, sharing the Python interpreter and all loaded modules. They communicate
via internal HTTP (them → me) using a shared secret token; all external traffic enters
through the them port.

External port convention (N = 0–29 on a full host):

| Port range | Role |
|------------|------|
| 8443–8472 | Node API (external) → them |
| 6443–6472 | Web UI (external) → static files + proxy |

## Identity and security

**Identity key** — an Ed25519 key pair generated at setup. The private key is never stored
on the node. It signs delegation certificates that link your permanent UUID to your node's
operational key.

**Node key** — the day-to-day Ed25519 signing key, stored encrypted in `node_config.json`.
Encrypted with Argon2id + AES-256-GCM using your passphrase.

**Registry escrow** — your identity private key is encrypted with your passphrase and
uploaded to the registry at setup. If you lose access to your node, visit the registry,
sign in with Google, enter your passphrase, and recover your key.

**Tang network-bound unlock** — the registry holds a per-node X25519 key. On startup, your
node asks the registry to compute a shared secret and deliver it to your node's registered
URL. The registry only delivers to the address it has on file, so the node can only unlock
if it's actually running at its registered location. No passphrase entry needed on restart.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `CONTACC_DOMAIN` | Domain name for TLS and public URLs |
| `CONTACC_DATA_DIR` | Where persistent data lives on the host (default `./data`) |
| `CONTACC_IDENTITY_PROXY_URL` | Registry URL (default `https://strk.xyzw.us:8421`) |
| `CONTACC_NODE_ADDRESS` | Public `https://` URL for this node slot |
| `CONTACC_WEB_ADDRESS` | Public `https://` URL for the web UI |
| `CONTACC_ME_PORT` | Internal port for the me server (default 28443+N) |
| `CONTACC_THEM_PORT` | Internal port for the them aggregator (default 18443+N) |
| `CONTACC_PASSPHRASE_UNSECURE` | Passphrase for dev/testing (never use in production) |
| `CONTACC_DEV` | Set to `1` to enable dev mode (uses "foobar" as default passphrase) |

## Running a registry

The registry is the shared directory that maps handles to node URLs and brokers Google
OAuth for all nodes it serves. To run one:

```bash
docker compose --profile registry up -d
```

The registry stores data in `$CONTACC_DATA_DIR/registry/`. It requires a Google OAuth2
client ID and secret (set in `.env`) and a publicly accessible URL.

Registry operators issue setup tokens to new users and provide them with a web UI URL for
one of the available node slots.

## Cloud deployment

Same as self-hosted. Use a persistent volume for `$CONTACC_DATA_DIR` so data survives
instance replacement. On AWS, attach an EBS volume and set `CONTACC_DATA_DIR` to its mount
point. On GCP/Azure, use equivalent persistent disk offerings.
