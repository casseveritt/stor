# Cloud Deployment Approach

*This is a design note, not a current implementation. The existing setup builds
images locally on each deploy machine, which works well for a small number of
Raspberry Pis. This document describes how to scale that up.*

---

## The core pattern

Build once in CI, deploy everywhere by pulling:

```
git push → GitHub Actions → ghcr.io/casseveritt/stor:latest
                                        ↓
                              deploy machines: docker pull
```

Every machine runs the identical binary. No build toolchain needed on deploy
hosts. New nodes come up in seconds.

## Image registry

GitHub Container Registry (`ghcr.io`) is the natural choice since the repo is
already on GitHub. A workflow in `.github/workflows/publish.yml` would build
and push on every merge to `main`, tagging with both `latest` and the commit
SHA for pinned rollbacks.

`docker-compose.yml` changes:
- `node-0-me` keeps `build: .` for local development
- All other services switch to `image: ghcr.io/casseveritt/stor:latest`
- The setup script drops `docker compose build` and does `docker compose pull`

## Dynamic node scaling in the cloud

Each node slot is already stateless at the image level — all state lives in the
data volume. Spinning up a new node is:

1. Provision a data volume (EBS, EFS, or equivalent)
2. Pull the image
3. Start the containers with the appropriate env vars (node N port offsets,
   `CONTACC_WEB_ADDRESS`, `CONTACC_NODE_ADDRESS`, etc.)
4. Hit `POST /setup/new` via the API to initialize
5. The node registers itself with the registry on first heartbeat

No human interaction required after step 4.

## TLS at scale

The current approach — Caddy with HTTP-01 ACME on port 80, one cert per
hostname — works well for a fixed small fleet. At scale, two better options:

- **DNS-01 challenge**: Caddy proves domain ownership via a DNS TXT record
  using the provider's API. No port 80 needed. Requires a Caddy build with the
  appropriate DNS plugin (Cloudflare, Route53, etc.) and an API token.

- **Load balancer TLS termination**: Put a cloud load balancer (ALB, Cloudflare,
  etc.) in front that handles TLS and forwards plain HTTP internally. Caddy
  drops to a plain HTTP server. Wildcard cert covers all node subdomains.

## Data persistence

SQLite + local files works well on a single machine but not across multiple
instances of the same node. For a horizontally scaled me/them pair:

- The me (biographer) service is inherently single-writer — one instance per
  node, backed by a single attached volume. This is a feature: your biographer
  has exactly one home.
- The them (aggregator) service could in principle run multiple instances
  behind a load balancer, but its session store (`_sessions` dict) is currently
  in-memory. Moving sessions to Redis or a shared DB would be the prerequisite.

For most real-world deployments, one me + one them per node is the right model.
Scaling means more nodes, not more instances of the same node.

## What doesn't need to change

The node architecture is already cloud-ready in the ways that matter:

- Image is a single self-contained artifact with no external build dependencies
  at runtime
- State is entirely in the data volume — image is disposable
- Port conventions (8443+N, 6443+N) map naturally to environment variables
- The registry is a separate service that can run anywhere
