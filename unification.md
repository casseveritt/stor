# Unification: Client as Node Identity and Auth Gateway

> **Design intent, partially realized** — The client does hold the node key and can sign federated requests, but the server still manages auth tokens and some identity state. Treat this as an aspirational design document, not a description of current architecture.

## Goal

The client becomes the node's sole identity and external interface. The server
becomes a pure data store that only accepts connections from its own client.
All authentication, signing, and outbound networking live in the client.

## Architecture

```
outside world
      │
      ▼
  [ client ]  ← holds private key, verifies inbound signatures,
      │          injects trusted identity headers, runs heartbeat
      │  X-Contacc-Internal + X-Contacc-Role + X-Contacc-Identity
      ▼
  [ server ]  ← data store only; trusts the client unconditionally;
                 makes zero outbound calls
```

## Signing Protocol

All outbound federation requests from our client include:

```
X-Contacc-Pubkey: <b64-raw-ed25519-pubkey>
X-Contacc-Ts:     <unix-timestamp>
X-Contacc-Sig:    <b64-ed25519-sig>
```

Signed message: `"{METHOD}\n{path}\n{timestamp}"`

Replay window: ±30 seconds.

Contact public keys are stored at contact-add time (from registry lookup).
Inbound signature verification confirms the signer holds the corresponding
private key, which confirms the registry entry is authentic.

## Inbound Auth (client catch-all proxy)

Before forwarding any request to the server, the client resolves identity:

| Condition | Role | Identity |
|---|---|---|
| valid session token | `owner` | — |
| valid sig + pubkey in contacts | `contact` | pubkey |
| valid sig + pubkey unknown | `authenticated` | pubkey |
| no sig | `public` | — |

Client strips any inbound `X-Contacc-Role`, `X-Contacc-Identity`,
`X-Contacc-Internal` headers before evaluation (prevent spoofing).

Client injects on every request to server:
```
X-Contacc-Internal: <internal_token>
X-Contacc-Role:     owner | contact | authenticated | public
X-Contacc-Identity: <pubkey-b64>   (contact and authenticated only)
```

## Server Auth

`AuthDep` verifies `X-Contacc-Internal` only — wrong or missing → 403.
Reads `X-Contacc-Role` and `X-Contacc-Identity` as trusted facts from client.

No Bearer token validation. No contacts table. No `X-Origin-Server` checks.
No OAuth machinery in the request path.

## Data Model Changes

### client_config.json gains:
```json
{
  "own_server": "http://server:9443",
  "contacts": [...],
  "node_key": {
    "argon2_salt": "<hex>",
    "encrypted_private_key": "<b64>"
  },
  "internal_token": "<random>"
}
```

Client receives `CONTACC_PASSPHRASE_UNSECURE` env var (same as server today).
At startup the client decrypts and holds the Ed25519 private key in memory.

### Server loses:
- `contacts` table (contact identity is the client's concern)
- Bearer token / JWT validation logic
- `sso.py` / `auth_routes.py` OAuth flow (login moves to client or simplifies)
- Registry heartbeat background task
- `encrypted_private_key` / `argon2_salt` (no longer needed)

## Setup Flow Change

Key pair is generated on the client side during first setup.
The server's setup endpoint returns `internal_token` in its response;
client stores it in `client_config.json`.
`CONTACC_PASSPHRASE_UNSECURE` is added to the client service in docker-compose.

## Registry Heartbeat

Moves from `server/main.py` to `client/main.py`.
Client signs heartbeat with the node private key — same logic, relocated.
Server makes zero outbound calls after this change.

## Implementation Order

1. Add `node_key` + `internal_token` to client config and `ClientConfig` model;
   client decrypts private key at startup from `CONTACC_PASSPHRASE_UNSECURE`
2. Internal token: server generates once at setup and returns it; client stores it;
   server rejects requests missing the correct token
3. Add signing headers to outbound federation requests in client
4. Add inbound signature verification + role/identity injection in client proxy
5. Simplify server `AuthDep` to internal token check only
6. Remove contacts table from server; remove server-side contact sync
7. Move registry heartbeat to client
8. Clean up: remove server crypto/OAuth/SSO that is now dead code
