# Roadmap

## Pending

**1. Client API test suite**
Comprehensive pytest suite for every `/api/` route the client exposes to the browser.

**6. Chat / direct messages**
1:1 and small-group messaging. End-to-end encrypted, stored on sender's node, pushed or
polled by recipient. Likely a separate `messages` table and UI panel.

**7. Plaintext metadata hardening**
Assess what post timestamps and asset filenames leak and whether it matters for the threat
model.

---

## Completed

**Identity and security**
- **Permanent user identity**: UUID + Ed25519 identity key generated at setup. Identity key
  never stored on node. Delegation cert links identity key → node key (1 year validity).
- **Registry escrow**: identity private key encrypted with owner passphrase (= node
  passphrase by default), uploaded to registry at setup. Recoverable via Google auth +
  passphrase at the registry landing page.
- **Tang network-bound unlock**: registry holds a per-node X25519 key. On startup the node
  sends its ephemeral public key C to the registry; registry computes S = X25519(t_priv, C)
  and delivers it to the node's registered URL — the delivery address is the implicit location
  proof. Node derives its passphrase from S and unlocks without user interaction.
  Auto-registers when a node changes its passphrase for the first time.
- **Tang retry**: attempts at 2s, 7s, 22s after startup; bails if already unlocked manually.
- **Default passphrase banner**: red banner prompts users still on "foobar" to set a real
  passphrase. Also updates registry escrow if escrow passphrase is also "foobar".
- **Non-unique handles**: registry primary key is `node_id`; handles can repeat across owners.
- **owner_id / node_id separation (0a)**: two distinct UUIDs — `owner_id` is permanent person identity, `node_id` is deployment-specific. Registry v3 schema uses `node_id` as PK.
- **1:n nodes per owner — registry (0b)**: registry now allows multiple node rows per `owner_id`. "Existing owner" setup path implemented server-side. Tang endpoints fixed to use `node_id` column.
- **Supersede endpoint (0c)**: `POST /nodes/{node_id}/supersede` marks a node as replaced; superseded nodes get HTTP 410 on heartbeat. UI button in registry landing page. Client-side restore flow integration remains TODO.
- **Contact description (1)**: per-contact notes field in client_config.json, editable from contact menu.
- **Contact categories + adaptive polling (2)**: family/close_friends/friends/colleagues/acquaintances with weights [1.0–0.3]; poll_interval = base_ms / weight; category picker in contact menu.
- **API versioning (3)**: GET /node includes api_version + extensions; registry GET /meta returns same.
- **Upload identity escrow from settings (4)**: profile panel "Upload identity escrow" section calls /setup/escrow-identity-key.
- **Profile photo hover preview (4)**: 100×100 popup on hover over any .post-author-avatar; event delegation, viewport-clamped.
- **Hybrid push/poll for live post updates**: subscribe to post on remote node; 2s cheap poll for pushed updates; 20s heavy poll replaced.
- **Reaction emoji + emoji picker**: 1800+ emoji from CDN, search, recently used row.
- **@mention notifications**: @ bell in header, dropdown, click-to-jump-to-post.

**Setup flow**
- **Setup wizard**: email, full name, handle, passphrase — all in one form.
- **Automatic escrow + Tang + registry registration**: all happen server-side during
  `/setup/new`; no extra screens shown to the user.
- **Full name at setup**: stored in profile table, picked up by heartbeat, searchable in
  registry.

**Feed and contacts**
- **Registry heartbeat + auto-register**: node signs and pushes to registry on startup and
  hourly.
- **Aggregate feed**: client fetches all contacts in parallel, merges by `created_at`.
- **Add/remove contacts by handle**: lookup via registry; contact URL auto-refreshed on
  failure.
- **Backup/restore bundle**: client augments server zip with `client_config.json`.
- **Search**: matches handle, display name, post body, comment bodies.
- **Author display**: profile photo/initials + display name on every post card.
- **Visibility/comment_access system**: `private` | `contacts` | `authenticated` | `public`;
  both must pass independently. UI dropdowns in compose/edit.
- **Inline mention editing**: `[pubkey|disptext]` format, shared compose/edit overlay.

**Infrastructure**
- **Multi-slot deployment**: up to 10 node slots per host (ports 8443–8452 / 6443–6452).
- **Web layer**: independent Caddy container per slot; static files + proxy to `them`.
- **Routing**: Caddy routes all external traffic to `them`; `them` proxies to `me` via
  catch-all with internal token. No path-based Caddy rules.
- **Registry landing page**: Google auth, node list, identity recovery, change owner
  passphrase.
