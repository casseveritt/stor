# Roadmap

## Pending

**5. Chat / direct messages — remaining work**

The DM feature is implemented (see Completed). Remaining:
- Small-group messaging (3+ participants)
- Asset/photo attachments in DMs
- Forward secrecy (Double Ratchet) — explicitly deferred, static thread key accepted for v1

**6. Client API test suite**
Comprehensive pytest suite for every `/api/` route the client exposes to the browser.

**7. Key inventory and threat review**

Walk through every key in the system, document where each is derived or stored, and
identify any threats in how keys are currently held or accessed.

Known keys to cover (at minimum):

- **Node master key** — derived from passphrase via Argon2; used as KDF root
- **DB key** — derived from master key; key for the SQLCipher database
- **File key** — derived from master key; AES-GCM key for asset files on disk
- **Node Ed25519 signing key** — derived from master key; used to sign federation requests,
  stored encrypted in node config
- **Identity Ed25519 key** — generated at setup; never stored on node; escrowed at registry
  encrypted under owner passphrase; signs delegation cert linking identity → node key
- **Owner passphrase** — used to decrypt identity escrow; same as node passphrase by default
  (explicit upgrade path exists)
- **Tang X25519 key pair** — registry holds `t_priv`; node sends ephemeral `C` on startup;
  shared secret `S` lets the registry deliver the passphrase-equivalent to the node
- **DM DH key pair** — X25519 key pair for DM thread key derivation; private key derived
  from master key (or generated at setup?); `dh_public` published in node record
- **DM thread key** — HKDF(DH(my_priv, peer_pub), thread_id); AES-256-GCM per message
- **Client cache key** — HKDF(master key, "contacc-client-cache-key"); AES-GCM for post
  cache on `them` container; delivered in-memory via internal endpoint after Tang unlock
- **Client DB key** — HKDF(node private key bytes, "contacc-client-db"); SQLite key for
  contact tags and poll state on `them` container; requires passphrase to derive

Questions to answer for each key: What is it derived from? Where (if anywhere) is it
persisted? Who can request it and under what conditions? What does an attacker gain if
they obtain it?

**8. Plaintext metadata hardening**
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
- **Tang retry**: fast attempts at 2s, 7s, 22s; then slow retry every 60s for up to 30 minutes; bails if already unlocked manually.
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
- **Chat / direct messages (6)**: 1:1 E2E encrypted DMs. X25519 DH key pair generated at setup; thread key = HKDF(DH(my_priv, peer_pub), thread_id). AES-256-GCM per message. Push delivery to peer's /dm/receive with heartbeat retry. Thread list + conversation view in header panel. "Message" button in contact menu. Static thread key (no ratchet) accepted for v1. Message bodies render as markdown (shared `renderBodyText`/`.dm-bubble` styling). Arrow-key thread navigation; emoji picker in the compose field.
- **SSE real-time updates**: browser holds a persistent `EventSource` to client's `/api/events`; client holds a persistent SSE subscription to server's `/dm/events`. DM events arrive with zero polling latency. Post/comment/reaction updates pushed from server to client's `/notifications/post-update` and forwarded via SSE. Replaces all polling loops.
- **Reaction emoji + emoji picker**: 1800+ emoji from CDN, search, recently used row.
- **Inline emoji insert button**: 😊 button beside the post/save action on inline compose,
  compose modal, edit modal, comment forms, and DM compose — opens a searchable picker that
  inserts at the cursor position.
- **@mention notifications**: @ bell in header, dropdown, click-to-jump-to-post.

**Setup flow**
- **Setup wizard**: email, full name, handle, passphrase — all in one form.
- **Automatic escrow + Tang + registry registration**: all happen server-side during
  `/setup/new`; no extra screens shown to the user.
- **Full name at setup**: stored in profile table, picked up by heartbeat, searchable in
  registry.

**Feed and contacts**
- **Signed registry records / peer-to-peer registry cache**: registry generates an Ed25519
  signing key and signs every `/nodes/{id}` lookup response with `queried_at` +
  `registry_signature` (public key published at `/meta`). Nodes expose
  `/registry-cache/{node_id}` so peers can serve cached, verifiable records; the client
  proxy checks its local cache, then peer caches (verifying signatures), then falls back
  to the registry directly. Records persist across restarts in a `registry_cache` table.
- **Mention rendering — link-style pill**: `[node_id|disptext]` mentions render as
  `🔗disptext`, never exposing the raw node_id to the reader; the highlight overlay in
  compose/edit dims the `[node_id|` prefix for both UUIDs and public keys.
- **Profile hover popup — message and add-contact actions**: hovering an avatar shows a
  rich popup (name, handle, photo) with ✉ (open/start a DM thread) and ➕👤 (add as
  contact, only shown for non-contacts) actions; the mention popup also gained a ✉ button.
  Contacts panel "+Add" renamed to "+👤" to match.
- **Mark individual notification as read on click**: `/api/notifications/mentions/{id}/seen`
  marks one notification seen with an optimistic UI update; the badge reflects only
  truly-unseen notifications, with "clear all" as a secondary bulk action.
- **Thread follow notifications**: commenting on a post implicitly "follows" the thread —
  subsequent comments by others trigger a `notif_type='thread'` notification ("X also
  commented on a post you commented on") with click-to-jump, pushed to every prior
  commenter (excluding the post owner and the new commenter).
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
