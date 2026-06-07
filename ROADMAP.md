# Roadmap

## Pending

**0. Signed registry records / peer-to-peer registry cache**

The registry signs each node-lookup response with a timestamp so any node that holds the
record can prove its authenticity to a third party. Other nodes can answer registry queries
from their cache; a node should only go to the registry directly if no peer has a fresh
enough record.

Design sketch:
- Registry `GET /nodes/{node_id}` response gains two new fields:
  `queried_at` (Unix seconds, set by registry at query time) and
  `registry_signature` (Ed25519 signature over a canonical serialisation of the record
  including `queried_at`, signed by the registry's own node key, whose public key is
  published at `GET /meta`).
- Nodes cache signed records locally (keyed by `node_id`).
- New inter-node endpoint `GET /registry-cache/{node_id}`: returns the node's cached signed
  record for that `node_id`, or 404 if not held.
- When a node needs a registry entry it:
  1. Checks its own cache — if fresh (within a configurable TTL, e.g. 4 h) uses it.
  2. Asks known contacts' `/registry-cache/{node_id}` — accepts the first valid, fresh,
     correctly-signed response.
  3. Falls back to querying the registry directly and caches the result.
- Browser-side: `_lookupNodeFromRegistry` tries the existing proxy first, which now checks
  the node's local cache before hitting the registry.
- Staleness threshold: records older than TTL are considered stale and trigger a refresh;
  records older than 2× TTL are rejected even from peers.

**1. Mention rendering: hide node_id, show link emoji + display text**

Mentions are stored as `[node_id|disptext]` but currently the raw token is visible in the
compose/edit highlight layer and—when the node_id can't be resolved—in rendered posts.
The rendered form should always be `[🔗disptext]` (or similar link-style pill), never
exposing the node_id to the reader.

Scope:
- `renderBodyText` / `mdRender` post-processing: replace `[node_id|disptext]` with a
  styled inline element showing only the display text, with a hover popup (already
  implemented) and a small link indicator (emoji or icon). The node_id moves to a
  `data-mention-id` attribute, invisible to the reader.
- Compose/edit highlight overlay (`_updateHighlight`): already dims the `[node_id|` prefix;
  verify it fully hides the UUID and only shows the display text in the live preview.
- If `disptext` is empty or stale, fall back to resolving the node_id via
  `_resolveIdentity` at render time so the name is always current.

**2. Profile hover popup — message and add-contact actions**

The profile hover popup (shown when hovering over an avatar) currently displays name,
handle, and photo. Add two action buttons:

- **✉ (envelope)** — opens the DM panel for that contact, or initiates a new thread if
  none exists yet. Visible for all nodes (own and contacts).
- **➕👤 (add-contact)** — adds the node as a contact. Only shown when the node is *not*
  already a contact and is not the viewer's own node. Tapping it runs the same flow as
  the "Add contact" dialog, pre-filled with the node's URL.

Implementation notes:
- The popup already has the node's `server_url` (from `post._server_url` or the author
  element's `data-server`). That's sufficient to drive both actions.
- The add-contact button should grey out / change to a checkmark after the contact is
  successfully added, without closing the popup.
- The message button should work even before a DM thread exists (the DM panel handles
  first-message creation).
- Also change the existing "+Add" button in the contacts panel header to "+👤" to match.

**3. Mark mention as read on selection**

Clicking a notification in the mentions/reactions dropdown currently jumps to the post but
does not mark that individual notification as read. The unread dot should clear immediately
on click, and the badge count should decrement.

Currently `_markMentionsSeen` marks *all* notifications seen at once (called when the panel
is opened). Instead:
- Mark the individual notification seen on click (optimistic UI update + API call).
- The badge count should reflect only truly-unseen notifications.
- Bulk "mark all read" can remain as a secondary action (e.g. a small "clear all" link in
  the panel header).

**4. Thread follow notifications**

If you have commented on a post, subsequent comments on that post by others should appear
in your notifications — you're implicitly "following" the thread.

Design:
- Server tracks which nodes have commented on each post (already available via
  `comments.author_identity`).
- When a new comment is added, push a notification to every node that has previously
  commented on the post (excluding the post owner, who already gets comment notifications,
  and the commenter themselves).
- Notification type: new entry in `mention_notifications` with `notif_type = 'thread'`
  (or reuse `'comment'`) and `post_id` pointing to the post.
- Client renders it in the mentions/reactions panel: "X also commented on a post you
  commented on" with a click-to-jump action.
- Opt-out: consider a per-post "unfollow thread" action so users can stop notifications
  for a specific thread without leaving a comment.

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
- **Chat / direct messages (6)**: 1:1 E2E encrypted DMs. X25519 DH key pair generated at setup; thread key = HKDF(DH(my_priv, peer_pub), thread_id). AES-256-GCM per message. Push delivery to peer's /dm/receive with heartbeat retry. Thread list + conversation view in header panel. "Message" button in contact menu. Static thread key (no ratchet) accepted for v1.
- **SSE real-time updates**: browser holds a persistent `EventSource` to client's `/api/events`; client holds a persistent SSE subscription to server's `/dm/events`. DM events arrive with zero polling latency. Post/comment/reaction updates pushed from server to client's `/notifications/post-update` and forwarded via SSE. Replaces all polling loops.
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
