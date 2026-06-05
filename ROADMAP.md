# Roadmap

## Pending

**0c. Restore-from-backup: revoke old node, update registry, shut down superseded instance**

When a user restores from a backup bundle onto a new node, the old node should be
superseded: revoke its delegation cert (or issue a new one invalidating the old node key),
update the registry with the new server URL, and notify the old node (if reachable) that
it has been replaced and should shut itself down. Any heartbeat from the superseded node
should be rejected by the registry with a "superseded" status.

**0a. Separate owner_id (person) from node_id (node deployment)**

Canonical terminology:
- `owner_id` — identifies a **person**. Permanent, stable, lives in the registry.
  In the registry, a "user" is identified by owner_id.
- `node_id`  — identifies a **node deployment**. Tied to a specific server instance
  and key pair. In the context of a node, a "user" is identified by node_id.

Currently both are the same UUID (1:1), so the field is called `user_id` throughout.
When we implement 1:n, `user_id` in the registry schema becomes `owner_id`, and each
node gets its own distinct `node_id`. Delegation certs bind `owner_id → node_id → public_key`.
All new code should use `owner_id`/`node_id` as the canonical names.

**0b. Multiple nodes per owner (1:n)**

One owner_id can control multiple node_ids — e.g. a personal node and a work node.
Requires a "link to existing identity" setup path where the user provides their identity
private key to sign a delegation cert for a new node under the same owner_id.

**1. Contact description**
Add a `description TEXT` field to the `contacts` table — natural language, editable via the
contact edit modal, eventually curated by an agent.

**2. Contact categories, weights, and adaptive aggregation**

A two-level system: predefined global categories (`family`, `close_friends`, `friends`,
`colleagues`, `acquaintances`) plus user-defined tags. Each contact gets a scalar weight
`[0,1]` derived from their categories but overridable.

*me side* holds the full category graph including private annotations. Sharing decisions
use weight thresholds — "visible to contacts with weight ≥ 0.6" — refining the current
`contacts` visibility tier without replacing it.

*them side* only sees a `poll_weight` float projected from the me-side model. This drives
adaptive aggregation: `poll_interval = base_ms / weight` so high-weight contacts are
polled more frequently and low-weight contacts less so.

Weight propagation: since me and them share a data volume, me writes `poll_weight` into
`client_config.json` alongside the contact entry when categories change; them reads from it.

Predefined category defaults: family=1.0, close_friends=0.8, friends=0.6,
colleagues=0.5, acquaintances=0.3. Custom tags start neutral and can be tuned.

**3. Upload identity escrow from settings**
Users who set up before the automatic escrow flow can upload their identity key escrow after
the fact from the profile/settings UI (requires them to have their identity private key).

**4. Profile photo preview on hover**
Show a larger version of a contact's photo when hovering over their avatar in post cards,
the contact list, etc.

**5. Client API test suite**
Comprehensive pytest suite for every `/api/` route the client exposes to the browser.

**6. Reaction emoji**
Allow users to react to posts and comments with emoji. Stored server-side, attributed to
the reactor. Display as grouped counts below each post/comment.

**7. @mention notifications**
When a post or comment contains `@handle`, push a lightweight ping to the tagged contact's
server. Surface an unread-mentions count/badge and mentions feed in the client.

**8. Chat / direct messages**
1:1 and small-group messaging. End-to-end encrypted, stored on sender's node, pushed or
polled by recipient. Likely a separate `messages` table and UI panel.

**9. Plaintext metadata hardening**
Assess what post timestamps and asset filenames leak and whether it matters for the threat
model.

---

## Completed

**Identity and security**
- **Permanent user identity**: UUID + Ed25519 identity key generated at setup. Identity key
  never stored on node. Delegation cert links identity key → node key (1 year validity).
- **Registry escrow**: identity private key encrypted with recovery passphrase (= node
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
- **Non-unique handles**: registry primary key is `user_id`; handles can repeat across users.

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
- **Registry landing page**: Google auth, node list, passphrase recovery, change recovery
  passphrase.
