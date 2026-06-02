# Roadmap

## Pending

**1. Contact description**
Add a `description TEXT` field to the `contacts` table. Natural language, potentially long.
User-editable via the UI (contact edit modal); also curated by the agent based on aggregated
information about the contact. Intended to give agents rich context about who a contact is.
Requires: DB migration, server PATCH /contacts, client API PATCH /api/contacts, edit modal in sidebar.

**2. Contact "goes by" short name for @mentions**
Each contact entry can have an owner-defined short name used for `@`-mention autocomplete and
insertion. Defaults to the contact's first name (or handle if set). Example: "Michael Toksvig"
goes by "Tox" — owner sets this locally; it doesn't need to be in the contact's profile.
The contact could also add an alias in their own profile that other nodes pick up.
Requires: `goes_by` field on `ContactEntry` (client-only), profile API field for self-declared
alias, UI in contact edit flow, `_mentionTag()` updated to prefer `goes_by`.

**3. Contact tags**
Each contact entry can be assigned a list of tags (e.g. "family", "work"). Tags will appear
as visibility/comment_access options alongside the built-in levels. Boolean expressions like
`contacts - (work + church)` are a longer-term goal; start with simple named tags as extra
visibility predicates. Requires: `contacts` table `tags` column (JSON), dynamic dropdowns in
compose/edit UI, tag-based check in `_passes()` in posts.py.

**3. Identity portability / `export_identity.py`**
Package just key material (encrypted private key + argon2 salt/params) separately from the
full backup bundle. Lets a user reclaim their username on a fresh instance without a full
restore — copy the key file, start up, data-less but identity intact.

**4. Registry profile fields**
Decide what (if anything) belongs in the registry beyond `{server_url, client_url, public_key, ttl}`.
Display name and photo_url are already being pushed by the heartbeat. Mostly a policy question now.

**5. Client API test suite**
Comprehensive pytest suite covering every endpoint the client exposes to the browser. Goals:
catch regressions early (e.g. missing `_internal_headers()` on profile GET), and document
the contract between frontend and client layer.

Scope — one test per client `/api/` route, plus the special-cased routes:

*Auth & session*
- `GET /client/login-url` → returns `{auth_url}`
- `POST /client/session` with valid server token → issues session token
- `POST /client/session` with bad token → 401
- `GET /auth/callback` with query params → proxies to server and follows redirect
- `GET /auth/callback` without query params → serves `callback.html`
- `GET /api/auth/me` → returns role/identity from server

*Config*
- `GET /api/config` → own_server, servers list, contacts

*Posts & feed*
- `GET /api/feed` (own + contacts)
- `GET /posts?limit=N` passthrough
- `POST /api/posts` (owner only)
- `PATCH /api/posts/{id}`
- `DELETE /api/posts/{id}`
- `GET /api/posts/{id}/comments`
- `POST /api/posts/{id}/comments`

*Profile*
- `GET /api/profile` → proxied to server with internal token (regression: was missing headers)
- `PUT /api/profile` → requires owner token
- `PUT /api/profile/photo` → multipart, requires owner token

*Assets*
- `GET /api/assets/{id}/thumb`
- `GET /api/assets/{id}`

*Contacts*
- `GET /api/contacts/lookup?handle=`
- `POST /api/contacts`
- `DELETE /api/contacts?url=`

*Backup/restore*
- `GET /api/backup` → zip with client_config appended
- `POST /api/restore`

*Admin*
- `GET /api/admin/...` (whatever admin routes are exposed)

*Setup intercepts*
- `POST /setup/new` → captures `node_key` + `internal_token` into `client_config.json`
- `POST /setup/restore` → same

Test approach: spin up a real server + client pair with `httpx.AsyncClient` against ASGI
(no Docker required). Use a temp directory for data, short argon2 params for speed. Mock
the identity proxy / Google SSO exchange only at the boundary. Run with `pytest -x`.

**6. Fresh VM end-to-end test**
Validate the full flow (Caddy TLS, Google SSO via identity proxy, setup wizard, backup/restore)
on a clean cloud VM — not the Pi. The identity proxy means zero Google Console setup for new
users; worth confirming end-to-end.

**6. Reaction emoji on posts and comments**
Allow users to react to posts and comments with emoji (👍 ❤️ 😂 etc.). Reactions are stored
server-side, attributed to the reactor's identity (owner or contact node). Display as counts
grouped by emoji below each post/comment.

**7. @mention notifications**
When a post or comment contains `@handle`, the sender's server should push a notification to
the tagged contact's server (a lightweight federated ping: post ID + sender). The contact's
client can then surface an "unread mentions" count/badge and a mentions feed. Requires: parse
@mentions on post/comment create, fan-out ping to tagged servers, mentions table on receiving
server, badge in client header.

**8. Chat / direct messages**
Real-time or near-real-time 1:1 and small-group messaging between contacts. Messages are
encrypted end-to-end (sender encrypts to recipient's public key), stored on the sender's
node, and pushed or polled by the recipient's node. Key open questions: push vs. poll
delivery, read receipts, group key management, and how chat threads relate to the existing
post/comment data model. Likely a distinct `messages` table and a separate UI panel rather
than shoehorning into posts.

**9. Profile photo preview on hover/click**
When clicking or hovering over a contact's profile photo (in post cards, comment authors,
contact list, reactors panel), show a larger version of the photo in a tooltip or small
lightbox. The photo URL is `server_url + "/profile/photo"` — the same endpoint already
used for thumbnails in search results and the reactors panel.

**10. Plaintext metadata hardening**
Some metadata (post timestamps, asset filenames) is stored or transmitted in plaintext.
Assess what leaks and whether it matters for the threat model.

---

## Completed

- **Registry heartbeat + auto-register**: server signs and pushes to registry on startup and every hour
- **Aggregate feed**: client fetches all contacts in parallel, merges by `created_at`; "All" button in sidebar
- **Add/remove contacts by handle**: lookup via registry, handle stored in `ContactEntry`; ✕ button in sidebar
- **Contact URL auto-refresh**: on fetch failure, look up handle in registry, update stored URL, retry
- **Backup/restore bundle**: client augments server zip with `client_config.json`; restore proxy extracts and applies contacts
- **Search expansion**: matches handle, display name (returns all posts), post body, and comment bodies
- **Author display on posts**: profile photo/initials + display name on every post card, handle on hover
- **Header redesign**: contacc logo top-left, profile avatar, @handle clickable to filter own posts
- **Server-side contacts table**: synced from client on add/remove; used to authorize inbound comments via X-Origin-Server
- **Contact-based comment auth**: contacts can comment on contacts-visible posts; X-Origin-Server identifies the node
- **Visibility/comment_access system**: replaces `is_public` boolean with `visibility` enum and `comment_access` field
  - Levels: `private` (owner only) | `contacts` | `authenticated` (any node with X-Origin-Server) | `public`
  - Intersection rule: both visibility and comment_access must pass independently
  - UI: compose and edit modals have dropdowns for both fields; post cards show 🔒/👥/🔑/🌐 icon
