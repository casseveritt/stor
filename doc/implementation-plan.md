# contac Implementation Plan

## Approach

Build a walking skeleton first — the thinnest vertical slice that exercises every layer of the system — then grow outward from it. Each phase must be working and tested before the next begins. The reference implementation uses Python and FastAPI; this may change if a compelling reason arises.

The existing `scripts/` and SQLite + `files/` storage layer are reused as-is. The web layer is a new component that sits on top of the store.

---

## Technology

| Concern | Choice | Notes |
|---|---|---|
| Language | Python | Consistent with existing scripts |
| Web framework | FastAPI | Async support for streaming; auto OpenAPI docs |
| Test harness | pytest | Integration tests against a live server instance |
| Auth (early) | Signed static tokens | Gets auth into the architecture without OAuth ceremony |
| Auth (later) | OAuth2/OIDC (SSO) | Replaces static tokens; Google et al. |
| Watermarking | Pillow (images), FFmpeg (video) | Applied in delivery pipeline |
| DB | SQLCipher | Encrypted SQLite (drop-in SQLite replacement); key derived from owner passphrase, held in process memory |
| File encryption | AES-256-GCM | Per-file; random 12-byte nonce prepended to ciphertext |
| Key derivation | Argon2id | Owner passphrase → 32-byte master key; Argon2id parameters + salt stored in node config; key never written to disk |
| Key injection | Passphrase at startup | Interactive prompt or `--key-stdin` (for systemd/scripted starts); no env-var or file-based key persistence |

---

## Encryption Architecture

All data at rest is encrypted. Decryption keys exist only in process memory for the lifetime of the running server. No key material is ever written to disk.

### Master Key and Subkeys

At node initialization the owner chooses a passphrase. A random 16-byte Argon2id salt is generated and stored in the node config file (plaintext — it is not secret). On every startup the passphrase is run through Argon2id with that salt to produce a 32-byte master key. Two subkeys are then derived via HKDF:

- `db_key = HKDF(master_key, info="contac-db")`
- `file_key = HKDF(master_key, info="contac-files")`

The master key and both subkeys exist only in memory. If the server process stops, the keys are gone; the next startup requires the passphrase again.

### Database Encryption

The SQLite database is opened via SQLCipher using `db_key`. SQLCipher encrypts at the page level; the `.db` file on disk is opaque ciphertext without the key. Schema migrations operate on the live SQLCipher connection exactly as they would on unencrypted SQLite.

### File Store Encryption

Each file written into `files/<xx>/<hash>` is encrypted with AES-256-GCM under `file_key`. A randomly generated 12-byte nonce is prepended to the ciphertext:

```
[ 12-byte nonce | AES-256-GCM ciphertext | 16-byte auth tag ]
```

Files are decrypted into memory on read. The stored filename is still the BLAKE3 hash of the original plaintext (content-addressable semantics are preserved; the hash is computed before encryption). Watermarking (Phase 5) operates entirely in memory on the decrypted bytes; neither decrypted content nor watermarked output is written to disk.

### Node Keypair

The Ed25519 private key is generated once at initialization and stored encrypted (AES-256-GCM, `master_key` derived key) in the node config file. It is decrypted into memory at startup alongside the database key.

### Startup Flow

1. Server reads the Argon2id parameters and salt from the node config file.
2. Owner provides the passphrase (interactive prompt, or piped via `--key-stdin` — never an env var or key file that could be logged or leaked).
3. Master key and subkeys are derived and held in process memory.
4. SQLCipher connection is opened with `db_key`; if the passphrase is wrong, the connection fails and the server does not start.
5. Node private key is decrypted into memory.
6. Server begins accepting requests.

### Ownership Boundary

The owner is the only party who can start the server (requires the passphrase), decrypt any data (all keys trace back to the passphrase), issue or revoke credentials (operations against the encrypted DB), or modify ACLs. Recipients authenticate to a running server and receive content in transit; they have no access to key material, the encrypted DB, or the raw files on disk.

---

## Phase 1 — Server Skeleton

**Goal**: A running server with a node identity and full encryption at rest. Proves the stack — including the encryption layer — works end-to-end before any real operations are added.

**Deliverables**:
- Node initialization CLI: generates Argon2id salt, derives master key and subkeys, initializes SQLCipher DB, generates and stores encrypted Ed25519 keypair; prompts for owner passphrase
- Startup passphrase handling: interactive prompt and `--key-stdin` flag; key derivation (Argon2id + HKDF) runs before any other startup step
- FastAPI app scaffolding with configuration (node address, encrypted keypair path, store path)
- SQLCipher connection setup; server refuses to start if passphrase is wrong
- File store encryption helpers: encrypt-on-write, decrypt-on-read (AES-256-GCM)
- Node metadata endpoint: returns node address, public key, watermarking policy declaration
- Health/liveness endpoint
- Basic logging

**DB changes**: SQLCipher-encrypted SQLite initialized with Argon2id-derived key.

**Tests**:
- Server starts cleanly against a temporary store with correct passphrase
- Server refuses to start with wrong passphrase
- DB file on disk cannot be opened as plaintext SQLite
- A file written through the encryption helper cannot be read back as plaintext
- Node metadata endpoint returns valid JSON with required fields
- Public key in response is valid Ed25519

---

## Phase 2 — QueryFeed

**Goal**: A client can query the feed and get asset metadata back. No ACL enforcement yet — owner credential only.

**Deliverables**:
- DB schema additions: `assets` table (metadata, predecessor/successor links)
- Migration/population script to import existing `relpaths` rows into `assets`
- `QueryFeed` endpoint: time window, pagination (cursor-based), `include_superseded` flag
- Owner credential: a static signed token for the owner identity (CLI tool to generate)
- Feed response format per spec §3

**DB changes**:
- Add `assets` table: `id`, `content_hash`, `media_type`, `size`, `created_at`, `title`, `tags`, `predecessor`, `successor`
- `relpaths` remains unchanged; `assets` is a new view over the same content

**Tests**:
- Feed returns empty list for empty store
- Feed returns correct metadata for imported assets
- Pagination: cursor advances correctly across pages
- `include_superseded=false` hides assets with a successor
- Request without valid credential is rejected

---

## Phase 3 — FetchAsset and FetchAssetMeta

**Goal**: A client can fetch asset content and metadata. Completes the core read path.

**Deliverables**:
- `FetchAsset` endpoint: streams content from `files/<b3sum[:2]>/<b3sum>`; returns `content_hash` in response metadata
- `FetchAssetMeta` endpoint: returns full metadata record for a single asset
- `FetchThumbnail` endpoint: generates and streams a thumbnail (Pillow for images; placeholder for other types)
- Content-type detection from stored MIME type

**DB changes**: None.

**Tests**:
- Fetch returns correct bytes for a known asset
- Content-hash in response matches stored hash
- Fetch for unknown asset ID returns appropriate error
- Thumbnail returns a valid image for image assets
- Request without valid credential is rejected

---

## Phase 4 — Auth and ACL Enforcement

**Goal**: Access control is enforced throughout the read path. Multiple recipients can be granted access to specific assets.

**Deliverables**:
- DB schema additions: `recipients`, `acl`, `tokens` tables
- `recipients`: known identities (`provider:identifier`, display name)
- `acl`: per-asset allow-list (`asset_id`, `recipient_id`)
- `tokens`: issued session tokens (id, recipient, expiry, revoked flag)
- Token issuance CLI tool (for owner and recipients)
- Token validation middleware applied to all endpoints
- ACL check on FetchAsset, FetchAssetMeta, FetchThumbnail, QueryFeed
- Owner identity always passes ACL checks

**DB changes**:
- Add `recipients` table
- Add `acl` table
- Add `tokens` table

**Tests**:
- Recipient with ACL access can fetch asset
- Recipient without ACL access is denied
- Expired token is rejected
- Revoked token is rejected
- Owner token always passes
- Feed only returns assets the caller has ACL access to

---

## Phase 5 — Watermarking

**Goal**: Asset content is watermarked at delivery time for recipients where watermarking is enabled.

**Deliverables**:
- Watermark pipeline step in FetchAsset and FetchThumbnail
- Visible text watermark for images (Pillow): recipient identity overlaid
- Steganographic watermark for images (optional, via a steganography library)
- FFmpeg-based watermark for video (recipient identity burned into frames)
- Non-media types passed through unchanged
- Node-level watermarking policy flag (enabled/disabled); surfaced in node metadata endpoint
- If watermarking is enabled and fails, return error (never fall back to un-watermarked delivery)

**DB changes**: None (watermark config in server config file).

**Tests**:
- Watermarked image contains visible recipient identity text
- Content-hash in response still matches original un-watermarked hash
- Watermark failure returns error, not un-watermarked content
- Non-media asset passes through unchanged regardless of watermark setting

---

## Phase 6 — SSO Authentication

**Goal**: Recipients authenticate via SSO (OAuth2/OIDC) rather than static tokens.

**Deliverables**:
- OAuth2/OIDC login flow (Google as first provider)
- After successful SSO, node issues a short-lived session token bound to the resolved identity
- Identity normalization: SSO claims mapped to `provider:identifier` form
- Identity mapping: node owner can map multiple SSO identities to one ACL entry
- Static token path remains as a fallback (for owner and share tokens)

**DB changes**:
- Add `identity_mappings` table: maps `provider:identifier` → `recipient_id`

**Tests**:
- Successful SSO flow results in a valid session token
- Session token is accepted on subsequent requests
- Unknown SSO identity (no mapping, no ACL) is denied
- Mapped identity passes ACL checks correctly

---

## Phase 7 — Comments

**Goal**: Recipients can post and read threaded comments on assets.

**Deliverables**:
- DB schema: `comments` table (`id`, `content_hash`, `asset_id`, `parent_id`, `author_recipient_id`, `body`, `created_at`, `predecessor`, `successor`)
- `FetchComments` endpoint: returns threaded comment tree
- `PostComment` endpoint: stores comment, returns record with content hash
- `RequestCommentEdit` endpoint: records a request; owner reviews and approves/rejects via CLI tool initially
- Approved edit: new comment created with predecessor link; original gains successor

**DB changes**:
- Add `comments` table
- Add `comment_edit_requests` table

**Tests**:
- Post comment returns record with correct content hash
- Fetch returns threaded structure correctly
- Reply to a comment sets parent correctly
- Edit request is recorded; approval creates successor/predecessor chain
- Deleted comment replaced with tombstone

---

## Phase 8 — Phase 2 Write Operations

**Goal**: The owner can publish assets, update metadata and ACLs, and issue share tokens via the API (not just CLI scripts).

**Deliverables**:
- `PublishAsset` endpoint (owner only)
- `UpdateMetadata` endpoint (owner only)
- `UpdateACL` endpoint (owner only)
- `IssueShareToken` endpoint (owner only)
- Share token: self-contained signed credential scoped to specific assets, carrying recipient identity for watermarking

**DB changes**: None (all tables already exist by Phase 7).

**Tests**:
- Published asset appears in feed
- Metadata update reflected in subsequent FetchAssetMeta
- ACL update takes effect immediately
- Share token grants access to scoped assets only
- Share token expiry is enforced

---

## Project Structure (Target)

```
stor/
  scripts/          # Existing maintenance scripts (unchanged)
  doc/              # Specs and plans
  server/
    main.py         # FastAPI app entry point
    config.py       # Configuration loading
    auth.py         # Token validation, SSO flow
    feed.py         # QueryFeed
    assets.py       # FetchAsset, FetchAssetMeta, FetchThumbnail
    comments.py     # FetchComments, PostComment, RequestCommentEdit
    watermark.py    # Watermark pipeline
    db.py           # DB connection and schema management
    node.py         # Node identity, keypair, metadata endpoint
  tests/
    conftest.py     # pytest fixtures: temp store, server instance, test tokens
    test_phase1.py
    test_phase2.py
    ...
  tools/
    generate_keypair.py
    issue_token.py
    import_assets.py   # Wrapper around existing import2filestore.py
```

---

## Guiding Principles

- **Each phase is shippable**: don't start the next phase until the current one has passing tests.
- **Encryption is in the architecture from Phase 1**: the SQLCipher DB and file encryption helpers are established before any data operations are added. No plaintext-first shortcuts.
- **Keys never touch disk**: Argon2id salt and Argon2id parameters are not secret and may be stored. The derived master key, subkeys, and node private key are never written to any file, log, or env var.
- **No mocking the storage layer in integration tests**: tests run against a real (temporary) SQLCipher store and encrypted `files/` directory.
- **Auth is in the architecture from Phase 2 onward**: no "add auth later" shortcuts that require ripping things out.
- **The spec is the contract**: if an implementation decision conflicts with `spec.md`, update the spec deliberately rather than quietly diverging.
