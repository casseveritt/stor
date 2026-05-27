# contacc Federation Protocol — Abstract Specification

## Status: Draft

This document defines the `stor` federation protocol at an abstract level. It describes entities, behaviors, and operations without committing to a specific wire format, transport, or implementation language. Concrete protocol bindings (e.g., HTTP/REST, gRPC) are defined in separate documents and must conform to the semantics described here.

The feed format is a clean custom design — minimal but extensible — taking lessons from existing standards (Atom's pagination discipline, the `type`-field extensibility of ActivityStreams, HTTP's principle of ignoring unknown fields gracefully) without adopting their full complexity or assumptions.

---

## 1. Core Concepts

### 1.1 Node

A **Node** is an autonomous instance of the system operated by a single primary user. A node:

- Hosts content on behalf of its primary user.
- Has a stable, globally reachable address (the form of that address is binding-specific).
- Is authoritative for all content and identities it originates.
- Does not mirror content from other nodes — content is always fetched from its origin node.

### 1.2 Identity

An **Identity** uniquely identifies a user within the federation. Identities are scoped to an authentication provider, using the form `provider:identifier` (e.g., `google:alice@gmail.com`, `github:alice`). This allows the same logical person to hold multiple identities across providers, which the node owner may map to a single ACL entry.

A node itself also has an identity, established by its keypair, used for node-to-node trust.

### 1.3 Asset

An **Asset** is the fundamental unit of content. It consists of:

- **Content**: The raw bytes of the file (stored once, content-addressed by a node-internal hash). Immutable.
- **Metadata**: Descriptive information about the asset (see §3). Mutable.
- **ACL**: The set of identities permitted to access this asset (see §4). Mutable.

Because content is immutable, replacing the bytes of an asset means publishing a new asset. The relationship between old and new is expressed via successor/predecessor links (see §3).

### 1.4 Feed

A **Feed** is a time-ordered, paginated sequence of asset metadata records. A feed query returns only metadata (not content) for assets the requesting identity is permitted to see. Clients use feed results to decide which assets to fetch.

### 1.5 Credential

A **Credential** is proof of identity presented by a client to authenticate requests. The primary authentication mechanism is SSO: the node accepts identity assertions from trusted SSO providers (OAuth2/OIDC and equivalents). After a successful SSO flow, the node issues a short-lived session credential for use in subsequent requests.

Credentials:
- Are bound to a specific identity.
- Have a defined validity period.
- Can be revoked by the issuing node.

Secondary credential mechanisms (invite tokens, node-to-node trust) are optional extensions for cases where SSO is unavailable.

### 1.6 Watermark

A **Watermark** is a recipient-specific marking applied to asset content **at delivery time**. Stored assets are never modified. Watermarks serve as a deterrent to unauthorized redistribution by embedding the recipient's identity in the content.

Watermarking is **not mandatory** — it is a capability that nodes may enable per asset or globally. However, the protocol is designed so that nothing in it degrades or strips a watermark that an implementation has applied. Nodes declare their watermarking policy so that all recipients are on notice that delivered content may carry hidden markings, regardless of whether a specific asset is actually watermarked.

### 1.7 Comment

A **Comment** is a piece of text associated with an asset, treated as content: the comment body is immutable once posted and is identified by its content hash. Comments:

- Are threaded: each comment may reference a parent comment, forming a tree.
- Are attributed to an identity.
- Are ordered by timestamp within each thread level.
- Are **owned by the asset's node**. A remote user posting a comment does so directly to the asset's node, which stores and serves it. There is no cross-node comment synchronization.
- May be requested for edit or deletion by their original author, but whether such requests are granted is at the sole discretion of the node owner.

An accepted edit results in a new comment with a `predecessor` link to the original; the original gains a `successor` link. Both remain accessible.

---

## 2. Federation Model

The system is **federated**: nodes are independent and there is no central authority.

### 2.1 Node Identity and Trust

Each node holds a long-lived keypair. The public key is reachable via the node's address and is used to verify node-issued credentials and signed content. Nodes establish bilateral trust explicitly — there is no automatic or transitive trust.

### 2.2 Cross-Node Access

A recipient authenticates to a node using SSO or a node-issued session credential. Cross-node credential acceptance (node B's credential honored by node A) is an optional extension requiring explicit bilateral trust configuration between nodes.

### 2.3 Content Locality

Content always remains on the origin node. Federation does not imply replication. A client accessing an asset must contact the node that holds it.

### 2.4 Node Discovery

Node discovery is **out-of-band and intentional**. A user learns of a node through an explicit invite from the node owner, or a referral from an existing user with access. There is no central registry and no automatic peer discovery. This is a deliberate design choice: access to a node is a social relationship, and the watermarking model means that sharing access — or the content it enables — carries accountability.

---

## 3. Asset Metadata

The following fields are defined for all assets. Metadata is mutable; content (and therefore `content_hash`) is not. Implementations must preserve unknown fields they receive rather than discarding them (forward compatibility).

| Field | Mutability | Description |
|---|---|---|
| `id` | Immutable | Stable identifier for the asset within its node |
| `node` | Immutable | Address of the origin node |
| `content_hash` | Immutable | Node-internal hash of the raw content. Opaque to clients; its meaning and algorithm are an implementation detail of the node. Used as a stable content identifier, not as a client-verifiable checksum. |
| `media_type` | Immutable | MIME type of the content |
| `size` | Immutable | Size of the raw content in bytes |
| `created_at` | Immutable | Timestamp when the asset was first published |
| `title` | Mutable | Optional human-readable title |
| `tags` | Mutable | Optional list of string tags |
| `comment_count` | Derived | Number of top-level comments |
| `predecessor` | Mutable | ID of the asset this one supersedes (optional) |
| `successor` | Mutable | ID of the asset that supersedes this one (optional) |
| `post_type` | Immutable | Post type classification (see §3.1). Defaults to `post` if absent. |

Assets with a `successor` are considered superseded. Feed queries return superseded assets only when explicitly requested.

### 3.1 Post Types

The `post_type` field classifies an asset's intended purpose and governs sharing and access behavior.

| Value | Description |
|---|---|
| `post` | Standard shareable content. Subject to the ACL; may be shared with recipients or published publicly. |
| `inner_monologue` | A private journal entry. Never shared; no recipients, no public flag. Not subject to the ACL beyond owner access. Excluded from feed queries unless explicitly requested. |

**`inner_monologue` constraints:**

- The ACL for an inner monologue asset contains only the owner. Attempts to add recipients are rejected by the node.
- Inner monologue assets are never included in feed responses to non-owner callers, regardless of any other access grant.
- AI agents acting on behalf of the owner do not have access to inner monologue assets by default. Access requires an explicit, scoped capability grant for the session or task. This boundary is intentional and load-bearing: it prevents unfiltered private thoughts from leaking into sessions where they were not deliberately introduced.
- How inner monologue entries are presented, searched, or surfaced in a client is a user preference stored in the user's own data store. The protocol imposes no presentation policy beyond the access constraints above.

Future post types may be defined as extensions. Implementations must not error on unknown `post_type` values — treat them as `post` for access-control purposes and preserve the value in metadata.

---

## 4. Access Control

### 4.1 ACL Model

Each asset has an **Access Control List (ACL)**: an explicit set of identities permitted to access it. Access is **deny by default**.

### 4.2 Special Identities

- **Owner**: The primary user of the hosting node. Always has full access; cannot be removed.
- **Public**: A wildcard meaning any authenticated requester from a trusted node. Nodes may optionally support unauthenticated public access per asset.

### 4.3 Identity Mapping

A node owner may map multiple provider-scoped identities (e.g., `google:alice@gmail.com` and `github:alice`) to a single logical person in the ACL. The mapping is local to the node and not exposed externally.

### 4.4 Share Tokens

For recipients without an SSO identity known to the node, the owner may issue **signed share tokens**: self-contained, time-limited credentials scoped to specific assets. Share tokens encode the recipient's identifying information for watermarking and are delivered out-of-band (e.g., invite URL, QR code).

---

## 5. Operations

Operations are defined abstractly. Concrete bindings map these to protocol-specific forms (HTTP methods and paths, gRPC service methods, etc.).

### 5.1 QueryFeed

**Purpose**: Retrieve a paginated list of asset metadata for assets the caller can access, filtered by time window.

**Inputs**:
- Target node address
- `since`: start of time window (inclusive)
- `until`: end of time window (inclusive); defaults to now
- `limit`: maximum results per page
- `cursor`: opaque pagination token from a prior response (optional)
- `include_superseded`: whether to include assets with a `successor` (default: false)
- Credential

**Outputs**:
- List of asset metadata records (see §3)
- `next_cursor`: absent if no further results
- Echo of node address and query parameters for verification

**Behavior**: Only assets where the caller's identity appears in the ACL are included. Results are ordered by `created_at` descending.

---

### 5.2 FetchAsset

**Purpose**: Retrieve the content of a specific asset.

**Inputs**:
- Target node address
- Asset ID
- Credential

**Outputs**:
- Asset content (bytes), watermarked if the node has watermarking enabled for this asset
- Content metadata (media type, size, `content_hash` of the pre-watermark original)

**Behavior**: ACL checked first. If watermarking is enabled, it is applied before delivery. Because delivered content may be watermarked, clients cannot verify `content_hash` against what they receive — it is provided as a stable content identifier, not a transport integrity check. A node may optionally provide a separately-computed delivery hash (of a declared algorithm) for transport integrity verification; this is distinct from `content_hash`. If watermarking is enabled but fails, the node must return an error rather than serve un-watermarked content.

---

### 5.3 FetchThumbnail

**Purpose**: Retrieve a small preview of an asset.

**Inputs**: Same as FetchAsset.

**Outputs**: Thumbnail image bytes, watermarked if watermarking is enabled.

**Behavior**: Same ACL rules as FetchAsset. Thumbnail generation strategy is implementation-specific.

---

### 5.4 FetchAssetMeta

**Purpose**: Retrieve full metadata for a single asset without fetching content.

**Inputs**:
- Target node address
- Asset ID
- Credential

**Outputs**: Full asset metadata record (see §3).

**Behavior**: ACL checked. No content or watermarking involved.

---

### 5.5 FetchComments

**Purpose**: Retrieve the comment thread for an asset.

**Inputs**:
- Target node address
- Asset ID
- Credential

**Outputs**: Threaded list of comments. Each comment: ID, content hash, parent ID (if any), author identity, body, timestamp, predecessor/successor links (if any).

**Behavior**: ACL check on the asset applies.

---

### 5.6 PostComment

**Purpose**: Add a comment to an asset's thread.

**Inputs**:
- Target node address
- Asset ID
- Parent comment ID (optional; omit for top-level)
- Comment body text
- Credential

**Outputs**: The created comment record, including its assigned ID and content hash.

**Behavior**: ACL check on the asset applies. Author identity is derived from the credential. The comment body is stored immutably and identified by its content hash.

---

### 5.7 RequestCommentEdit *(optional)*

**Purpose**: Request that the node owner approve an edit or deletion of a comment.

**Inputs**:
- Target node address
- Comment ID
- New body text (omit to request deletion)
- Credential (must match the original comment's author identity)

**Outputs**: Request acknowledgment. The outcome is asynchronous and at the owner's discretion.

**Behavior**: If approved, a deletion removes the comment from the thread (or replaces it with a tombstone). An approved edit creates a new comment with a `predecessor` link; the original gains a `successor` link.

---

### 5.8 PublishAsset *(Phase 2 — Owner only)*

**Purpose**: Add a new asset to the node.

**Inputs**:
- Content bytes
- Metadata (media type, title, tags, predecessor asset ID if superseding, etc.)
- Initial ACL
- Credential (must resolve to node owner)

**Outputs**: Created asset record including assigned ID and `content_hash`.

**Behavior**: Content stored content-addressed. Asset immediately queryable via feed by ACL members.

---

### 5.9 UpdateMetadata *(Phase 2 — Owner only)*

**Purpose**: Update mutable metadata fields of an existing asset.

**Inputs**:
- Asset ID
- Metadata fields to update (title, tags, successor, predecessor, etc.)
- Credential (must resolve to node owner)

**Outputs**: Updated asset metadata record.

---

### 5.10 UpdateACL *(Phase 2 — Owner only)*

**Purpose**: Modify the ACL for an existing asset.

**Inputs**:
- Asset ID
- ACL delta: identities to add and/or remove
- Credential (must resolve to node owner)

**Outputs**: Updated ACL.

**Behavior**: Owner cannot be removed. Changes take effect immediately.

---

### 5.11 IssueShareToken *(Phase 2 — Owner only)*

**Purpose**: Issue a share token for a recipient without a known SSO identity.

**Inputs**:
- Recipient identifying information (name or description, for watermarking)
- Asset scope (specific asset IDs, or node-wide)
- Validity period
- Credential (must resolve to node owner)

**Outputs**: A signed share token the recipient can use to authenticate scoped requests.

---

## 6. Watermark Behavior (Normative)

1. Watermarking is **optional** — nodes and asset owners choose whether to enable it.
2. When enabled, watermarking is applied **after** ACL verification and **before** content is returned.
3. The stored asset is **never modified**.
4. An enabled watermark **must encode the recipient's identity** in a form that survives reasonable transformations (e.g., screenshot, re-save).
5. If watermarking is enabled and fails, the node **must not** fall back to un-watermarked delivery — it must return an error.
6. Nodes **must** declare their watermarking policy in their node metadata, so all recipients are on notice that content may carry hidden markings. This declaration does not reveal which assets are watermarked or by what method.
7. Protocol operations **must not** involve steps that would degrade or strip a watermark (e.g., re-encoding, transcoding as part of delivery is prohibited unless the watermark is re-applied afterward).

---

## 7. Extensibility

- Metadata records may contain fields not defined in this spec. Implementations must preserve and forward unknown fields rather than discarding them.
- New operation types may be defined in binding documents or future spec versions. Implementations must not error on unknown operation types — they should return an appropriate "not supported" response.
- The `type` field (where applicable) is reserved for extensibility and must be included in all records that may be subclassed.

---

## 8. Out of Scope (for this version)

- Search across assets
- Node-to-node content replication or caching
- End-to-end encryption of content (separate from transport security)
- Fine-grained permissions beyond read access (e.g., download vs. stream only)
- Moderation across federated nodes
- Automatic node discovery or peer exchange
