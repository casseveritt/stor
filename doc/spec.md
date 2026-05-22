# stor Federation Protocol — Abstract Specification

## Status: Draft

This document defines the `stor` federation protocol at an abstract level. It describes entities, behaviors, and operations without committing to a specific wire format, transport, or implementation language. Concrete protocol bindings (e.g., HTTP/REST, ActivityPub, gRPC) are defined in separate documents and must conform to the semantics described here.

---

## 1. Core Concepts

### 1.1 Node

A **Node** is an autonomous instance of the system operated by a single primary user. A node:

- Hosts content on behalf of its primary user.
- Has a stable, globally reachable address (the form of that address is binding-specific).
- Is authoritative for all content and identities it originates.
- Does not mirror content from other nodes — content is always fetched from its origin node.

### 1.2 Identity

An **Identity** is a globally unique reference to a user. It is composed of a local name and the address of the node that vouches for it. Identities are used in ACLs, credentials, comment authorship, and inter-node trust.

A node itself also has an identity, used for node-to-node trust relationships.

### 1.3 Asset

An **Asset** is the fundamental unit of content. It consists of:

- **Content**: The raw bytes of the file (stored once, content-addressed).
- **Metadata**: Descriptive information about the asset (see §3).
- **ACL**: The set of identities permitted to access this asset (see §4).

Assets are immutable once published. Updates are expressed as new asset versions (versioning strategy TBD).

### 1.4 Feed

A **Feed** is a time-ordered, paginated sequence of asset metadata records. A feed query returns only the metadata (not content) for assets that the requesting identity is permitted to see. Clients use feed results to decide which assets to fetch.

### 1.5 Credential

A **Credential** is proof of identity, issued by a node and presented by a client to authenticate requests. Credentials:

- Are bound to a specific identity.
- Have a defined validity period.
- Can be revoked by the issuing node.
- May be honored by other nodes that trust the issuing node (cross-node credential acceptance is a federation concern).

The internal structure of a credential is implementation-specific; what matters is the behavior it enables.

### 1.6 Watermark

A **Watermark** is a recipient-specific marking applied to asset content **at delivery time**. Stored assets are never modified. Watermarks serve as a deterrent to unauthorized redistribution by embedding the recipient's identity in the content.

- Watermarking applies to media types where embedding is feasible (images, video).
- Non-media assets are passed through without modification.
- The watermark strategy (visible, steganographic, or both) is configurable per node and optionally per asset.
- A watermark must encode enough information to identify the recipient.

### 1.7 Comment

A **Comment** is a piece of text associated with an asset. Comments:

- Are threaded: each comment may reference a parent comment, forming a tree.
- Are attributed to an identity (which may be on a different node than the asset).
- Are ordered by timestamp within each thread level.
- Are owned by the asset's node for moderation purposes, regardless of author origin.

---

## 2. Federation Model

The system is **federated**: nodes are independent and there is no central authority. Federation is expressed through the following relationships:

### 2.1 Node Identity and Trust

Nodes establish trust through cryptographic identity. Each node holds a long-lived keypair. The public key is discoverable via the node's address and is used to verify node-issued credentials and signed content.

### 2.2 Cross-Node Access

A recipient on node B may be granted access to an asset on node A. When the recipient presents a credential issued by node B to node A:

- Node A may accept the credential if it trusts node B (explicit peer trust).
- Node A may reject it and require a locally-issued credential.
- The trust model between nodes is bilateral and explicit — nodes are not open by default.

### 2.3 Federated Comments

Comments may be authored by identities from any trusted node. The asset's home node is authoritative for the comment thread and is responsible for storing and serving all comments, regardless of author origin. The mechanism by which a comment from a remote user reaches the asset's node is an open design question (see §7).

### 2.4 Content Locality

Content (asset bytes) always remains on the origin node. Federation does not imply replication. A client wanting to access an asset must contact the node that holds it.

---

## 3. Asset Metadata

The following fields are defined for all assets. Additional fields may be added in concrete bindings.

| Field | Description |
|---|---|
| `id` | Stable, globally unique identifier for the asset within its node |
| `node` | The address of the origin node |
| `content_hash` | The BLAKE3 hash of the raw content (used for integrity verification) |
| `media_type` | The MIME type of the content |
| `size` | Size of the raw content in bytes |
| `created_at` | Timestamp when the asset was first published |
| `title` | Optional human-readable title |
| `tags` | Optional list of string tags |
| `comment_count` | Number of top-level comments |

---

## 4. Access Control

### 4.1 ACL Model

Each asset has an **Access Control List (ACL)**: an explicit set of identities that are permitted to access it. Access is **deny by default** — an identity not on the ACL has no access, even if authenticated.

### 4.2 Special Identities

- **Owner**: The primary user of the node that hosts the asset. Always has full access. Cannot be removed from the ACL.
- **Public**: A special wildcard identity meaning "any authenticated requester from a trusted node." Nodes may optionally support a further level of "unauthenticated public" access per asset.

### 4.3 Credential-less Access

A node may issue **signed share tokens** — self-contained credentials that grant access to a specific asset (or set of assets) without requiring the recipient to have an account. These tokens:

- Are time-limited.
- Encode the recipient's identifying information for watermarking purposes.
- Cannot be used to access assets beyond what they explicitly authorize.

---

## 5. Operations

Operations are defined abstractly. Each operation has a name, required inputs, outputs, and behavioral postconditions. Concrete bindings map these to protocol-specific forms (e.g., HTTP methods and paths, gRPC service methods).

### 5.1 QueryFeed

**Purpose**: Retrieve a paginated list of asset metadata for assets the caller can access, filtered by time window.

**Inputs**:
- Target node address
- `since`: start of time window (inclusive)
- `until`: end of time window (inclusive); defaults to now
- `limit`: maximum number of results
- `cursor`: opaque pagination token from a previous response (optional)
- Credential

**Outputs**:
- List of asset metadata records (see §3)
- `next_cursor`: pagination token, absent if no further results
- Node address and query echo for verification

**Behavior**: Only assets the caller's identity appears in the ACL for are included. Results are ordered by `created_at` descending.

---

### 5.2 FetchAsset

**Purpose**: Retrieve the content of a specific asset, watermarked for the caller.

**Inputs**:
- Target node address
- Asset ID
- Credential

**Outputs**:
- Asset content (bytes), watermarked if the media type supports it
- Content metadata (media type, size, content hash of the pre-watermark original)

**Behavior**: ACL is checked before content is delivered. Watermarking is applied based on the resolved identity of the caller. The content hash in the response refers to the original un-watermarked content, allowing integrity verification against the stored asset.

---

### 5.3 FetchThumbnail

**Purpose**: Retrieve a small preview of an asset.

**Inputs**: Same as FetchAsset.

**Outputs**: Thumbnail image bytes (format is binding-specific), watermarked.

**Behavior**: Same ACL rules as FetchAsset. Thumbnail generation strategy is implementation-specific.

---

### 5.4 FetchAssetMeta

**Purpose**: Retrieve full metadata for a single asset without fetching content.

**Inputs**:
- Target node address
- Asset ID
- Credential

**Outputs**: Full asset metadata record (see §3), plus any extended fields.

**Behavior**: ACL is checked. No content or watermarking involved.

---

### 5.5 FetchComments

**Purpose**: Retrieve the comment thread for an asset.

**Inputs**:
- Target node address
- Asset ID
- Credential

**Outputs**: Ordered, threaded list of comments. Each comment includes: ID, parent ID (if any), author identity, body, timestamp.

**Behavior**: ACL check on the asset applies. Comments from all trusted nodes are included.

---

### 5.6 PostComment

**Purpose**: Add a comment to an asset's thread.

**Inputs**:
- Target node address
- Asset ID
- Parent comment ID (optional; omit for top-level)
- Comment body text
- Credential

**Outputs**: The created comment record.

**Behavior**: ACL check on the asset applies. Author identity is derived from the credential. The node may apply content moderation policy.

---

### 5.7 PublishAsset *(Phase 2 — Owner only)*

**Purpose**: Add a new asset to the node.

**Inputs**:
- Content bytes
- Metadata (media type, title, tags, etc.)
- Initial ACL
- Credential (must resolve to the node owner)

**Outputs**: The created asset record including assigned ID and content hash.

**Behavior**: Content is stored content-addressed. Metadata and ACL are recorded. Asset becomes immediately queryable via feed by identities in the ACL.

---

### 5.8 UpdateACL *(Phase 2 — Owner only)*

**Purpose**: Modify the ACL for an existing asset.

**Inputs**:
- Asset ID
- ACL delta: identities to add and/or remove
- Credential (must resolve to the node owner)

**Outputs**: Updated ACL.

**Behavior**: Owner cannot be removed. Changes take effect immediately.

---

### 5.9 IssueCredential *(Phase 2 — Owner only)*

**Purpose**: Issue a credential for a recipient identity.

**Inputs**:
- Recipient identity
- Validity period
- Scope (optional: restrict to specific assets)
- Credential (must resolve to the node owner)

**Outputs**: A credential the recipient can use to authenticate requests.

**Behavior**: The issued credential is signed by the node's keypair. The node retains a record for revocation purposes.

---

## 6. Watermark Behavior (Normative)

The following rules apply to all conforming implementations:

1. Watermarking is applied **after** ACL verification and **before** content is returned to the client.
2. The stored asset is **never modified**.
3. The watermark **must encode the recipient's identity** in a form that survives reasonable transformations (e.g., screenshot, re-save).
4. Implementations **should** support at minimum a visible text watermark for images.
5. Implementations **may** additionally support steganographic embedding.
6. If watermarking fails (e.g., unsupported format, processing error), the node **must not** fall back to serving un-watermarked content — it must return an error.

---

## 7. Open Questions

1. **Comment federation delivery**: How does a comment authored on node B reach the asset on node A? Options: (a) push — node B delivers it to node A at post time; (b) pull — node A polls or node B notifies node A. The choice affects latency, complexity, and reliability.

2. **Feed format standardization**: Should the feed format align with an existing standard (Atom, ActivityStreams) to enable interoperability with existing readers and clients?

3. **Watermark strength policy**: Should the spec mandate a minimum watermark strength, or leave it entirely to implementations? A weak watermark undermines the ACL model.

4. **Credential distribution UX**: How does a recipient receive their initial credential out-of-band? This is a usability question with security implications (e.g., email link, QR code, invite URL).

5. **Asset versioning**: Assets are described as immutable. What is the model for correcting or replacing content? Linked successor assets? A version chain?

6. **Node discovery**: How does a client learn that a node exists and that it holds content of interest? Currently assumed to be out-of-band. A more formal discovery mechanism may be needed for federation at scale.

---

## 8. Out of Scope (for this version)

- Search across assets
- Node-to-node content replication or caching
- End-to-end encryption of content (separate from transport security)
- Fine-grained permissions beyond read access (e.g., download vs. stream only)
- Moderation across federated nodes
