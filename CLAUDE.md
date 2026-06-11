# contacc/stor — development axioms

## Identity: always use node_id, not handle or server URL

`node_id` and `owner_id` are permanent UUIDs assigned by the registry. Handles and server URLs are mutable and can change.

**Rule**: whenever code needs to identify a node or person — in signatures, notification payloads, database records, API endpoints, log messages — use `node_id` (for the node deployment) or `owner_id` (for the person). Never use handle or server URL as an identifier.

- Registry endpoints that act on a specific node: `/retire/{node_id}`, `/nodes/{node_id}` — not `/{handle}`
- Notification records: store `post_node_id`, `author_node_id` — not server URLs
- Signature messages: `f"contacc:retire:{node_id}:{timestamp}"` — not handle
- Cross-node references: resolve node_id → server URL at lookup time via the registry; never store the URL as a durable reference

Handle and server URL are display/routing hints that the registry can update at any time. Treat them as caches, not identities.
