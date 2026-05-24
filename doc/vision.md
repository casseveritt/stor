# contac — Broader Vision

*This document captures aspirational directions that are out of scope for the current design phase but should inform how the system is architected. None of this is normative. The goal is to avoid making decisions today that would foreclose these possibilities tomorrow.*

---

## This Is Not Just a Photo Sharing System

The core protocol is framed around sharing photos and videos with friends, because that is the most tangible and immediate use case. But the underlying system — content-addressed storage, per-asset ACLs, identity-scoped access, AI-mediated judgment about what to surface — is not inherently limited to media files.

The same model applies to any personal data: email, chat histories, documents, health records, financial records, location history. The interesting and largely unsolved problem is how a person can make selective, limited, auditable use of that data — including making it available to AI agents — without surrendering blanket access to any of it.

---

## Bootstrapping from Existing Data Sources

A practical barrier to any new personal data system is the cold start problem: the data is already somewhere else. Services like Google Takeout, Apple's data export, and similar mechanisms from other platforms provide a structured way to retrieve a copy of one's own data.

The intent is not to import and re-share everything — most of it wouldn't be appropriate to share at all. But a well-designed import pipeline could ingest a Takeout archive and make a curated subset available with minimal effort: organizing photos into albums, surfacing them in the feed for specific recipients, applying watermarks before delivery. The existing `import2filestore.py` script is a primitive version of this idea applied to a local directory; the same concept extends naturally to structured export formats.

Import from external sources should be a first-class concern in the tooling layer, even if it is not part of the protocol itself.

---

## Personal Data as a Managed Resource for Agents

A more ambitious direction: treating the node not just as a sharing system but as a **personal data vault** that AI agents can query with scoped, time-limited, auditable access.

The scenario: a user wants an AI agent to help them with something that requires access to their email or chat history — summarizing a thread, finding a reference, drafting a reply in context. Today, this typically means giving the agent access to the entire account. That is an all-or-nothing grant that most people rightly find uncomfortable.

A `contac` node could provide a different model:

- The user imports email and chat data into the node (or the node connects to live sources with read-only access).
- When an agent needs access, it requests it via the same credential and ACL mechanism used for any other recipient.
- The node owner — or an AI acting on their behalf — decides what subset to surface: a specific date range, a specific correspondent, a specific topic. The rest is simply not in scope.
- The agent operates on what it receives, with watermarking or other attribution mechanisms ensuring the provenance of any information it uses is traceable.
- Access is time-limited and revocable. The agent cannot accumulate data beyond what was explicitly surfaced.

This is a substantially different and harder problem than photo sharing, and it raises questions about live data connectors, data freshness, and the semantics of ACLs over structured data (email threads, conversation graphs) rather than files. It is noted here not as a near-term goal but as a direction worth keeping in view when making architectural decisions — particularly around identity, credentialing, and the expressiveness of access scoping.

---

## The Unifying Idea

What connects photo sharing, social media import, and agent-scoped data access is a single underlying concern: **a person should be able to decide, with appropriate granularity and ongoing judgment, what of their personal information is available to whom, under what conditions, and for how long.** The current tools — platform privacy settings, OAuth scopes, email forwarding — are too coarse, too permanent, and too opaque to support this well.

`contac` is an attempt to build the substrate for something better, starting from the simplest case and leaving the architecture open enough to grow.
