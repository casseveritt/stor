# stor Design Philosophy

*This document is aspirational and non-normative. It captures the intent and thinking behind the system's design for the benefit of implementers and future contributors. Nothing here overrides or extends the protocol specification.*

---

## The Protocol as Substrate

The `stor` protocol defines the mechanics of how content is stored, addressed, protected, and exchanged. It deliberately says very little about *why* content is shared with a particular recipient at a particular time, or *how* a client decides what to do with the content it receives. Those decisions are left to the edges — to the node owner and the client user respectively.

This is intentional. The protocol is a substrate, not a policy engine.

---

## Sharing as an Expression of the Node Owner

The node owner decides what to share, with whom, and under what conditions. The ACL system defines hard outer boundaries — a recipient not on an asset's ACL simply cannot access it. But within those boundaries, the owner's decisions about how to organize, tag, annotate, and selectively share content are their own.

Rather than encoding these decisions as rigid, rule-based policies, we expect that in practice they will often reflect something more like judgment: context-sensitive, personal, and difficult to fully specify in advance. LLMs and other AI agents are natural tools for expressing and executing this kind of judgment on the owner's behalf — helping to decide which assets to surface to which recipients, how to annotate content for different audiences, when to open or restrict access based on context, and so on.

The protocol does not prescribe how this judgment is implemented. It only needs to provide the right handles — rich enough metadata, expressive enough ACLs, and a feed structure that an AI agent can reason about.

---

## Consumption as an Expression of the Client

On the receiving end, how a client aggregates, filters, prioritizes, and presents content from one or more nodes is entirely up to the client and its user. Two clients connected to the same node may present completely different views of the same feed, reflecting different interests, contexts, or habits.

Again, AI agents are a natural fit here. Rather than the client presenting a raw chronological feed and leaving the user to sort through it, a client might use an LLM to summarize what's new, surface content the user is likely to care about, make connections across assets, or present content in a form suited to the current context.

The protocol's pull model — query metadata first, fetch content selectively — is designed with this in mind. A lightweight feed query gives an AI agent enough signal to make intelligent fetch decisions without requiring it to download everything.

---

## Ephemerality and Intentional Consumption

Metadata may be cached on the client side. But both metadata and underlying assets should be treated as **ephemeral**: what is available today may not be available tomorrow. Access can be narrowed, assets can be superseded, and the node owner's judgment about what to surface can change. Clients should not assume that a cached view of the feed reflects the current state of the node, or that a previously accessible asset will remain accessible.

This has a direct implication for how clients should behave: **pull what you have strong reason to believe the user will actually see.** Speculative or pre-emptive fetching — downloading assets in case the user might want them — works against the spirit of the system. A node observing client behavior that looks like a bulk scrape rather than purposeful human-driven access may limit that client's access and flag the behavior to the node owner. Clients that consume intentionally and at a human pace are less likely to be mistaken for automated extraction.

The node is not obligated to explain its access decisions. Throttling, narrowing, or suspending access is at the node owner's discretion, and may itself be mediated by AI judgment about whether a client's behavior pattern is consistent with legitimate use.

---

## What This Means for the Protocol

This philosophy has a few practical implications for how the protocol should be designed, even if they are not enforced normatively:

- **Metadata should be rich and machine-readable.** The more context an AI agent has from the feed alone, the better the decisions it can make about what to fetch and how to present it. Tags, titles, timestamps, predecessor/successor relationships, and comment counts all contribute.

- **The feed should be composable.** A client aggregating feeds from multiple nodes should be able to treat them uniformly. Consistent field names, cursor-based pagination, and forward-compatible extensibility all support this.

- **ACLs should be expressive enough for delegation.** If an AI agent is acting on behalf of the node owner, it needs enough granularity in the ACL and token system to make targeted, principled decisions — not just all-or-nothing access.

- **The protocol should not presuppose a particular UX.** There is no canonical client. The system should be equally well-suited to a traditional file browser, a photo gallery app, an AI-mediated news digest, or a command-line tool.

---

## Sharing as Conversation, Not Policy

The most useful mental model for how this system is intended to work is not a file server with an access control list, but **a person sharing personal information with a friend**.

When a person shares something with a friend, they are not consulting a policy document. They are making a judgment — shaped by the nature of the relationship, the context of the moment, what has been shared before, how that was received, and an intuition about what feels appropriate now. They might share something freely in one conversation and hold it back in another. They might revisit a decision to share something and wish they hadn't. They share at a human pace, in response to interest and context, not in bulk.

This is the model for how a node owner relates to their recipients. The ACL defines the outer boundary — who is in the relationship at all — but what is actually surfaced, and when, is more like an ongoing conversation than a static permission grant. It is governed by ephemeral, context-sensitive judgment rather than rigid rules. That judgment may be exercised directly by the owner, delegated to an AI agent acting on the owner's behalf, or some combination of both.

The protocol encodes the rigid structural parts — identities, assets, operations, credentials — because those need to be unambiguous. But the **subjective availability** of content: what the feed surfaces, how much is shared at once, how access evolves over time — should be understood as fluid, under constant reconsideration, and reflective of a living relationship rather than a fixed contract. Implementers should resist the temptation to treat the ACL as a complete specification of intent. It is a floor, not a ceiling, and the space above it is where the most interesting and human decisions happen.

---

## A Note on Accountability

The watermarking system exists precisely because content sharing mediated by fuzzy judgment — whether human or AI — is inherently imperfect. Access may be granted that in hindsight shouldn't have been; content may be shared further than intended. Watermarking ensures that the trail of accountability is embedded in the content itself, independent of whatever logic decided to share it.

This is the system's backstop: the protocol cannot fully anticipate every sharing decision, so it ensures that every delivery carries its own record.
