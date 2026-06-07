# contacc Agent Architecture

*This document captures the dual-agent model for contacc: one biographer (me) and one aggregator (them) per user. It is non-normative design intent, not a protocol specification. It should inform protocol extensions and implementation decisions.*

---

## Overview

Each user's contacc deployment consists of two agents operating at a process boundary:

- A **me agent** (biographer) that manages what the user shares with others
- A **them agent** (aggregator) that manages what the user sees from others

Both are nominally AI-controlled. Both evolve their behavior through interaction with the user. They are deliberately separated: sharing between them is explicit and limited to what helps each make good, consistent decisions.

---

## Me Agent

The me agent is responsible for the sharing side of the user's relationships. Its core function is to manage the "space above the ACL floor" — the hard ACL defines who has access at all, but what is actually surfaced to each contact, and when, is governed by the me agent's judgment.

### Policy as Code, Judgment as AI

The me agent operates against a policy layer expressed in code: contact categories, baseline access rules, what normal behavior looks like for each relationship type. The AI layer operates above this: it monitors usage patterns, detects when behavior diverges from the expected envelope, proposes policy changes, and consults the user before acting on them.

### Natural Language Queries

Because the server has a real agent, it can do more than serve assets in response to feed queries. An authorized contact or their agent may ask a natural language question — "how was Cass's trip to Japan?" — and the me agent can synthesize a response drawing on available assets. This extends the "sharing as conversation" model: the server can respond the way a person might, not just as a file server.

Constraints on this capability:
- The agent draws only on assets the querying contact is authorized to see. The natural language interface does not widen access.
- Synthesized responses carry citations back to the source assets they drew from. Accountability is preserved even when the form of the answer is synthetic.
- The depth and character of the response is shaped by the relationship context — the me agent knows who is asking and calibrates accordingly.
- The owner can restrict which contacts may use this interface, and what kinds of questions the agent will engage with.

### What the Me Agent Knows (Me-Private)

- Raw access patterns per contact: frequency, depth, what was requested
- Whether contacts bump against access limits or exhibit anomalous behavior
- Who has attempted to access the node and been denied
- The full ACL and policy configuration

This data stays on the server. It informs what the server contributes to the shared contact layer, but it is not exposed to the them agent directly.

---

## Them Agent

The them agent is responsible for the consumption side of the user's relationships. It aggregates status across all connections and decides what to surface to the user, how, and when. Like the me agent, it adapts its behavior through interaction — what the user engages with, dismisses, or explicitly preferences shapes how it presents content over time.

### What the Them Agent Knows (Them-Private)

- What the user expresses interest in seeing more or less of
- How the user reacts to content from each contact
- Consumption patterns across the user's connections
- The user's current contextual and relational state as expressed through interaction

This data stays on the client. It informs what the client contributes to the shared contact layer, but is not exposed to the me agent directly.

---

## The Process Boundary

The server and client run in separate processes — potentially on separate hardware. They communicate through a defined interface, not shared state. The guiding principle for what crosses the boundary:

> Share what helps the agents make good, consistent decisions. Err on the side of limiting what is shared.

The key distinction is between **evidence** (raw behavioral data, which stays on the side that generated it) and **judgment** (synthesized signals about the relationship, which cross the boundary).

---

## The Shared Contact Layer

Each contact has a relationship document with three layers:

### Me-Private Annotations
Raw behavioral signals and policy context that inform what the server contributes to the shared core. Not exposed to the client.

### Shared Core
The settlement between what both agents know about the relationship. Both agents read from it and contribute to it. It carries:

- **Relationship characterization**: natural language context about who this person is, the texture of the relationship, relevant history
- **Trust and warmth level**: a synthesized signal reflecting how open or guarded the relationship is
- **Relationship trajectory**: whether the relationship is becoming more or less close
- **Sharing level** (contributed by server): how much the user currently surfaces to this contact — a synthesized signal, not raw ACL data
- **Consumption level** (contributed by client): how much the client is currently receiving from this contact's node
- **Expected symmetry**: whether this relationship is understood to be asymmetric by nature (a family member who shares a lot but receives less; a trusted elder; a one-way broadcast contact)

Natural language is the primary medium for relationship context. The goal is not a set of structured tags but a living characterization that both agents can reason from.

### Them-Private Annotations
Expressed preferences and consumption-side context that inform what the client contributes to the shared core. Not exposed to the server.

---

## Observed Symmetry

The default assumption for most relationships is rough symmetry: if a contact shares a lot with the user, it is natural for the user to share similarly back. If a contact shares nothing, they should expect less in return.

The them agent is the natural place to track this, because it is the only entity that sees both sides: what the user's server shares (via the sharing level signal in the shared contact layer) and what the client receives from the contact's node (observed directly).

Symmetry is a heuristic, not a rule. Some relationships are understood to be asymmetric, and the expected symmetry field in the shared contact layer captures this. The them agent uses observed symmetry as signal about the health and nature of each relationship — a useful indicator, not a constraint.

### The Feedback Loop

When the client detects a meaningful imbalance — particularly a contact who receives content but shares nothing in return — it can recommend a policy adjustment to the user's server. This is a distinct channel: the client talking to its own server, not to the contact's server.

The server can treat this as a proposal (surface to the user for confirmation) or act autonomously if the user has authorized standing delegation for this kind of adjustment.

The loop:
1. Server contributes sharing level to shared contact layer
2. Client observes consumption level from contact's node
3. Client agent assesses balance against expected symmetry
4. Client agent flags significant imbalances to user's server
5. Server adjusts sharing policy, updates shared contact layer

No cross-node communication is required for the default observed symmetry case.

---

## What This Means for the Protocol

The agent architecture has several implications for protocol design, even if the agent layer itself is not part of the protocol:

- **Contact metadata is a first-class shared data type** between client and server. The protocol (or a private channel between a user's own components) needs to support reading and writing the shared contact layer.
- **Natural language query is a new operation type**: a contact or their agent submits a question; the me agent returns a synthesized natural language response with citations to source assets. This extends the existing operation set without replacing it.
- **The client is a privileged contact of the server**: the user's own client needs a credential and role that grants it access to the sharing level signal and the ability to submit policy recommendations. This is distinct from the owner credential but similarly trusted.
- **ACL expressiveness must support delegation**: if the me agent acts on behalf of the owner, it needs enough granularity to make targeted decisions — not all-or-nothing access.
