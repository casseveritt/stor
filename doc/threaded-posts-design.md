# Posts as a Tree: Unifying Posts, Comments, and Edits

*This document captures an exploratory design discussion about replacing the current
posts-with-owned-comment-logs model with a single recursive primitive: immutable posts
that may reference an immutable parent. It is non-normative design intent, not a
protocol specification — a record of the reasoning so a future implementation effort
can pick it up without re-deriving it.*

---

## The core idea

There is no separate "comment" entity. There are only **posts**. A post may optionally
reference a **parent** post. A post with no parent is what we'd currently call a
top-level post; a post with a parent is what we'd currently call a comment or reply.
Both are the same primitive, stored, synced, rendered, and reacted-to the same way.

This collapses two storage models, two sync paths, two render paths, and two ACL
systems into one. It also resolves a problem that's awkward in any "comments belong to
the post owner" design: how do you comment on something you don't own? Here the answer
is trivial — a reply is just your own post, on your own node, that names someone else's
post as parent. This is the same move federated systems (ActivityPub/Mastodon) made
when they unified "toot" and "reply."

Children of a post look like unthreaded comments under it, filtered to whatever subset
is visible to the viewer. Users can navigate the resulting structure up (toward the
root) or down (into replies) as a tree.

---

## Visibility narrows monotonically

A post's audience (the set of people who may see it) can only be the same size or
smaller than its parent's. If a reply narrows the audience, only that narrower subset
can see the reply (and, transitively, anything that replies to *it* is bounded by that
narrower set). This gives a single, principled, recursively-checkable invariant for
visibility composition — no bespoke ACL-merging logic per feature.

The poster must themselves be visible to (a member of the audience of) the parent —
you can't reply to something you can't see — which is also what makes the narrowing
rule self-enforcing in practice: you can only construct an audience from people you
know to be in the parent's audience, because that's the only audience you can see.

---

## Visibility lists: immutable, content-addressed, ownerless

To make the narrowing invariant *verifiable* rather than merely *claimed*, visibility
lists themselves need to be:

- **Immutable** — a list never changes once created. "Narrowing an audience" for an
  ongoing conversation means minting a *new*, smaller list (and, naturally, a new post
  that uses it) — not mutating the old one. This is what makes the narrowing invariant
  checkable at all: if lists could change after the fact, "subset of parent's audience"
  would be a claim about a moving target.
- **Content-addressed** — a list's id is a pure function of its membership: the hash of
  the sorted set of member node_ids. Identical audiences, constructed independently or
  at different times, automatically collapse to the same id. This buys deduplication
  for free and turns "has this audience changed" into a non-question — it cannot have,
  by construction; only a different id can exist.
- **Ownerless** — no node is "the" authority for a list. You come to know a list's id
  one of two ways: you constructed it yourself (it need not even include your own
  node), or you encountered it referenced by a post that is visible to you (which by
  definition means you're a member, since visibility is gated by list membership).
  There is no directory, lookup service, or canonical server to stand up. Existence-
  knowledge and legitimate interest are perfectly aligned: you cannot learn of a list
  you have no legitimate path to, and there is nothing to enumerate or probe.

### Serving and replication

A peer asked for a list's membership should refuse unless the requester is themselves a
member of that list (checkable directly: the requester proves their identity via the
existing signature infrastructure, and the serving node checks whether that node_id
appears in the list it's being asked to disclose — no chicken-and-egg, since the server
already holds the data and is just deciding whether to release it).

This produces a pleasant emergent property: the set of nodes both willing and able to
serve a list is exactly its own membership — the people who legitimately need it are
exactly the people who have it (because encountering a visible post that names the list
is how you learn of it in the first place). The list ends up naturally replicated across
its own audience, with no special infrastructure: as long as any member is online, the
list resolves.

### Will the number of lists become unmanageable?

Probably not, and for a self-correcting reason: real usage tends to draw from a small,
stable set of standing audiences per person ("close friends," "family," "this group of
three," "everyone who follows me"), reused across many posts. Content-addressing means
identical audiences — however and whenever constructed — collapse to one id. The more
people reuse audiences (the normal case, because that's how social circles actually
work), the fewer distinct lists exist. The pathological case — a fresh bespoke audience
minted per post — is precisely the "narrowing" behavior this design bets is rare. Worth
instrumenting once live, but not expected to be a real problem.

---

## Supersession as the edit mechanism

Posts are immutable. "Editing" a post means minting a *new* post that **supersedes**
the old one — the same content-addressed, signed structure as everything else, just
with a pointer back to what it replaces.

### Why immutable parent references matter

Crucially, when post B replies to post A, B's parent reference names A — and continues
to name A even after A is superseded by A′. This is a deliberate and important choice:
it means a reply's context can never be pulled out from under it. In mutable systems, an
author can edit a post after the fact in a way that makes existing replies look
unhinged, sarcastic, or nonsensical, because the thing they were responding to no longer
exists in the form they saw it. Here, B is forever and verifiably a reply to *A as it
was* — a permanent anchor that survives any number of future edits to the public-facing
version.

This also opens a clean presentation possibility (a UI concern, but one the structure
needs to *allow*, which it does): show the latest version of a post by default, while
making it easy to see that it differs from the original and to A/B between them. Readers
get the up-to-date version; the historical thread remains coherent and inspectable.

A second consequence, essentially free: every post's edit history becomes a walkable
chain of immutable supersessions — version history without a bolted-on feature for it.

### Connection to cross-node staleness (TODO #9)

This also reframes the "client doesn't see edits made on another node" problem (logged
as TODO item 9). In a mutable-post world, "has this changed?" requires re-fetching and
diffing remote state. In an immutable, content-addressed world, it becomes "does a
supersession record exist for this content-address?" — a question with a stable,
cacheable-forever answer once posed, rather than a moving target to keep re-polling.
If this design direction is pursued, the staleness-detection mechanism and the
threading/visibility-verification mechanism are likely to be the same mechanism wearing
two hats — they should be designed together, not sequentially.

---

## Authenticity: signed posts and a public chain of key supersession

Every post must be signed by its author, and that signature must be verifiable
independent of whoever served the post to you. This isn't really an addition to the
design above so much as something it already implies: once posts are immutable,
content-addressed, and routinely fetched/cached/replicated by parties other than their
origin — which is exactly how visibility and threading work — "authenticity" can only
mean *self-contained, independently verifiable* authenticity. A signature that requires
contacting the origin node to validate would defeat the purpose of a content-addressed
system: you'd be back to trusting whoever handed you the bytes.

### This builds on infrastructure that already exists

The system already has the right two-level shape for this:

- An **identity key** — a stable, person-level key generated at setup, escrowed
  (encrypted under the owner's passphrase) at the registry, recoverable via the owner's
  auth provider plus passphrase, and never stored on the node itself.
- A **node key** — the operational signing key for one deployment, rotatable
  independently of the person-level identity (e.g. via re-delegation after a node
  rebuild or key loss).
- A **delegation certificate**, signed by the identity key, attesting "identity I
  delegates signing authority to node key N for node_id X."

That's already most of a key-supersession mechanism. What's missing is *durability*:
re-delegation currently overwrites the prior certificate in place. To get a publicly
visible chain, the system needs to retain every delegation certificate ever issued, in
order, each tagged with the window during which it was authoritative — so that a
verifier who encounters an old post, signed by a since-retired node key, can establish
"this key held legitimate delegated authority at the moment this post was made," for as
long as the post exists.

### Shape of the chain

Notice this is the third time the same structural idea has appeared in this document —
immutable, signed, content-addressed records that reference their predecessor (posts
referencing parents, visibility lists identified by their membership, and now keys
referencing the key they supersede). The natural design is a hash-linked **sigchain**:
each link says, in effect, "key K_n is superseded by key K_(n+1) as of time T, attested
by K_n and/or the identity key." This is tamper-evident by construction — altering any
link breaks the hash references of everything downstream of it, detectably, to anyone
holding even a partial copy.

Where it lives matters less than that it's append-only and broadly held. The registry is
a natural anchor (much as Certificate Transparency anchors certificate issuance into
public logs), but per the ownerless/replicated-by-the-interested pattern already
established for visibility lists, contacts who've verified a node's signatures could
also hold and cross-check copies — so no single party, including the registry, can
quietly rewrite history.

### Open questions this raises

- **Root of trust.** Node-key rotation is cleanly authorized by the identity key — and
  that mechanism already exists. But what authorizes *identity*-key rotation, if that
  key is ever compromised or unrecoverable? This is the unsolved-in-general problem at
  the root of every PKI-like system: eventually you reach a key that nothing else
  vouches for. The existing escrow-plus-auth-provider-recovery flow is the de facto
  answer today; whether that recovery event should *itself* produce a public,
  chain-recorded "identity key superseded, attested by [recovery mechanism]" entry —
  rather than remaining an invisible side-channel — deserves a deliberate decision
  rather than a default.
- **Validity windows and clock trust.** For "this signature was valid at the time" to
  mean anything, supersession events need trustworthy timestamps, and verifiers need a
  notion of "which key was authoritative when a given post was signed." Whether to trust
  local clocks, rely on witnessed/anchored timestamps, or accept some fuzziness is a
  scope decision — easy to over-engineer well past what a personal store actually needs.
- **What travels with a post.** For verification to be self-contained, a signed post
  likely needs to carry — or make trivially resolvable — the signing key's identifier, a
  timestamp, and enough of a pointer into the supersession chain for a verifier to
  confirm the key's authority window covered the signing time, without necessarily
  shipping the whole chain inline with every post.

---

## Deletion as tombstone-supersession

Because posts are immutable, an edit can't mean "erase and replace" — that would break
the permanence guarantee that makes threading trustworthy. Retraction therefore lives at
a different layer: **deletion**, modeled as supersession by a tombstone. This keeps
"everything is a post" true even for the one operation that looks like it should be
special-cased — a tombstone is just a post that supersedes another and carries no
content (perhaps with an optional author-supplied reason).

Children of a deleted post still exist; their parent reference still names the original,
immutable content-address, but that address now resolves to a tombstone. The chain is
visibly broken — readers can tell a reply's context was retracted, as distinct from a
reply that simply has no parent. (This is preferable to silently clearing the parent
reference and promoting the orphan to top-level status, which would erase useful context
about *why* the thread looks the way it does.)

Deletion is the only retraction mechanism this design offers. It is a heavy hammer, but
a necessary one — and, realistically, the only one that's coherent once immutability is
load-bearing for everything else.

### What "deletion" can and can't promise

One thing worth holding honestly, and communicating clearly to users: in any system
where immutable content can be cached or replicated by other parties — which this design
explicitly allows, since that's how visibility and threading work — "delete" can only
ever mean *"I stop serving this and ask others to do likewise,"* not *"this content is
now cryptographically guaranteed to not exist anywhere."* This is not a flaw specific to
this design; it's the universal shape of the problem (the same tension behind "right to
be forgotten" vs. immutable ledgers in any federated or content-addressed system).
Deletion should be specified and presented to users as **retraction with best-effort
propagation**, not erasure — so expectations match what the system can actually deliver.

---

## Open questions / follow-ups

- **Canonical encoding for list ids.** "Hash of sorted node_ids" needs a precise spec
  (encoding, separator, hash function) so independently-computed ids always match.
- **Storage lifetime of lists.** A list must remain resolvable for as long as any post
  referencing it exists. Since lists are immutable and ownerless, this is presumably
  just "as long as some member keeps a copy" — worth confirming this composes cleanly
  with backup/restore and the eventual node-departure story.
- **Tombstone shape.** What, if anything, does a tombstone carry — just "deleted," or an
  optional reason, timestamp, etc.? And does superseding-with-a-tombstone require the
  same signature/authorship checks as any other supersession (it should — only the
  original author should be able to retract their own post).
- **Reactions.** Not addressed here in depth — they were raised alongside edits in TODO
  #9 as another kind of "property change" the client needs to learn about. Whether
  reactions fit naturally into this same post-with-parent model (a "like" as a minimal
  post whose parent is the liked post) or remain a distinct lighter-weight mechanism is
  worth a separate look once the core tree model is validated.
- **Reply discovery / fan-out.** The hardest remaining protocol question: how does a
  post's owner learn that replies exist on other nodes, so a thread can be rendered
  completely rather than only from the replies the owner happens to have encountered?
  This is the same problem federated systems solve with inbox delivery / pingbacks, and
  it's still open here.
