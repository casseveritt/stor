# contacc vs. the Fediverse: How Our Threaded-Posts Thinking Compares to ActivityPub

*This document captures an exploratory comparison between the threaded-posts design
direction described in [threaded-posts-design.md](threaded-posts-design.md) and the
ActivityPub/Mastodon model it deliberately echoes in places and diverges from in
others. It is non-normative — a record of where we consciously align with prior art,
where we depart from it, and why the departures feel like the right bet philosophically.
Useful for anyone wondering "haven't the Fediverse folks already solved this?" — the
short answer is: partly, and the parts they haven't are exactly where our design leans
hardest into verifiability over trust.*

---

## Where we're aligned

### Unifying "post" and "comment" into one primitive

This is the core structural move, and it's one we're consciously following rather than
inventing. ActivityPub made the same move when it collapsed Mastodon's "toot" and
"reply" into a single `Note` object distinguished only by an optional `inReplyTo`
field. There is no second-class "comment" entity in either model — a reply is just a
post that names another post as its parent. The threaded-posts design doc calls this
out directly: it's the same unification, for the same reason (a reply to something you
don't own is otherwise awkward to model).

### Tombstones for deletion

ActivityPub has a `Tombstone` object type: when something is deleted, federated
servers may replace it with a tombstone referencing the original ID, so a gap in a
thread is visible rather than silently erased. Our framing — "supersession by a
content-less post" — is closer in spirit than letter (we keep "everything is a post"
uniform rather than introducing a distinct object type), but the underlying idea is the
same one ActivityPub already settled on: retraction should leave a visible marker, not
a hole that quietly closes up.

---

## Where we diverge — and why it matters

### Audience model: addressing vs. verifiable membership

ActivityPub addresses messages to actor/collection URLs — `to`, `cc`, a `followers`
collection that lives on and is served by your home server. It's fundamentally a
*delivery-list* model: mutable, server-owned, optimized for "who do I send this to."
It was never designed to answer "can I prove this audience hasn't changed since I last
checked?"

Our visibility lists are immutable and content-addressed — a list's id *is* the hash of
its sorted membership. Identical audiences, however and whenever constructed, collapse
to the same id, and "has this audience changed" becomes structurally unanswerable in
the affirmative: only a *different* id can exist. Different problem, different solution
shape — ActivityPub optimizes for routing, we're optimizing for verifiability.

### Monotonic visibility narrowing

This one we don't think ActivityPub has at all. In Mastodon you can reply to a public
toot with a followers-only reply, or a direct message — there's no structural
relationship enforced between a reply's audience and its parent's; it's purely an
authoring choice with no cross-checking. We're proposing a recursively-checkable
invariant — a reply's audience can only be the same size or smaller than its parent's —
baked into the structure itself, not left as a UI convention or honor system.

### Editing and parent-reference permanence

Mastodon mutates posts in place when edited, with an edit-history view bolted on
top. A reply's `inReplyTo` points at a URI whose content can silently change underneath
it — there's no protocol-level guarantee that the thing you replied to still resembles
what you saw when you wrote your reply.

Our supersession model makes "editing" mint an entirely new immutable post — and,
crucially, a reply's parent reference *always* names the original, pre-edit version,
forever. This is a materially stronger context-preservation guarantee than the
Fediverse offers today: nobody can retroactively rewrite what you were responding to in
a way that makes your reply look unhinged, sarcastic, or out of context. The historical
shape of a conversation is permanent, even as the public-facing "latest version" of any
post in it can still evolve.

### Content addressing vs. location addressing

ActivityPub identity is fundamentally URI-based —
`https://instance.example/users/alice/statuses/12345` — which ties an object's identity
to *where it's hosted*. Our design leans toward content-addressing (hash-derived ids
for posts, lists, and eventually keys), which is closer to a git/IPFS model: an
object's identity is intrinsic to its bytes, so any peer can serve a verified copy
without anyone needing to trust *where* it came from. This is what makes the
"ownerless, self-replicating visibility list" idea coherent at all — there's no
canonical server to be the bottleneck or single point of failure.

### Sigchains for key supersession

This is largely new territory relative to ActivityPub/Mastodon, which has no standard
answer for "verify a signature made by a key that's since been rotated out." Key
rotation in ActivityPub amounts to "update your actor object's `publicKey` field" —
there's no public, append-only record of prior keys with attested validity windows.
Our hash-linked sigchain of delegation certificates is closer in spirit to Certificate
Transparency or a Keybase-style sigchain than to anything currently in the Fediverse's
toolset. It's the layer that makes "every post is signed and independently verifiable,
forever" actually mean something once keys inevitably rotate.

---

## Where we're stuck on the same open problem

**Reply discovery / fan-out** — how does a post's owner learn that replies exist
elsewhere, so a thread can be rendered completely rather than only from the replies the
owner happens to have stumbled across? ActivityPub solves this with inbox delivery and
`replies`-collection polling. The threaded-posts design doc flags this as our hardest
open question too, and honestly, whatever we land on will probably rhyme with inbox
delivery — just, true to form, likely signed and content-addressed like everything
else here rather than trusting the delivering server's word for it.

---

## The throughline

The *shape* of the core primitive — a post that may optionally reference a parent — is
an idea ActivityPub already proved out, and we're glad to stand on that. What's
different is where we place the trust boundary. Almost everything ActivityPub treats as
"a delivery and routing problem, solved by servers speaking HTTP to each other in good
faith" — audiences, identity, edit history, key rotation — we're trying to push down
into structurally verifiable, content-addressed, signed records that don't depend on
trusting whoever happens to be serving them to you at the moment.

That's the philosophical lean we like: not "trust the server that hands you this," but
"verify the thing itself, regardless of who handed it to you." It costs more in
protocol complexity up front. It buys a system where authenticity, context, and
audience are properties of the *content*, not promises made by infrastructure — which
feels like the right trade for something meant to outlast any particular server, host,
or moment in time.
