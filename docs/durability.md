# Durability and recovery

What loam promises when a machine loses power mid-operation, and what
it does with whatever it finds afterwards. Four contracts: which log
is authoritative, how an artefact reaches its name, what a composed
write leaves behind, and how many replicas must answer before a write
is acknowledged.

## Recovery authority

**Each public-surface module's own write-ahead log is authoritative
for that module's materialised state.** The metadata plane above it —
`raft_metadata_client`, and clustor behind it — is authoritative for
*acceptance*: which operations were admitted and in what order. It is
not a replayable history loam can rebuild state from.

That split is not a preference; it follows from what the plane keeps.
`raft_metadata_client` rotates its log once each boot's replay has
drained, because every record in it has committed downstream by then
and replaying it again would push the same decisions through Raft on
every subsequent boot. A record the plane has already delivered is
therefore not recoverable from the plane. If the module that received
it applied it and acknowledged it without logging it locally, the
operation is lost after a restart despite having been reported
successful.

Two rules follow, and every metadata module holds them:

- No in-memory mutation, durability claim, or success response may
  depend on an append whose outcome was not observed.
- A record arriving on the committed stream is subject to the same
  rule as one arriving on the request stream. Being committed upstream
  makes it *admitted*, not *durable here*.

### Appends span steps

A storage provider over a real device answers `E_AGAIN` for work it
has accepted but not finished. A module that treated that as failure
would convert ordinary device latency into operation refusal, so the
append is a state machine rather than a call: one record is staged,
driven across as many steps as the device needs, and only a completed
fence licenses the mutation and the acknowledgement. While a record is
staged the module consumes no further work, so nothing overtakes it
and nothing is acknowledged ahead of it.

The machine selects its tier from the provider's capability bitmap:
the pipelined asynchronous write plus fence-ticket tier where the
provider offers it, and checked synchronous write plus fsync
otherwise, with `E_AGAIN` retried across steps on either.

A hard failure — anything other than `E_AGAIN` — after frame bytes
have reached the log leaves a tail that no later record can be read
past. The filesystem contract has no truncate, so the module latches
the log as unusable and refuses every subsequent operation rather than
acknowledging writes over a log that can no longer carry a durability
claim.

## Publishing an artefact

Fencing a file's bytes does not publish the name that finds them. A
body written with `OPEN_CREATE` and fsynced has durable bytes
reachable by no durable name: after a power cut the file may be
absent, or present with its previous contents. Publication therefore
has its own step, and `body_store` selects a recipe from what the
storage provider advertises:

| Provider offers | Recipe | Interrupted publication leaves |
| --- | --- | --- |
| Atomic rename | write staging file → fence bytes → rename onto the content path | nothing under the content path; a staging file the next boot removes |
| Durable name fence only | write the content path → fence bytes → fence the name | a short file under the content path, detectable because the path is the hash of its contents |
| Neither | refused | nothing |

The third row is the point of the table. A backend with no durable
name publication cannot publish, and the acknowledgement of a body
write is a durability claim — so the write is refused rather than
acknowledged over bytes no durable name reaches. Which row a backend
falls in is read from what it advertises, not assumed from what it
is: bare-metal FAT32 and the host filesystem both offer the rename,
and a provider that offers only the name fence gets the in-place
recipe with content addressing carrying the detection.

Retirement is publication in reverse and gets the same treatment: an
unlink whose directory entry is still volatile can reappear after a
power cut, so the name is fenced where the provider can.

Two consequences worth stating on their own:

- **A body already present at its full length is never rewritten.**
  The path is the hash of the contents, so an artefact there at the
  right length already is the bytes being written. Rewriting it would
  destroy something durable and open a window that did not need to
  exist. Because the in-memory slot table is empty after a restart,
  this is the ordinary path for a retried write, not a rare one.
- **A streamed write publishes by renaming its own temporary.** The
  temporary already holds every declared byte and has been verified
  against the declared digest, so where atomic rename exists the
  commit is one operation and no partial artefact is ever observable.

At boot, `body_store` sweeps its root: a `.wip_` temporary whose
session is gone belongs to a stream that died before its commit, and a
`.pub_` staging file belongs to a publication interrupted before its
rename. Neither is reachable by any content path, so both are removed
and an interrupted write leaves the same state every time.

Mutable keyed blobs — volume extents and erasure-coded shards — take
the same recipe. Their contract is last-write-wins on a derived key,
which an atomic rename satisfies exactly: an overwrite is crash-visible
as the old extent or the new one, never as an absent or half-replaced
one. Where the provider offers no atomic replace, the old entry must
be removed before a shorter payload can be written over it, so the
extent is briefly absent — a property of that tier rather than of the
operation.

## Body names against the embedded profile's name length

A content-addressed artefact is named by its digest — 64 hex
characters — and its staging name is `.pub_` plus 16 more, 21. The
embedded profile's filesystem carries long names, so both forms are
representable and the rename recipe applies there unchanged. The
metadata plane never depended on this, because a WAL path is chosen by
its module (`PROPOSER.WAL`) rather than derived from content.

The published name is the constraint worth watching: at 64 characters
it sits exactly on the provider's long-name ceiling, which refuses a
longer name rather than clipping it. Nothing may be appended to a body
name — no extension, no suffix, no per-tier tag — and a wider digest
encoding would not fit. The staging name has room; the published one
has none.

## The composed write

`PUT_FILE` is three independently durable stages behind one request:
the body lands in the content-addressed store, an object descriptor
records its digest and size, and a namespace binding points a path at
that descriptor. The orchestration between them lives in the router's
memory and does not survive a restart.

**The contract is idempotent retry, unreachable intermediate state,
and conservative reclamation — not coordinator replay.** A crash
abandons the composed operation; the client retries it whole, and each
stage recognises the retry as the same write it already performed. No
intermediate state is reachable, because a path binds only at the last
stage: until it does, nothing names the descriptor and nothing names
the body. What the crash leaves behind is unreachable, and the
lifecycle sweeps collect it.

Three properties make retry work, and all three are load-bearing:

- The body's identity is its content, so re-writing it yields the same
  digest and the same artefact.
- The descriptor's identity is derived from that digest, so
  re-creating it at the same size is the same descriptor.
- A binding at the same revision to the same object is the same write
  arriving twice and succeeds without mutating. Refusing it would make
  a retried write indistinguishable from a genuine conflict — which is
  a different thing, and is still refused: the same revision naming a
  *different* object is a conflict.

### Fault matrix

Every crash point, and what a client and the store are left with.
"Retry" throughout means the client re-sends the same request with the
same revision.

| Crash point | Client saw | Durable state | Retry | Left behind |
| --- | --- | --- | --- | --- |
| Before the body write | nothing | nothing | succeeds | nothing |
| Mid body write | nothing | staging file, or a short artefact on a backend without atomic rename | succeeds; a full-length artefact is reused, a short one is rewritten | staging file, swept at boot |
| After the body, before the descriptor | nothing | body only | succeeds | orphan body, collected by the body sweep |
| After the descriptor, before the bind | nothing | body and descriptor, neither reachable | succeeds | orphan body and unbound descriptor, collected by the two sweeps |
| After the bind, before the reply | nothing | complete and reachable | succeeds — the identical bind is recognised | nothing |
| After the reply | success | complete and reachable | succeeds | nothing |
| Mid streamed write, before commit | per-chunk acknowledgements | temporary only | client re-opens the stream | temporary, swept at boot |
| After commit, before the descriptor | digest | body only | succeeds | orphan body |

No row needs a coordinator log. The matrix has no cell where the store
must remember an intention it did not durably record, because no cell
makes a partial composition reachable and no cell makes a retry
ambiguous. A coordinator log would let the store finish an abandoned
write without the client, which is a different guarantee — worth
having only if a client that never returns becomes a requirement. It
is not a guarantee loam makes.

## Reclaiming what a crash left

The lifecycle sweep alternates over two inventories: the body store's
content-addressed blobs, and the object index's descriptors. Both are
cursor-paged, so a pass costs a bounded step regardless of how much is
stored.

For each entry the sweep asks the namespace whether the entry's object
id is bound anywhere. Absence alone is not licence to delete: an
ordinary bind can commit between the answer and the deletion, and the
sweep would then delete something reachable. So the sweep takes a
namespace **reservation** on the object id *before* it asks, and holds
it until the deletions complete. While an id is reserved the namespace
refuses to admit a bind naming it, with a distinct transient refusal
the client retries — so absence stays proven all the way to the
deletion, including across the cursor-paged pages of the proof itself.

Reservations are never logged. A crash clears every one of them, which
is the correct restart state: an unfinished sweep leaves either the
descriptor, which a later pass collects, or a refused bind, which its
client re-issues.

Ordering is explicit. The descriptor is deleted before the body,
because the descriptor is the half a binding would reach. Neither
deletion can strand a reachable pointer — both happen only while the
id is unbound and reserved — so a crash between them leaves an orphan
body, which the body sweep collects on a later pass.

Two things are deliberately out of the sweep's reach. Keyed blobs are
their writers' to retire. And a descriptor whose object id is not
content-derived was minted by something other than a composed write;
its lifecycle belongs to whoever minted it, which is the same rule
keyed blobs follow.

The reservation fences every bind that passes through the namespace
module holding it. A deployment that admits binds through more than
one metadata front door needs the reservation to be a replicated
decision rather than local state; single-front-door deployments are
what the sweep supports.

## Synchronous replication

**Every selected replica must acknowledge a body write before the
write is acknowledged.** Desired replicas and required synchronous
replicas are one number, and that is the contract.

The alternative — separate desired, minimum-durable, and repair
targets — buys write availability when a selected target is slow or
gone. It costs a durable record of which bodies owe copies, and an
owner for finishing them. Loam's scrub converges the fleet by
comparing member inventories, which heals under-replication once the
fleet is whole again but is not a work list: nothing durably records
that a particular write was acknowledged short. Without that ledger, a
write acknowledged below its desired replica count has no owner for
the remainder and no way to tell a reader that it is reading something
less durable than it asked for. Adding the availability without the
ledger would be a weaker promise wearing the same words.

What the current contract gives in exchange:

- **Read-after-write is exact.** Every selected replica holds the body
  by the time the write is acknowledged, so a read routed to any of
  them finds it. There is no window where a reader must be steered
  away from a replica that has not caught up.
- **Failure is visible at the write.** A selected target that cannot
  take the body fails the write, rather than converting into
  background debt the operator learns about later. Reads keep their
  own fallback: a read walks the ranked targets, so losing a replica
  after the write costs latency rather than the object.
- **Placement changes do not invalidate acknowledged writes.** The
  fleet snapshot is broadcast as an epoch and the routers rank targets
  locally from it. A write is acknowledged against the epoch it was
  ranked under; a later epoch can rank a different set, and reads
  tolerate that because they walk the ranked targets and fall back.
  Scrub is what moves bodies onto the current fleet.

Revisit when a named deployment cannot meet its availability target
under this rule. The change is the ledger first — durable
under-replication records with an owner that retires them — and the
separated replica counts second. Not the other way round.
