# D-MLS Design Note

This note scopes a decentralized group-messaging extension for Star-Mesh. It is a research
construction sketch, not an implementation of RFC 9420. The key design constraint is that an MLS
commit is not an ordinary CRDT value: it changes the epoch secret and authenticates a specific
prior tree. Therefore, arbitrary concurrent commits cannot be merged by taking the union of their
TreeKEM updates.

## Goals and boundary

D-MLS aims to provide:

- asynchronous publication and retrieval of group proposals through a Kademlia DHT,
- deterministic convergence on one authenticated group epoch despite concurrent proposals,
- MLS-style epoch secrets after a winning commit,
- explicit detection of forks and equivocation by DHT replicas.

D-MLS does not make a Kademlia DHT a consensus system. Availability, Sybil resistance, and the
ability to fetch a quorum of records remain deployment assumptions. A CRDT can provide eventual
reconciliation of signed objects; it cannot by itself provide Byzantine agreement or guarantee
that an adversary has not hidden a competing branch.

## Group record

A group is addressed by `gid = H(group_id || creator_identity)`. Replicas store an authenticated
operation set, not a mutable “current tree”:

```text
GroupOp = {
    gid,
    parent_epoch,
    parent_tree_hash,
    op_id = H(gid || parent_epoch || author || body || nonce),
    author,
    body,                 # RFC 9420 proposal or commit
    signature,
    received_at            # local metadata; never used for ordering
}
```

`author` must be an MLS credential already present in the parent epoch. The signature covers every
field except `received_at`. `parent_tree_hash` prevents a proposal from being replayed onto a
different tree, and `op_id` makes replication idempotent. Replicas merge by set union keyed by
`op_id`; this is the CRDT portion of D-MLS.

A DHT record should include the operation-set digest, a bounded operation range, and replica
signatures. Replica signatures attest to storage and observation, not to the cryptographic
validity of an MLS operation.

## Deterministic commit selection

For each `(gid, parent_epoch, parent_tree_hash)`, a client validates all fetched operations and
selects at most one commit using a deterministic total order:

```text
winner = min(valid_commit, (commit_hash, author_credential_hash))
```

The order is only a convergence rule. It is not a substitute for an MLS delivery service: a
client must wait for an application-defined observation window or quorum before treating the
winner as final. A later operation that wins under a different observed set is a fork, not a
merge, and must be retained as evidence rather than silently applied.

The winning commit creates epoch `parent_epoch + 1`. Its MLS confirmation tag and parent tree hash
must validate before the client derives the new epoch secret. Loser commits remain in the
operation set as rejected conflicts and cannot contribute secret material.

## Membership operations

Concurrent membership changes are intentionally serialized by the winner rule. In particular:

- concurrent Add proposals for different leaves may both be represented in the CRDT, but only a
  commit containing the selected parent state advances the epoch;
- concurrent Remove and Update operations for one leaf are not merged; the selected valid commit
  determines the leaf state;
- a proposal authored by a member removed in the winning epoch is invalid for later epochs;
- an old operation is rejected when its parent epoch or tree hash is stale.

This preserves MLS's state-machine invariant at the cost of losing some otherwise commutative
application operations. The protocol should expose rejected conflicts to the application and log
them for equivocation analysis.

## DHT and fork handling

Replicas publish operations under `H(gid || parent_epoch || parent_tree_hash)` and periodically
publish signed checkpoints:

```text
Checkpoint = {
    gid, epoch, tree_hash, op_set_digest,
    observed_frontier, replica_id, signature
}
```

A client that receives two valid checkpoints for the same `(gid, epoch)` with different
`tree_hash` values records an equivocation/fork event. It must not silently choose whichever
checkpoint arrived last. Recovery requires fetching the union of both frontiers and applying the
deterministic winner rule from their common parent, or explicitly resetting the group.

This makes fork detection possible, but not fork prevention under partition or eclipse. A Sybil
attacker can still delay an honest operation, and a client that cannot reach enough independent
replicas cannot know that its view is complete.

## Security claims to test

A future implementation and proof should test these separately:

1. **Convergence:** honest clients with the same validated operation set derive the same winner,
   tree hash, and epoch.
2. **No unauthenticated transition:** a client never advances an epoch from an invalid signature,
   stale parent tree, or invalid MLS confirmation tag.
3. **Fork evidence:** conflicting valid checkpoints are detectable and retained.
4. **Post-compromise recovery:** after an honest update/commit by a non-compromised member, the
   resulting MLS epoch secret is unavailable to an adversary that lacks the fresh update path.
5. **Availability limits:** the system states separately what fails under DHT eclipse, partition,
   replica equivocation, and permanent message loss.

The existing ProVerif models do not cover these properties. In particular, adding a CRDT set to a
symbolic model without modeling competing parents would verify convergence by assumption rather
than test the difficult part of D-MLS.
