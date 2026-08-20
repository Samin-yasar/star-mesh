# Concurrent KEM Buffer State Machine

The single `PQ^{loc}_{sk}` and single `PQ^{pending}_{ct}` fields are insufficient when multiple
PQ ratchet messages are in flight. A delayed ciphertext can otherwise be applied to the wrong
secret key, while a second initiation can overwrite the first keypair.

## State

Each session maintains:

```text
pq_send_seq: u64
pq_recv_seq: u64
pq_outstanding: map<kem_id, {local_sk, local_pk, sent_epoch, status}>
pq_incoming: map<kem_id, {ciphertext, peer_pk, received_epoch, status}>
pq_retired: bounded set<kem_id>
```

`kem_id = H("StarMesh-KEM-v1" || session_id || initiator_identity || pq_pk || seq)` is carried
in the authenticated message header. It is not inferred from arrival order.

## Transitions

1. **Initiate:** generate a fresh ML-KEM keypair, allocate `kem_id`, insert it into
   `pq_outstanding`, and transmit `pq_pk` with the authenticated header.
2. **Encapsulate:** on a valid unseen `kem_id`, encapsulate once against its `pq_pk`, insert the
   ciphertext in the peer's response record, and mark the incoming record `encapsulated`.
3. **Receive response:** look up `kem_id`, require the ciphertext and transcript binding to match,
   decapsulate exactly once, and derive the next root/entropy-pool state. Mark the record
   `completed`, zeroize its secret key, and add `kem_id` to `pq_retired`.
4. **Duplicate/replay:** a completed or retired `kem_id` is idempotently acknowledged or rejected;
   it never causes a second root-key update.
5. **Timeout:** an outstanding record may expire and be retired without changing the root key.
   Re-initiation uses a new sequence and keypair.
6. **Concurrent completion:** completed updates are applied in a deterministic order, such as
   increasing `kem_id` or authenticated send sequence. Each update consumes the current root key
   and produces a new epoch; replies for later IDs wait until all earlier selected updates have
   retired.

## Why the order rule matters

ML-KEM shared secrets are not a commutative merge operation. Applying two valid KEM updates in
opposite orders gives different root keys. Deterministic ordering prevents honest peers from
silently diverging when responses cross in the network. A bounded buffer must apply backpressure or
reject new initiations when capacity is exhausted; silently evicting an outstanding key would
invalidate the PCS recovery claim.

## Security conditions

The PCS theorem should target a message after every selected update has completed, not merely after
one response has arrived. The proof must account for buffer capacity, timeout/retry behavior,
replays, duplicate responses, state compromise while records are outstanding, and loss of a peer's
buffer state. The current ProVerif ratchet model has one hard-coded round-trip and does not verify
these concurrent transitions.
