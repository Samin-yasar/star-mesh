# Concurrent KEM Buffer State Machine

The single `PQ^{loc}_{sk}` and single `PQ^{pending}_{ct}` fields are insufficient when multiple
PQ ratchet messages are in flight. A delayed ciphertext can otherwise be applied to the wrong
secret key, while a second initiation can overwrite the first keypair.

## State

The Rust proof-of-concept implements this state in `RatchetState`:

```text
pq_send_seq: u64
pq_recv_seq: u64
pq_outstanding: map<kem_id, {local_sk, sent_epoch, status}>
pq_incoming: map<kem_id, {shared_secret, ciphertext, sequence}>
pq_retired: bounded set<kem_id>
```

`kem_id = H("StarMesh-KEM-v1" || session_id || pq_pk || seq)` is carried in the
ML-DSA-authenticated message header. It is not inferred from arrival order.

## Transitions

1. **Initiate:** `pq_ratchet_init` generates a fresh ML-KEM keypair, allocates `kem_id`, signs
   the recovery header, inserts the secret key into `pq_outstanding`, and transmits the header.
2. **Encapsulate:** `pq_ratchet_encapsulate` verifies the trusted ML-DSA identity and header
   bindings, encapsulates once, and stores the result in the completed buffer.
3. **Receive response:** `pq_ratchet_decapsulate` consumes the matching secret key exactly once
   and queues the result. Ordered draining derives the new root and both directional chains,
   then retires the identifier.
4. **Duplicate/replay:** a completed or retired `kem_id` is rejected and cannot update the root
   twice.
5. **Timeout:** an outstanding record may expire and be retired without changing the root key.
   Re-initiation uses a new sequence and keypair.
6. **Concurrent completion:** completed updates are applied in increasing authenticated
   sequence. Later responses remain buffered until earlier selected updates have retired.

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
