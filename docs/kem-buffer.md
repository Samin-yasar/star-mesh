# Concurrent KEM Buffer State Machine

> **Synced with spec.md / paper rev:** v0.1 (October 2026)
>
> **Source of truth**: Byte-level formats, domain labels, and wire structures are canonically
> defined in [`spec.md`](../spec.md). Cryptographic security claims and proofs are in
> `paper/paper.tex`. If there is any discrepancy, [`spec.md`](../spec.md) and `paper.tex` win.

---

The single `PQ^{loc}_{sk}` and single `PQ^{pending}_{ct}` model assumed in naive double-ratchet
descriptions is insufficient in asynchronous, high-latency, or decentralized networks.
When multiple PQ ratchet messages are in flight, a delayed ciphertext can otherwise be applied
to the wrong secret key, while a second initiation would overwrite the first keypair.

## 1. State Representation

The Rust proof-of-concept implements this state in `RatchetState`:

```rust
pub struct RatchetState {
    pub session_id: [u8; 32],
    pub next_kem_sequence: u64,
    pub next_kem_to_apply: u64,
    outstanding_kems: HashMap<KemId, OutstandingKem>,
    completed_kems: HashMap<KemId, CompletedKem>,
    retired_kems: HashSet<KemId>,
    transcript_hash: [u8; 32],
    valid_predecessors: HashSet<[u8; 32]>,
    // ...
}
```

- `outstanding_kems`: Stores locally generated secret keys waiting for a peer's encapsulation reply.
- `completed_kems`: Buffers decapsulated or encapsulated shared secrets waiting for strictly sequential derivation.
- `retired_kems`: Replay-protection filter; prevents a retired or duplicate `kem_id` from ever triggering a state change.

### `kem_id` Derivation (§6.1 in `spec.md`)

```
kem_id = BLAKE3("StarMesh-KEM-v1" ‖ session_id ‖ seq_be64 ‖ EPH_PQ_pk)
```

The 32-byte `kem_id` is carried in the ML-DSA-authenticated message header; it is **never**
inferred from network arrival order.

---

## 2. Wire Formats and Authentication

To guarantee active post-compromise security (Theorem 4.17), both the proposal header and the
encapsulation response carry explicit ML-DSA-65 signatures under hardware-isolated identity keys.

### 2.1 Update Header (`RecoveryUpdateHeader`)

Initiator (Alice) constructs and signs:

```
m_init = "StarMesh-UpdateAuth-Init-v1"
         ‖ session_id                    ← 32 bytes
         ‖ kem_id                        ← 32 bytes
         ‖ seq_be64                      ← 8-byte big-endian
         ‖ epoch_be64                    ← 8-byte big-endian
         ‖ predecessor                   ← 32-byte transcript_hash
         ‖ EPH_PQ_pk                     ← 1184-byte ML-KEM-768 public key

σ_init = ML-DSA-65.Sign(IK_DSA_sk_A, m_init)
```

The transmitted header contains:
`(session_id, kem_id, sequence, epoch, predecessor, EPH_PQ_pk, identity_pk, σ_init)`.

### 2.2 Update Response (`RecoveryUpdateResponse`)

Responder (Bob) encapsulates into `EPH_PQ_pk`, binds `EPH_PQ_pk` into the response payload to
prevent key-substitution, and signs:

```
m_resp = "StarMesh-UpdateAuth-Resp-v1"
         ‖ session_id       ← 32 bytes
         ‖ kem_id           ← 32 bytes
         ‖ EPH_PQ_pk        ← 1184 bytes (explicitly bound)
         ‖ ct               ← 1088-byte ML-KEM ciphertext
         ‖ epoch_be64       ← 8-byte big-endian
         ‖ predecessor      ← 32-byte predecessor hash

σ_resp = ML-DSA-65.Sign(IK_DSA_sk_B, m_resp)
```

The transmitted response contains:
`(kem_id, EPH_PQ_pk, ct, responder_identity_pk, σ_resp)`.

---

## 3. State Machine Transitions

1. **Initiate (`pq_ratchet_init`):**
   - Check buffer capacity (`outstanding_kems.len() < KEM_BUFFER_CAPACITY`).
   - Sample fresh ML-KEM-768 keypair `(EPH_PQ_pk, EPH_PQ_sk)`.
   - Allocate `sequence = next_kem_sequence++`.
   - Derive `kem_id` and compute `σ_init`.
   - Insert `OutstandingKem { sequence, secret_key: Some(EPH_PQ_sk) }` into `outstanding_kems`.
   - Transmit `RecoveryUpdateHeader`.

2. **Encapsulate (`pq_ratchet_encapsulate`):**
   - Validate header: check `session_id`, verify `kem_id` construction, check that `predecessor` is in `valid_predecessors`, and verify `σ_init` under peer's `IK_DSA_pk`.
   - Encapsulate: `(ct, SS_PQ) ← ML-KEM-768.Encaps(EPH_PQ_pk)`.
   - Sign `σ_resp` over `m_resp`.
   - Insert into `completed_kems` keyed by `kem_id`.
   - Call `drain_completed()` to apply in strict sequence.
   - Transmit `RecoveryUpdateResponse`.

3. **Decapsulate (`pq_ratchet_decapsulate`):**
   - Retrieve record from `outstanding_kems` by `response.header`.
   - Verify `σ_resp` under Bob's `trusted_responder_identity`.
   - **Consume `EPH_PQ_sk` exactly once** via `Option::take()` and drop it.
   - Decapsulate: `SS_PQ ← ML-KEM-768.Decaps(EPH_PQ_sk, ct)`.
   - Insert into `completed_kems`.
   - Call `drain_completed()`.

4. **Ordered Application (`drain_completed`):**
   - Loop finding the entry in `completed_kems` whose `sequence == next_kem_to_apply`.
   - Call `mix_pq_secret`:
     ```
     PRK = HKDF-Extract(salt=SS_PQ, ikm=RK ‖ EP)
     EP' = HKDF-Expand(PRK, "StarMesh-v1-EntropyPool" ‖ kem_id ‖ ct, L=32)
     RK', CK_s, CK_r = HKDF-Expand(PRK, "StarMesh-v1-PQ-RK" ‖ kem_id ‖ ct, L=96)
     ```
   - Advance running transcript: `transcript_hash' = BLAKE3(transcript_hash ‖ kem_id ‖ ct)`.
   - Insert `transcript_hash'` into `valid_predecessors`.
   - Remove from `outstanding_kems`, insert `kem_id` into `retired_kems`, and increment `next_kem_to_apply`.

5. **Replay & Stale Proposal Exclusion:**
   - Any header or response with a `kem_id` in `completed_kems` or `retired_kems` is rejected with `CryptoError::DuplicateKemId`.
   - Headers referencing an unknown predecessor hash are rejected with `CryptoError::InvalidHeader`.

---

## 4. Why Deterministic Ordering Matters

ML-KEM shared secrets are not commutative. Applying two valid KEM updates in opposite orders
yields divergent root keys. Strict sequential draining using `next_kem_to_apply` ensures that
both endpoints compute identical root keys even if responses cross in the network or arrive
out of order.

A bounded buffer must apply backpressure or reject new initiations when capacity
(`KEM_BUFFER_CAPACITY = 32`) is reached. Silently evicting an in-flight key would invalidate
PCS recovery.

---

## 5. Asymmetric Exposure Window Analysis

The vulnerability window following a state compromise at $t_{\mathrm{comp}}$ is asymmetric:

- **Initiator (Alice):**
  Recovers full post-compromise confidentiality within $\approx 1$ RTT (as soon as Bob's signed response arrives and is decapsulated).
- **Responder (Bob):**
  Requires $\approx 1.5$ RTT. Because Bob cannot know whether his response was dropped or delayed in transit, Bob must continue sending on the old chain until an authentic message arrives encrypted under the new chain key (or an explicit handshake ACK is received).
  *Critical boundary:* If the initiator goes silent after proposing an update, the responder's exposure window is unbounded until the peer resumes communication.

---

## 6. Formal Verification Boundary

- **`formal/ratchet.pv`:** Machine-checks forward secrecy and PCS healing under a *passive network adversary during the recovery round-trip* (Corollary 5.5). It uses unsigned KEM operations matching standard passive-after-compromise models.
- **`paper/paper.tex` (Theorem 4.17):** Provides the concrete reduction against an *active post-compromise adversary*, proving that the mutual ML-DSA-65 signatures ($\sigma_{\mathrm{init}}$ and $\sigma_{\mathrm{resp}}$) prevent MITM key injection and stale-proposal replay.
