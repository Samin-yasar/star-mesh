# Star-Mesh Ratchet State Machine Specification

This document defines the formal state machine for the Star-Mesh Post-Quantum Double Ratchet, ensuring adherence to the security properties of Post-Quantum Forward Secrecy (PQ-FS) and Post-Compromise Security (PCS).

## 1. Ratchet State Struct
Each node maintains a `RatchetState` for every active session.

```rust
struct RatchetState {
    // Core Keys
    root_key: [u8; 32],             // Advanced by DH and PQ ratchets
    send_chain_key: [u8; 32],       // Symmetric ratchet for outgoing messages
    recv_chain_key: [u8; 32],       // Symmetric ratchet for incoming messages
    
    // Classical DH Keys
    dh_sk_local: x25519::SecretKey, // Current local DH secret
    dh_pk_remote: x25519::PublicKey,// Current remote DH public
    
    // Post-Quantum Keys
    pq_outstanding: map<KemId, OutstandingKem>, // One secret per in-flight update
    pq_completed: map<KemId, CompletedKem>,     // Responses waiting for ordered application
    pq_retired: set<KemId>,                     // Replay protection
    
    // Counters and Metadata
    n_s: u32,                       // Number of messages sent in current DH ratchet
    n_r: u32,                       // Number of messages received in current DH ratchet
    pn: u32,                        // Number of messages in previous DH ratchet
    pq_counter: u32,                // Messages since last PQ ratchet step
    
    // Skipped Key Cache (Out-of-order handling)
    // Map: (Remote_DH_PK, Sequence_Number) -> Message_Key
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}
```

## 2. Initialization from PQ-X3DH
Upon successful completion of the PQ-X3DH handshake, the state is initialized using the 64-byte `OKM` (Output Keying Material).

- **Root Key:** `state.root_key = OKM[0..32]`
- **Chain Keys:** 
  - If Initiator (Alice): `state.send_chain_key = OKM[32..64]`.
  - If Responder (Bob): `state.recv_chain_key = OKM[32..64]`.
  - The peer's initial receive chain is installed during authenticated session setup.
- **PQ Keys:** Initialized from the `PQ_OTPK` used in the handshake.

## 3. Symmetric-Key Chain Ratchet
Each time a message is sent or received, the corresponding chain key is ratcheted using BLAKE3.

1.  **Message Key Derivation:** $MK = \text{BLAKE3-KDF}(CK, \text{0x01}, \text{"StarMesh-MK"})$
2.  **Next Chain Key:** $CK_{next} = \text{BLAKE3-KDF}(CK, \text{0x02}, \text{"StarMesh-CK"})$
3.  **Erasure:** Immediately overwrite $CK$ with $CK_{next}$ and zeroize the old $CK$ from memory.

## 4. Post-Quantum (PQ) Ratchet Step
The PQ Ratchet ensures security recovery against $Adv_{Quant}$.

- **Trigger:** Triggered when `pq_counter >= 50` OR session time exceeds 24 hours.
- **Process:**
  1.  **Initiation:** Alice generates a fresh ML-KEM pair, allocates `kem_id`, and signs
      `session_id || kem_id || sequence || epoch || predecessor_transcript || pq_pk` with ML-DSA.
      The secret is stored under `kem_id`.
  2.  **Response:** Upon receiving `pq_pk_local`, Bob performs `Encaps(pq_pk_local)`, deriving `(ct, SS_PQ)`.
  3.  **Key Update:** Both parties update the `root_key` and both directional chain keys:
      $$ RK_{new},\; CK_{new} = \text{HKDF-SHA3-256}(SS_{PQ},\; salt = RK_{old},\; info = \text{"StarMesh-PQ-RK"},\; \ell = 96) $$
      The 96 bytes are root, initiator-to-responder chain, and responder-to-initiator chain.
  4.  **Replacement:** The KEM secret is consumed exactly once and the identifier is moved to
      `pq_retired`. A second response for the identifier is rejected.

## 5. Message Key Derivation and Header
The message header must provide enough info for the receiver to synchronize the state without leaking identity.

### Header Structure:
- `dh_pk`: Alice's current ephemeral X25519 public key.
- `n`: Message index in the current DH ratchet.
- `pn`: Number of messages in the previous DH ratchet.
- `pq_pk`: (Optional) New ephemeral ML-KEM public key (if Alice is initiating a PQ step).
- `pq_ct`: (Optional) ML-KEM ciphertext (if Alice is responding to Bob's PQ step).
- `kem_id`: Authenticated identifier for a PQ ratchet exchange; responses are matched by this
  identifier rather than arrival order.

### Final Encryption:
- **Ciphertext:** $C = \text{AES-256-GCM}(MK, \text{Plaintext}, \text{Header})$
- **Auth Tag:** Included in GCM.

## 6. Out-of-Order Message Handling
If a message arrives with a sequence number $N > state.n\_r$:

1.  **Key Calculation:** The receiver ratchets the `recv_chain_key` forward to $N$.
2.  **Caching:** All intermediate $MK$s derived during this process are stored in `state.skipped_keys` indexed by `(dh_pk_remote, seq_num)`.
3.  **Limits:** `skipped_keys` is capped at 1000 entries. If full, the oldest keys are shredded.
4.  **Retrieval:** If a delayed message arrives, the receiver checks `skipped_keys`, decrypts, and immediately deletes the cached key.

## 7. State Deletion Schedule (Security Critical)
To maintain the **Forward Secrecy** claims, the following deletion schedule is mandatory:

- **Message Keys ($MK$):** Deleted immediately after one-time use (encryption or decryption).
- **Chain Keys ($CK$):** Deleted as soon as the next chain key is derived.
- **Root Key ($RK$):** Deleted as soon as a DH or PQ ratchet updates it.
- **PQ Secret Keys ($PQ\_sk$):** One secret is stored per outstanding `kem_id` and consumed
  before decapsulation completes; it is then dropped and zeroized.
- **Skipped Keys:** Deleted after use OR after a 7-day TTL (Time-To-Live).
- **Session State:** If a session is closed or a node is "logged out," the entire `RatchetState` must be zeroized using the `zeroize` crate to prevent cold-boot attacks.

## 8. Implementation-to-theorem correspondence

| Theorem transition | Rust transition |
|---|---|
| authenticated send | `RatchetState::pq_ratchet_init` |
| authenticated delivery/encapsulation | `RatchetState::pq_ratchet_encapsulate` |
| exactly-once decapsulation | `RatchetState::pq_ratchet_decapsulate` |
| deterministic concurrent application | `RatchetState::drain_completed` |
| KEM secret erasure | `OutstandingKem.secret_key.take()` and `Drop` |
| root/chain deletion | `mix_pq_secret` replaces and zeroizes old keys |
| replay exclusion | `retired_kems` |

The executable correspondence is tested by
`test_concurrent_out_of_order_updates_and_bidirectional_chains` and
`test_recovery_header_authentication_is_verified`. It is not a mechanically verified
refinement proof.
