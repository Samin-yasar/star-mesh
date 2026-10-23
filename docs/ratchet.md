# Star-Mesh Ratchet State Machine Specification

> **Synced with spec.md / paper rev:** v0.1 (October 2026)
>
> **Source of truth**: Byte-level formats, domain labels, wire structures, and KDF inputs
> are canonically defined in [`spec.md`](../spec.md). State transitions and security proofs
> are derived from `paper/paper.tex`. If there is any discrepancy, [`spec.md`](../spec.md)
> and `paper.tex` win.

---

This document defines the formal state machine for the Star-Mesh Post-Quantum Double Ratchet,
ensuring adherence to Post-Quantum Forward Secrecy (PQ-FS) and Post-Compromise Security (PCS).

## 1. Ratchet State Struct

Each node maintains a `RatchetState` for every active session. In the Rust reference
implementation (`poc/rust/src/main.rs`), the state is defined as:

```rust
pub struct RatchetState {
    pub session_id: [u8; 32],
    pub is_initiator: bool,
    
    // Identity and Authentication Keys (ML-DSA-65)
    signing_key: SigningKey<MlDsa65>,
    trusted_identity: Option<VerifyingKey<MlDsa65>>,
    trusted_responder_identity: Option<VerifyingKey<MlDsa65>>,
    
    // Core Ratchet Keys
    pub root_key: [u8; 32],
    pub entropy_pool: [u8; 32],
    pub send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    
    // Transcript and Replay Protection
    transcript_hash: [u8; 32],
    valid_predecessors: HashSet<[u8; 32]>,
    
    // Post-Quantum Ratchet Buffers
    pub next_kem_sequence: u64,
    pub next_kem_to_apply: u64,
    outstanding_kems: HashMap<KemId, OutstandingKem>,
    completed_kems: HashMap<KemId, CompletedKem>,
    retired_kems: HashSet<KemId>,
    
    // Counters and Skipped Keys
    pub pq_step_counter: u32,
    pub skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}
```

---

## 2. Initialization from PQ-X3DH

Upon successful completion of the PQ-X3DH handshake, the state is initialized using the 64-byte `OKM`:

- **Root Key:** `state.root_key = OKM[0..32]`
- **Entropy Pool:** `state.entropy_pool = state.root_key` (identical initial value)
- **Transcript Hash:** `state.transcript_hash = BLAKE3("StarMesh-transcript-v1")`
- **Predecessors:** `state.valid_predecessors = { state.transcript_hash }`
- **Directional Chain Keys:**
  - If Initiator (Alice): `state.send_chain_key = Some(OKM[32..64])`, `state.recv_chain_key = None`.
  - If Responder (Bob): `state.recv_chain_key = Some(OKM[32..64])`, `state.send_chain_key = None`.
- **Identity Keys:** Local ML-DSA-65 signing key loaded; peer verifying keys set from authenticated handshake bundle and $M_0$ signature $\sigma_{M_0}$.

---

## 3. Symmetric-Key Chain Ratchet

Each time a message is sent or received, the corresponding chain key is ratcheted using BLAKE3:

1. **Message Key Derivation:**
   $$MK_i = \text{BLAKE3-KDF}(CK_i, \text{domain} = \text{0x01}, \text{info} = \text{"StarMesh-MK"})$$
2. **Next Chain Key Derivation:**
   $$CK_{i+1} = \text{BLAKE3-KDF}(CK_i, \text{domain} = \text{0x02}, \text{info} = \text{"StarMesh-CK"})$$
3. **Erasure:** Immediately overwrite and zeroize $CK_i$ with $CK_{i+1}$. $MK_i$ is zeroized immediately after one-time encryption or decryption.

---

## 4. Classical DH Ratchet Step

When an incoming message carries a new ephemeral X25519 public key:

1. Compute classical shared secret: $DH_{new} = \text{X25519}(local\_eph\_sk, remote\_eph\_pk)$.
2. Derive new root and send chain key:
   $$out = \text{HKDF-SHA3-256}(ikm = DH_{new}, salt = RK, info = \text{"StarMesh-RK"}, L = 64)$$
   $$RK_{new} = out[0..32], \quad CK_s = out[32..64]$$
3. Zeroize old $RK$ and ephemeral private keys.
4. Classical healing relies on Assumption 4.3 (DDH / PRF-ODH on X25519). Standard PRF security of HMAC-SHA3-256 applies because the salt is the secret $RK$.

---

## 5. Post-Quantum (PQ) Ratchet Step — PCS Recovery

Triggered when `pq_step_counter >= 50` messages or session age exceeds 24 hours.

1. **Initiation (Alice):**
   - Samples fresh ML-KEM-768 keypair `(EPH_PQ_pk, EPH_PQ_sk)`.
   - Derives `kem_id = BLAKE3("StarMesh-KEM-v1" || session_id || seq || EPH_PQ_pk)`.
   - Signs `m_init` payload with ML-DSA-65 ($\sigma_{\mathrm{init}}$).
   - Inserts secret key into `outstanding_kems` and transmits `RecoveryUpdateHeader`.

2. **Encapsulation (Bob):**
   - Verifies `σ_init` under Alice's `IK_DSA_pk` and checks `predecessor ∈ valid_predecessors`.
   - Computes `(ct, SS_PQ) ← ML-KEM-768.Encaps(EPH_PQ_pk)`.
   - Signs `m_resp` payload with ML-DSA-65 ($\sigma_{\mathrm{resp}}$), binding `EPH_PQ_pk` and `ct`.
   - Queues update in `completed_kems` and transmits `RecoveryUpdateResponse`.
   - Calls `drain_completed()`.

3. **Decapsulation (Alice):**
   - Verifies `σ_resp` under Bob's `trusted_responder_identity`.
   - Consumes and zeroizes `EPH_PQ_sk` via `Option::take()`.
   - Computes `SS_PQ ← ML-KEM-768.Decaps(EPH_PQ_sk, ct)`.
   - Queues update in `completed_kems` and calls `drain_completed()`.

4. **Ordered Application (Single Extract, Two Expands):**
   Updates are applied in strictly increasing sequence (`next_kem_to_apply`):

   $$PRK = \text{HKDF-Extract}(salt = SS_{PQ}, ikm = RK_{old} \mathbin{\|} EP_{old})$$
   $$EP_{new} = \text{HKDF-Expand}(PRK, \text{"StarMesh-v1-EntropyPool"} \mathbin{\|} kem\_id \mathbin{\|} ct, L = 32)$$
   $$out = \text{HKDF-Expand}(PRK, \text{"StarMesh-v1-PQ-RK"} \mathbin{\|} kem\_id \mathbin{\|} ct, L = 96)$$

   $$RK_{new} = out[0..32]$$

   **Directional Assignment:**
   | Role | `send_chain_key` | `recv_chain_key` |
   |---|---|---|
   | Initiator (Alice) | `out[32..64]` | `out[64..96]` |
   | Responder (Bob) | `out[64..96]` | `out[32..64]` |

   - Advances transcript: `transcript_hash' = BLAKE3(transcript_hash ‖ kem_id ‖ ct)`.
   - Adds `transcript_hash'` to `valid_predecessors`.
   - Moves `kem_id` to `retired_kems`.

---

## 6. Message Headers and Wire Formats

### 6.1 Conversational Message Header
- `dh_pk`: Current local ephemeral X25519 public key.
- `n`: Sequence number in current symmetric chain.
- `pn`: Previous chain length.

### 6.2 Handshake Message $M_0$ Wire Structure
```
M_0 = ( IK_DSA_pk_A, IK_DH_pk_A, EK_pk_A, ct_1, ct_2, prekey_id, tag_A, σ_{M_0} )
```
where $\sigma_{M_0}$ is Alice's ML-DSA-65 signature over `m_init` (§4.6 in `spec.md`).

### 6.3 Update Proposal Header (`RecoveryUpdateHeader`)
```
Header = ( session_id, kem_id, sequence, epoch, predecessor, EPH_PQ_pk, identity_pk, σ_init )
```

### 6.4 Update Response (`RecoveryUpdateResponse`)
```
Response = ( kem_id, EPH_PQ_pk, ct, responder_identity_pk, σ_resp )
```

---

## 7. Out-of-Order Message Handling & Skipped Keys

If an incoming message arrives with sequence number $N > n_r$:
1. Receiver ratchets `recv_chain_key` forward to $N$.
2. All skipped message keys $MK$ are stored in `skipped_keys` indexed by `(dh_pk_remote, seq_num)`.
3. `skipped_keys` is capped at 1000 entries; oldest keys are zeroized if capacity is reached.
4. When a delayed message arrives, receiver retrieves $MK$, decrypts, and **immediately zeroizes** the cached key.
5. All cached skipped keys are purged after a 7-day TTL.

> **Security Caveat (Corollary 5.5, Caveat 2):** Any message key cached in `skipped_keys`
> prior to state compromise at $t_{\mathrm{comp}}$ remains compromised even after a successful
> PQ healing round-trip. This is machine-checked in ProVerif (`attacker(w_skipped_pre) is true`).

---

## 8. State Deletion Schedule (Security Critical)

| Key Material | Erasure Timing |
|---|---|
| Message Keys ($MK$) | Immediately after one-time encryption or decryption |
| Chain Keys ($CK$) | Overwritten and zeroized as soon as next chain key is derived |
| Root Key ($RK$) | Overwritten and zeroized as soon as DH or PQ ratchet derives new root |
| Entropy Pool ($EP$) | Overwritten and zeroized as soon as PQ ratchet derives new pool |
| Ephemeral KEM Secrets ($EPH\_PQ\_sk$) | Consumed via `Option::take()` before decapsulation; zeroized immediately |
| One-Time Pre-Key Secrets ($PQ\_OTPK\_sk$) | Zeroized immediately after handshake decapsulation |
| Skipped Message Keys | Deleted upon retrieval OR after 7-day TTL |
| Session State | Entire `RatchetState` zeroized via `Drop` + `zeroize` upon session close |

---

## 9. Implementation-to-Theorem Correspondence

| Protocol Operation | Paper Reference | Rust PoC Implementation |
|---|---|---|
| Handshake Authentication | Claim 5.1 / §3.4 | Verified $\sigma_{M_0}$ via `m0_signature_bytes` |
| Authenticated PQ Update Send | Theorem 4.17 / §3.5.4 | `RatchetState::pq_ratchet_init` ($\sigma_{\mathrm{init}}$) |
| Authenticated PQ Encapsulation | Theorem 4.17 / §3.5.4 | `RatchetState::pq_ratchet_encapsulate` ($\sigma_{\mathrm{resp}}$) |
| Single-Use Decapsulation & Erasure | Theorem 4.17 / §3.5.4 | `OutstandingKem.secret_key.take()` in `pq_ratchet_decapsulate` |
| Deterministic In-Order Application | §3.5.4 / `kem-buffer.md` | `RatchetState::drain_completed` (sorted by sequence) |
| Root & Chain Key Derivation | §3.5.3 (Single extract, two expands) | `RatchetState::mix_pq_secret` ($salt=SS_{PQ}$, $L=96$) |
| Replay & Stale Update Exclusion | Freshness Cond. 5 / §4.5 | `retired_kems` set + predecessor validation |

Tested by `cargo test` in `poc/rust/src/main.rs`.
