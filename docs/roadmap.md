# Star-Mesh (StarConnect) Development Roadmap

> **Synced with spec.md / paper rev:** v0.1 (October 2026)
>
> **Source of truth**: Byte-level formats, domain labels, wire structures, and KDF inputs
> are canonically defined in [`spec.md`](../spec.md). Engineering phases implement the
> constructions analyzed in `paper/paper.tex`.

---

## 1. Executive Summary & Success Criteria
This plan decomposes the Star-Mesh protocol into six engineering phases, moving from cryptographic primitives to a cross-platform deployment. The north-star deliverable is a formally specified, memory-safe Rust core (WASM-targeted) that satisfies the adversary models $Adv_{Net}$ and $Adv_{Quant}$ defined in the abstract.

### Hard Success Criteria
- [ ] **Cryptographic Resilience**: 100% test coverage on SS derivation under $Adv_{Quant}$ (ML-KEM-768 + X25519 hybrid).
- [ ] **DHT Latency**: Kademlia DHT mailbox retrieval latency < 5s for $k=20$ nearest nodes under churn.
- [ ] **Forward Secrecy**: Verified via session key compromise simulation (keys at $t-1$ must be irrecoverable).
- [ ] **Metadata Obfuscation**: Validated against statistical traffic analysis (Chi-squared test on lookup patterns).

---

## 2. Phase 1: Cryptographic Core & Identity Layer (Months 1–3)

### 2.1 Milestone: Post-Quantum Identity Module
- **Crate**: `star_mesh_identity`
- **Identity Architecture**:
  - `IK_DSA`: Long-term ML-DSA-65 signing keypair (FIPS 204), hardware/enclave isolated.
  - `IK_DH`: Long-term X25519 classical static DH keypair (RFC 7748).
  - `SPK`: Medium-term X25519 signed pre-key.
  - `PQ_SPK`: Medium-term ML-KEM-768 static pre-key (FIPS 203).
- **Key Material Structure**:
  ```rust
  pub struct IdentityBundle {
      pub ik_dsa_sk: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
      pub ik_dsa_pk: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
      pub ik_dh_sk: x25519_dalek::StaticSecret,
      pub ik_dh_pk: x25519_dalek::PublicKey,
      pub spk: x25519_dalek::StaticSecret,
      pub pq_spk_sk: ml_kem::DecapsulationKey<ml_kem::MlKem768>,
      pub pq_spk_pk: ml_kem::EncapsulationKey<ml_kem::MlKem768>,
  }
  ```
- **Persistence**: Private key material must be protected via platform secure enclaves or encrypted using AES-256-GCM with keys derived from a master seed via Argon2id.
- **Deliverable**: `IdentityBundle` generation, serialization, and encrypted storage.

### 2.2 Milestone: Hybrid PQ-X3DH Handshake
- **Crate**: `star_mesh_handshake`
- **Pre-Key Bundle Publishing**: A peer’s bundle is published to DHT key `SHA3-256(IK_DSA_pk)`:
  ```
  Bundle = { IK_DSA_pk, IK_DH_pk, SPK_pk, PQ_SPK_pk, OTPK_pk[], PQ_OTPK_pk[], σ_bundle }
  ```
  where `σ_bundle = ML-DSA-65.Sign(IK_DSA_sk, BundlePayload)`.
- **Hybrid Secret Derivation**:
  1. Classical component: $SS_{cl} = DH_1 \parallel DH_2 \parallel DH_3 \parallel DH_4$ (4 X25519 outputs).
  2. Post-quantum component: $(ct_1, SS_{PQ1}) \gets \text{Encaps}(PQ\_SPK)$, $(ct_2, SS_{PQ2}) \gets \text{Encaps}(PQ\_OTPK)$.
  3. Hybrid concatenation: $SS_{hybrid} = 0\text{xFF} \parallel SS_{cl} \parallel SS_{PQ1} \parallel SS_{PQ2}$.
  4. HKDF-SHA3-256 derivation with bound identities and ciphertexts:
     $$OKM = \text{HKDF-SHA3-256}(ikm = SS_{hybrid}, salt = 0^{32}, info = info, L = 64)$$
     $$RK = OKM[0..32], \quad CK_s = OKM[32..64]$$
  5. Confirmation tags: $tag_A$ in $M_0$, $tag_B$ in responder reply.
  6. $M_0$ wire signature: $\sigma_{M_0} = \text{ML-DSA-65.Sign}(IK^{DSA}_{sk,A}, m_{\mathrm{init}})$.
- **Deliverable**: Functional initiator and responder handshake with test vectors.

### 2.3 Milestone: Double Ratchet Engine
- **Crate**: `star_mesh_ratchet`
- **Root Chain & Entropy Pool**: Initialized from handshake $OKM[0..32]$.
- **Symmetric Ratchet**: Per-message keys derived using BLAKE3-KDF:
  $$MK_i = \text{BLAKE3-KDF}(CK_i, \text{domain} = \text{0x01}, \text{"StarMesh-MK"})$$
  $$CK_{i+1} = \text{BLAKE3-KDF}(CK_i, \text{domain} = \text{0x02}, \text{"StarMesh-CK"})$$
  Immediate zeroization of $MK_i$ after one-time use; $CK_i$ replaced and zeroized.
- **Classical DH Ratchet**: Triggered by incoming ephemeral X25519 public key, updating $RK$ and $CK_s$ via HKDF-SHA3-256 (Assumption 4.3 DDH / PRF-ODH).
- **Post-Quantum Ratchet**: Triggered every 50 messages or 24h:
  - Initiator signs `RecoveryUpdateHeader` ($\sigma_{\mathrm{init}}$) under `IK_DSA_sk`.
  - Responder signs `RecoveryUpdateResponse` ($\sigma_{\mathrm{resp}}$) under `IK_DSA_sk`.
  - Derivation via single extract, two expands:
    $$PRK = \text{HKDF-Extract}(salt = SS_{PQ}, ikm = RK \parallel EP)$$
    $$EP' = \text{HKDF-Expand}(PRK, \text{"StarMesh-v1-EntropyPool"} \parallel kem\_id \parallel ct, L = 32)$$
    $$out = \text{HKDF-Expand}(PRK, \text{"StarMesh-v1-PQ-RK"} \parallel kem\_id \parallel ct, L = 96)$$
  - Directional chain key assignment: initiator receives send=`out[32..64]`, recv=`out[64..96]`; responder receives send=`out[64..96]`, recv=`out[32..64]`.
- **Deliverable**: Ratchet state machine with out-of-order KEM buffer.

---

## 3. Phase 2: Network Layer & Peer Discovery (Months 3–5)

### 3.1 Milestone: libp2p Stack Integration
- **Crate**: `star_mesh_network`
- **Transport Stack**: QUIC (over UDP) as primary transport. Fallback to TCP/IP via DNS.
- **Security Upgrade**: Use `star_mesh_handshake` as a custom `SecurityProtocol` implementing `libp2p::core::upgrade::InboundUpgrade` and `OutboundUpgrade`.
- **Peer ID Generation**: $PeerId = multihash(sha3\_256(IK\_DSA\_pk))$ cryptographically bound to the post-quantum identity.

### 3.2 Milestone: Kademlia DHT for Discovery & Routing
- **DHT Configuration**:
  - $k = 20$ (standard Kademlia bucket size).
  - $\alpha = 3$ (parallelism parameter).
  - **Replication factor**: Store each record on the $k$ closest nodes to the key.
- **Record Types**:
  - `PreKeyBundleRecord`: TTL = 7 days. Key = $SHA3\_256(IK\_DSA\_pk)$.
  - `MultiaddrRecord`: TTL = 1 hour. Contains QUIC/TCP endpoints.
  - `MailboxPointerRecord`: TTL = 24 hours. Points to encrypted message blobs.
- **Bootstrapping**: Hardcoded list of 5–10 "Genesis Nodes" (run by the project team). These are purely for initial peer discovery and cannot read message content.
- **Deliverable**: Functional DHT node that can publish and retrieve Pre-Key Bundles. Network simulation test with 100 nodes under 30% churn.

### 3.3 Milestone: NAT Traversal & Hole Punching
- **Auto-NAT**: Use libp2p's autonat protocol to determine if the node is publicly dialable.
- **DCUtR (Direct Connection Upgrade through Relay)**: For nodes behind symmetric NATs, use a relay node to coordinate hole punching. Relay only sees encrypted QUIC packets.
- **STUN-less Operation**: Explicitly avoid centralized STUN/TURN. If hole punching fails, messages fall back to the DHT Mailbox.

---

## 4. Phase 3: Asynchronous Persistence & The Mailbox (Months 5–7)

### 4.1 Milestone: Encrypted Message Blob Storage
- **Crate**: `star_mesh_mailbox`
- **Blob Structure**: An encrypted message blob stored on DHT nodes near $H(pk_B)$:
  ```rust
  struct MessageBlob {
      header: BlobHeader,         // Non-encrypted routing info
      ciphertext: Vec<u8>,        // AES-256-GCM encrypted payload
  }
  
  struct BlobHeader {
      recipient_hint: [u8; 32],   // H(pk_B) - routing hint
      ttl: u64,                   // Unix timestamp expiration
      padding: Vec<u8>,           // Randomized padding (1KB - 4KB) to obscure size
  }
  ```
- **Storage Logic**: When Alice sends to Bob, she calculates $target\_key = SHA3\_256(Bob\_IK\_pub)$ and performs a PUT to the DHT for $target\_key$.
- **TTL & Garbage Collection**: Default TTL = 72 hours. Nodes run background reaping tasks. Storage limit per node: 10GB FIFO eviction.

### 4.2 Milestone: Private Information Retrieval (PIR-Lite) Scan
- **The Problem**: Bob cannot query the DHT for "messages for me" without revealing his identity to the nodes he asks.
- **PIR-Lite Protocol**:
  - Bob maintains a local index of $target\_keys$ for his contacts.
  - Bob performs randomized GET lookups across the DHT for keys in his contact list, interleaved with dummy lookups for random keys.
  - **Rate Limiting**: Bob queries at a fixed rate (e.g., 1 query / 5 seconds) to create cover traffic.
  - **Bloom Filter Optimization**: Bob’s client locally builds a Bloom filter of recent $target\_keys$ to avoid redundant full-message fetches.
- **Deliverable**: Functional mailbox PUT/GET with PIR-lite scanning. Simulation test proving metadata resistance.

### 4.3 Milestone: Gossipsub Availability & Pull Triggers
- **Availability Announcement**: When Bob comes online, he publishes a signed `OnlineAnnouncement` to a Gossipsub topic `"/starmesh/online/v1/H(pk_B)[0:4]"`.
- **Pull Trigger**: Alice’s client, if it has pending messages for Bob, receives the gossip and initiates a direct P2P connection.

### 4.4 Milestone: D-MLS Group Messaging Research Track
- **Design note**: See `docs/d-mls-design.md` for the operation-set CRDT, deterministic commit
  selection, checkpoint format, and fork-handling rules.
- **Core invariant**: CRDT union reconciles signed proposals and commits, but MLS tree states
  are never merged directly; only one valid commit with the matching parent tree may advance an
  epoch.
- **Deliverable**: A bounded simulator with concurrent Add/Remove/Update commits, DHT partitions,
  replica equivocation, convergence checks, and fork-evidence checks.
- **Security gate**: Do not claim Byzantine consensus or MLS security until convergence,
  unauthenticated-transition rejection, fork detection, and post-compromise recovery are tested
  separately.

### 4.5 Milestone: UC Security Formulation
- **Specification**: See `docs/uc-formulation.md` for `F_SM`, corruption/recovery semantics,
  ratchet epochs, and the explicit mixnet leakage interface.
- **Deliverable**: Define the real and ideal protocol interfaces, a simulator, and a computational
  realization theorem quantified over sessions, epochs, corruptions, and transmissions.
- **Security gate**: The existing game proofs and ProVerif models are not UC proofs; do not claim
  composable security until environment/simulator indistinguishability is established.

---

## 5. Phase 4: Local Storage & Cross-Platform Interface (Months 7–9)

### 5.1 Milestone: Encrypted-at-Rest SQLite (SQLCipher)
- **Crate**: `star_mesh_storage`
- **Schema**:
  ```sql
  CREATE TABLE sessions (
      session_id BLOB PRIMARY KEY,  -- H(initiator_IK || responder_IK)
      root_key BLOB,                -- Encrypted
      sending_chain_key BLOB,       -- Encrypted
      receiving_chain_key BLOB,     -- Encrypted
      last_message_timestamp INTEGER
  );
  
  CREATE TABLE messages (
      message_id BLOB PRIMARY KEY,
      session_id BLOB,
      sequence_number INTEGER,
      ciphertext BLOB,
      direction INTEGER CHECK(direction IN (0,1)), -- 0=incoming, 1=outgoing
      timestamp INTEGER,
      status INTEGER CHECK(status IN (0,1,2,3)) -- pending, delivered, failed, synced
  );
  ```
- **Encryption**: SQLCipher with AES-256-CBC (page-level encryption). The encryption key is derived from the master seed via Argon2id.
- **Forward Secrecy for Storage**: Rotate SQLCipher key every 100 messages or 7 days; old keys shredded via `zeroize`.

### 5.2 Milestone: WASM Compilation & FFI Bridge
- **WASM Target**: Compile `star_mesh_core` to `wasm32-unknown-unknown`.
- **Bindings**: Use `wasm-bindgen` to expose:
  - `StarMeshNode::new(mnemonic: &str)`
  - `StarMeshNode::send_message(...)`
  - `StarMeshNode::poll_messages()`
- **Memory Safety in WASM**: Ensure Rust Box allocations are freed on the JS side. Use `wee_alloc` to minimize WASM binary size.

### 5.3 Milestone: Platform Adapters
- **React Native (Mobile)**: Use `react-native-wasm` or JSI modules. BG processing task to run Gossipsub/DHT polling every 15 minutes.
- **Tauri (Desktop)**: WASM core runs in WebView worker. Tauri commands handle DB operations.

---

## 6. Phase 5: Formal Security Analysis (Months 9–11)

### 6.1 Milestone: Adversary Model Validation
- **Methodology**:
  - **Forward Secrecy Proof**: Model the Double Ratchet as a sequence of KDF applications. Prove via game-hopping that compromising $chain\_key_i$ leaves $chain\_key_{i-1}$ indistinguishable from random.
  - **Post-Quantum Resistance**: Under $Adv_{Quant}$, X25519 is broken, but ML-KEM-768 guarantees safety by reduction to the Module-LWE problem.
  - **Metadata Obfuscation**: Formalize PIR-lite. Prove that DHT nodes learn only that "some peer queried some key."

### 6.2 Milestone: Penetration Testing & Fuzzing
- **Fuzzing Targets**: `derive_shared_secret` via AFL++, `MessageBlob` deserialization via `cargo fuzz`, DHT record parsing.
- **Side-Channel Resistance**: Use `dudect` to verify constant-time properties of the ML-KEM decapsulation wrapper.

### 6.3 Milestone: IACR Paper Draft
- Write LaTeX drafts, including sections: Introduction, Preliminaries, Protocol Specification, Security Model, Proofs, Implementation.

---

## 7. Phase 6: Optimization, Hardening & Release (Months 11–12)

### 7.1 Milestone: Performance Benchmarks
- **Handshake Latency**: < 150ms over local network.
- **Message Encryption**: > 10,000 ops/sec on a single core.
- **DHT Lookup**: < 2s for $k=20$ nearest nodes in a 10,000-node simulation.
- **Binary Size**: WASM core < 2MB (compressed).

### 7.2 Milestone: Hardening Checklist
- [ ] Remove all `unwrap()` and `expect()` from production code.
- [ ] Clean cargo audit passes.
- [ ] Miri tests for undefined behavior.
- [ ] Constant-time verification for all secret-key operations.
- [ ] Supply-chain security (pin dependencies, vendor oqs and dalek).

### 7.3 Milestone: Open Source & Community
- **Licenses**: Dual MIT / Apache-2.0.
- **Repositories**: `star-mesh-core` (Rust), `star-mesh-paper` (LaTeX), `star-mesh-apps` (Tauri & RN).

---

## 8. Dependency & Risk Matrix

| Component | Primary Crate / Tool | Risk | Mitigation |
| :--- | :--- | :--- | :--- |
| **ML-KEM-768** | `ml-kem` (FIPS 203) / `pqcrypto` | Constant-time side-channels. | Benchmark constant-time guarantees; continuous testing. |
| **ML-DSA-65** | `ml-dsa` (FIPS 204) | Enclave signing latency. | Hardware-enclave isolation; batch operations. |
| **Classical DH** | `x25519-dalek` (RFC 7748) | Implementation bugs / zero-point validation. | Use dalek v2.0+ with strict point validation. |
| **libp2p** | `libp2p` | Brittle custom security protocol. | Maintain fork for custom SecurityProtocol; upstream patches. |
| **SQLCipher** | `sqlcipher` | Mobile performance degradation. | Archive messages (move to encrypted blob after 90 days). |
| **WASM** | `wasm-bindgen` | JS/Rust boundary overhead; leaks. | Use ray-on for parallelization; strict drop tests. |

---

## 9. Engineering Team Structure

| Role | Count | Responsibility |
| :--- | :--- | :--- |
| **Cryptographic Engineer** | 1 | Core crypto modules (`identity`, `handshake`, `ratchet`). Formal proofs. |
| **Network Protocol Engineer** | 1 | libp2p integration, DHT logic, Gossipsub, NAT. |
| **Systems/Storage Engineer** | 1 | SQLCipher, WASM core, memory safety, FFI. |
| **Client Engineer** | 1 | React Native & Tauri UI wrapper, background tasks. |
| **Security Auditor / Writer** | 1 | Fuzzing, dudect, LaTeX paper draft, IACR reviews. |
