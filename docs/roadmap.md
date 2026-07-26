# Star-Mesh (StarConnect) Development Roadmap

This document outlines the phased engineering roadmap for the Star-Mesh protocol, transitioning the cryptographic models from paper to a production-ready, cross-platform implementation.

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

### 2.1 Milestone: Self-Sovereign Identity (SSI) Module
- **Crate**: `star_mesh_identity`
- **Entropy Source**: Use `rand::rngs::OsRng` to generate 128-bit entropy. Map to BIP-39 mnemonic via the `tiny-bip39` crate.
- **SLIP-0010 Derivation**: Implement hierarchical derivation for Ed25519. *Critical*: Do not use secp256k1 paths. The derivation path must be `m/44'/784'/0'/0'/0'` (Star-Mesh coin type registered at 784' per SLIP-44).
- **Key Material Structure**:
  ```rust
  pub struct IdentityBundle {
      pub master_seed: [u8; 16],              // 128-bit entropy
      pub ik: ed25519_dalek::Keypair,         // $IK$ - Long-term signing
      pub spk: x25519_dalek::StaticSecret,    // $SPK$ - Medium-term handshake
      pub pq_pk: oqs::kem::PublicKey,         // $PQ-PK$ - ML-KEM-768
      pub pq_sk: oqs::kem::SecretKey,         // $PQ-SK$ - Stored encrypted-at-rest
  }
  ```
- **Persistence**: The `pq_sk` and `spk` must be encrypted using AES-256-GCM with a key derived from the master seed via Argon2id (memory=64MB, iterations=3, parallelism=4) before hitting the filesystem.
- **Deliverable**: `IdentityBundle` generation, serialization, and encrypted storage. Unit tests for BIP-39 round-trip and SLIP-0010 vector compliance.

### 2.2 Milestone: Hybrid PQ-X3DH Handshake
- **Crate**: `star_mesh_handshake`
- **Pre-Key Bundle Publishing**: A peer’s bundle is a signed structure containing:
  - `ik_pub` (Ed25519)
  - `spk_pub` (X25519)
  - `spk_sig` (Signature of `spk_pub` by `ik`)
  - `pq_pk` (ML-KEM-768 public key)
  - `otpk_pub` (Optional one-time X25519 pre-key, rotated every 24h)
- **Shared Secret Derivation (SS)**:
  ```rust
  pub fn derive_shared_secret(
      eph_x25519_sk: &x25519_dalek::EphemeralSecret,
      remote_spk: &x25519_dalek::PublicKey,
      remote_pq_pk: &oqs::kem::PublicKey,
      associated_data: &[u8],
  ) -> Result<[u8; 64], HandshakeError> {
      // 1. Classical ECDH
      let ecdh_shared = eph_x25519_sk.diffie_hellman(remote_spk).to_bytes();
      
      // 2. Post-Quantum KEM Encapsulation
      let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768)?;
      let (ct, pq_shared) = kem.encapsulate(remote_pq_pk)?;
      
      // 3. Concatenation & HKDF
      let mut concat = Vec::with_capacity(ecdh_shared.len() + pq_shared.len());
      concat.extend_from_slice(&ecdh_shared);
      concat.extend_from_slice(&pq_shared);
      
      // HKDF-SHA3-256 -> 512-bit output (split for sending chain / receiving chain)
      let okm = hkdf_sha3_256(&concat, associated_data, 64)?;
      Ok(okm)
  }
  ```
- **Associated Data (AD)**: Must bind the handshake to specific identities to prevent identity misbinding attacks:
  $$ AD = \text{"StarMesh-v1"} \parallel |IK_{pk}^A| \parallel IK_{pk}^A \parallel |IK_{pk}^B| \parallel IK_{pk}^B $$
- **Deliverable**: Functional Alice→Bob and Bob→Alice handshake with test vectors. Formal proof sketch of SS indistinguishability under $Adv_{Quant}$.

### 2.3 Milestone: Double Ratchet Engine
- **Crate**: `star_mesh_ratchet`
- **Root Chain**: Initialized with the first 32 bytes of SS.
- **Message Chain**: Standard Signal-protocol Double Ratchet with a critical modification:
  - **DH Ratchet**: Uses X25519 ephemeral keys.
  - **KEM Ratchet**: Every 50 messages (or 24 hours), trigger a "PQ Ratchet Step" where a new ML-KEM encapsulation is performed and mixed into the root chain via $HKDF(root\_key \parallel pq\_shared)$.
  - **Hash Chain**: Uses BLAKE3 for speed and length-extension resistance.
  - **Key Material Exposure Limit**: Each message key is derived as $mk_i = KDF(chain\_key\_i, 0x01)$ and immediately zeroized from memory after encryption/decryption using the `zeroize` crate.
- **Deliverable**: State machine implementation with serialization/deserialization. Test: Compromise `chain_key` at message $N$; verify message $N-1$ keys are irrecoverable.

---

## 3. Phase 2: Network Layer & Peer Discovery (Months 3–5)

### 3.1 Milestone: libp2p Stack Integration
- **Crate**: `star_mesh_network`
- **Transport Stack**: QUIC (over UDP) as the primary transport. Fallback to TCP/IP via DNS if QUIC is blocked. `libp2p_quic::Config::default()` with custom TLS certificate logic replaced by Star-Mesh identity keys.
- **Noise Framework Replacement**: Do not use libp2p's default Noise handshake. Instead, use the `star_mesh_handshake` crate as a custom `SecurityProtocol`. This requires implementing `libp2p::core::upgrade::InboundUpgrade` and `OutboundUpgrade`.
- **Peer ID Generation**: `PeerId` must be derived from `IK_pub` (Ed25519) to create a cryptographically bound identity: $PeerId = multihash(sha2\_256(IK\_pub))$.

### 3.2 Milestone: Kademlia DHT for Discovery & Routing
- **DHT Configuration**:
  - $k = 20$ (standard Kademlia bucket size).
  - $\alpha = 3$ (parallelism parameter).
  - **Replication factor**: Store each record on the $k$ closest nodes to the key.
- **Record Types**:
  - `PreKeyBundleRecord`: TTL = 7 days. Key = $SHA3\_256(IK\_pub)$.
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
| **ML-KEM** | `oqs` (liboqs bindings) | NIST standard evolving; side-channels. | Audit C bindings; use `pqcrypto` or native Rust `ml-kem` as fallback. |
| **Ed25519** | `ed25519-dalek` | Signature malleability issues. | Pin to v2.0+; verify signatures with zip215 rules. |
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
