# Cryptographic Construction: Star-Mesh Protocol

> **Synced with spec.md / paper rev:** v0.1 (October 2026)
>
> **Source of truth**: Byte-level formats, domain labels, wire structures, and KDF inputs
> are canonically defined in [`spec.md`](../spec.md). All security formulas, theorems, and
> reduction proofs are derived from `paper/paper.tex`. If there is any discrepancy,
> [`spec.md`](../spec.md) and `paper.tex` win.

---

## 1. Cryptographic Primitives (§2.4)

| Role | Primitive | Standard | Output / Key Size |
|---|---|---|---|
| Identity Signatures | ML-DSA-65 (Dilithium3) | FIPS 204 | 3309 B signature, 1952 B public key |
| Key Encapsulation | ML-KEM-768 (Kyber768) | FIPS 203 | 1088 B ciphertext, 32 B shared secret |
| Classical DH | X25519 | RFC 7748 | 32 B public key, 32 B DH output |
| Key Derivation | **HKDF-SHA3-256** | RFC 5869 + FIPS 202 | Variable output |
| Symmetric Ratchet KDF | **BLAKE3-KDF** | — | 32 B message/chain keys |
| Transcript & KEM Hashing | BLAKE3 | — | 32 B digest |
| Payload AEAD | AES-256-GCM | NIST SP 800-38D | 128-bit tag |

> **Note on KDF instantiation:** Star-Mesh specifies **HKDF-SHA3-256** for all handshake and
> ratchet root-key derivation steps (§2.4, Assumption 4.2). The symmetric per-message ratchet
> uses **BLAKE3-KDF** due to its low per-message latency on constrained devices (§3.5.1).
> These are two separate, non-interchangeable instantiations — do not conflate them.

---

## 2. Key Generation and Identity (§3.2)

A node's **Identity Bundle** comprises:

1. `IK_DSA`: Long-term ML-DSA-65 signing keypair $(IK^{DSA}_{sk}, IK^{DSA}_{pk})$ (isolated in secure hardware/enclave).
2. `IK_DH`: Long-term X25519 static DH keypair $(IK^{DH}_{sk}, IK^{DH}_{pk})$.
3. `SPK`: Medium-term X25519 signed pre-key.
4. `PQ_SPK`: Medium-term ML-KEM-768 static pre-key.

### Pre-Key Bundle Publication (§3.3)

Each node publishes a signed bundle to the Kademlia DHT at lookup key `SHA3-256(IK_DSA_pk)`:

```
Bundle_A = { IK_DSA_pk_A, IK_DH_pk_A, SPK_pk_A, PQ_SPK_pk_A,
             OTPK_pk_A[], PQ_OTPK_pk_A[], σ_A }
```

where `σ_A = ML-DSA-65.Sign(IK_DSA_sk_A, BundlePayload_A)` and:

```
BundlePayload_A = "StarMesh-v1" ‖ len32(IK_DSA_pk_A) ‖ IK_DSA_pk_A
                              ‖ len32(IK_DH_pk_A)   ‖ IK_DH_pk_A
                              ‖ len32(SPK_pk_A)      ‖ SPK_pk_A
                              ‖ len32(PQ_SPK_pk_A)   ‖ PQ_SPK_pk_A
                              ‖ BLAKE3(all OTPK_pk_A concatenated)
                              ‖ BLAKE3(all PQ_OTPK_pk_A concatenated)
```

`len32(x)` is the 4-byte big-endian encoding of `len(x)`.

A bundle verifier must check:
1. `σ_A` is valid under `IK_DSA_pk_A`.
2. The DHT lookup key equals `SHA3-256(IK_DSA_pk_A)` from the signed payload.

- `OTPK_pk_A[]` — pool of classical one-time X25519 pre-keys.
- `PQ_OTPK_pk_A[]` — pool of one-time ML-KEM-768 pre-keys (critical for per-session PQ-FS).

---

## 3. Hybrid PQ-X3DH Handshake (§3.4)

Alice fetches and verifies Bob's bundle, then executes:

### Step 1 — Classical X3DH Component (4 DH values)

Alice generates fresh ephemeral keypair `EK_A` and computes:

```
DH_1 = X25519(IK_DH_sk_A, SPK_pk_B)
DH_2 = X25519(EK_sk_A,    IK_DH_pk_B)
DH_3 = X25519(EK_sk_A,    SPK_pk_B)
DH_4 = X25519(EK_sk_A,    OTPK_pk_B)   ← omitted if no OTPK available

SS_cl = DH_1 ‖ DH_2 ‖ DH_3 ‖ DH_4     (128 or 96 bytes)
```

### Step 2 — Post-Quantum KEM Component

```
(ct_1, SS_PQ1) ← ML-KEM-768.Encaps(PQ_SPK_pk_B)
(ct_2, SS_PQ2) ← ML-KEM-768.Encaps(PQ_OTPK_pk_B)   ← omitted if no PQ_OTPK
```

Bob immediately zeroizes `PQ_OTPK_sk_B` after decapsulation, cementing per-session PQ-FS.

### Step 3 — Cryptographic Binding and Key Derivation

**Associated Data** (binds both DSA identities; prevents UKS/misbinding attacks):

```
AD = "StarMesh-v1" ‖ len32(IK_DSA_pk_A) ‖ IK_DSA_pk_A
                   ‖ len32(IK_DSA_pk_B) ‖ IK_DSA_pk_B
```

**Transcript Binder** (satisfies IND-CCA2 precondition of Giacon et al. KEM combiner):

```
info = AD ‖ len32(EK_pk_A) ‖ EK_pk_A
          ‖ len32(ct_1) ‖ ct_1
          ‖ len32(ct_2) ‖ ct_2
```

**Hybrid IKM:**
```
SS_hybrid = 0xFF ‖ SS_cl ‖ SS_PQ1 ‖ SS_PQ2
```

> **Note on `0xFF`:** A fixed one-byte format marker. Unlike Signal's 32-byte $\mathbf{F}$ constant,
> it has no XEdDSA role and carries no cryptographic security weight, which is provided by `info`
> with the versioned `StarMesh-v1` label. It is not an attribution from Bindel et al.

**Output Keying Material (64 bytes via HKDF-SHA3-256):**

```
OKM = HKDF-SHA3-256(ikm=SS_hybrid, salt=0^32, info=info, L=64)
```

- `OKM[0:32]` → Initial Root Key `RK`
- `OKM[32:64]` → Initial Chain Key `CK_s` (Alice's send chain key; Bob's receive chain key `CK_r`)

`session_id = BLAKE3(OKM)` (32 bytes).

### Step 4 — Explicit Confirmation Tags

Alice derives confirmation key and generates one-sided confirmation tag:

```
confirm_info = "StarMesh-Confirm" ‖ info
K_conf = HKDF-SHA3-256(ikm=OKM, salt=0^32, info=confirm_info, L=32)
tag_A  = HMAC-SHA3-256(K_conf, info)
```

Bob verifies `tag_A`, then returns:

```
tag_B = HMAC-SHA3-256(K_conf, "Bob" ‖ info)
```

Alice verifies `tag_B` before treating the session as mutually confirmed. `tag_A` alone provides
one-sided explicit authentication; mutual confirmation requires the complete round-trip.

### Handshake Message $M_0$ and Initiator Signature

Alice transmits:

```
M_0 = ( IK_DSA_pk_A, IK_DH_pk_A, EK_pk_A, ct_1, ct_2, prekey_id, tag_A, σ_{M_0} )
```

where `σ_{M_0} = ML-DSA-65.Sign(IK_DSA_sk_A, m_init)` over:

```
m_init = "StarMesh-Handshake-M0-Init-v1"
         ‖ len32(IK_DSA_pk_A) ‖ IK_DSA_pk_A
         ‖ IK_DH_pk_A
         ‖ len32(IK_DSA_pk_B) ‖ IK_DSA_pk_B
         ‖ EK_pk_A
         ‖ len32(ct_1) ‖ ct_1
         ‖ len32(ct_2) ‖ ct_2
         ‖ len32(prekey_id) ‖ prekey_id
         ‖ tag_A
```

This cryptographically binds `IK_DH_pk_A` and all ephemeral material to Alice's long-term
identity, preventing DH-key substitution attacks and guaranteeing PQ initiator authentication.

---

## 4. Ephemeral PQ Double Ratchet (§3.5)

### 4.1 Symmetric Ratchet (§3.5.1)

Per-message keys are derived via BLAKE3-KDF with domain separation bytes:

```
MK_i    = BLAKE3-KDF(CK_i, domain=0x01, info="StarMesh-MK")
CK_i+1  = BLAKE3-KDF(CK_i, domain=0x02, info="StarMesh-CK")
```

`MK_i` is used once for AES-256-GCM encryption/decryption, then **immediately zeroized**.
`CK_i` is overwritten with `CK_i+1` and zeroized.

### 4.2 Classical DH Ratchet (§3.5.2)

When an incoming message contains a new ephemeral X25519 public key `DH_pk`:

```
DH_new   = X25519(local_eph_sk, remote_eph_pk)
out      = HKDF-SHA3-256(ikm=DH_new, salt=RK, info="StarMesh-RK", L=64)
RK       = out[0:32]
CK_s     = out[32:64]
```

Under Assumption 4.3, X25519 is computationally secure under DDH / PRF-ODH against classical
adversaries (not plain CDH). Because the salt is the current secret `RK`, standard PRF security
of HMAC-SHA3-256 applies directly.

### 4.3 Post-Quantum Ratchet — PCS Recovery (§3.5.3, §3.5.4)

Triggered every $\Delta = 50$ messages or after 24 hours of session inactivity.

1. **Initiator (Alice):** Generates fresh ephemeral ML-KEM keypair `(EPH_PQ_pk, EPH_PQ_sk)`,
   derives `kem_id`, and signs `RecoveryUpdateHeader` ($\sigma_{\mathrm{init}}$) under `IK_DSA_sk_A`.
2. **Responder (Bob):** Verifies `σ_init` under Alice's identity, encapsulates:
   `(ct, SS_PQ) ← ML-KEM-768.Encaps(EPH_PQ_pk)`, signs `RecoveryUpdateResponse` ($\sigma_{\mathrm{resp}}$)
   under `IK_DSA_sk_B`, and transmits the response.
3. **Decapsulation:** Alice verifies `σ_resp` under Bob's identity, decapsulates using `EPH_PQ_sk`
   (which is **immediately consumed via `Option::take()` and zeroized**).
4. **Key Derivation (Single Extract, Two Expands):**
   Both parties execute:

```
PRK  = HKDF-Extract(salt=SS_PQ, ikm=RK ‖ EP)
EP'  = HKDF-Expand(PRK, "StarMesh-v1-EntropyPool" ‖ kem_id ‖ ct, L=32)
out  = HKDF-Expand(PRK, "StarMesh-v1-PQ-RK"       ‖ kem_id ‖ ct, L=96)

RK'    = out[0:32]
CK_i2r = out[32:64]    # Initiator-to-responder chain key
CK_r2i = out[64:96]    # Responder-to-initiator chain key
```

**Directional Chain Assignment:**
- **Initiator (Alice):** `send_chain_key = out[32:64]`, `recv_chain_key = out[64:96]`
- **Responder (Bob):** `send_chain_key = out[64:96]`, `recv_chain_key = out[32:64]`

Because `salt = SS_PQ` is a uniform 32-byte secret under ML-KEM-768 IND-CCA2, pseudorandomness
of the PRK follows from plain PRF security of HMAC-SHA3-256 without dual-PRF or extractor
assumptions. Furthermore, past root entropy ($RK \parallel EP$) is preserved across the update.

---

## 5. Security Properties (§4, §5)

### Provable Properties

| Property | Mechanism | Paper Reference |
|---|---|---|
| Handshake PQ-FS | `PQ_OTPK_sk` zeroized after single decapsulation | §3.4, §5.2 (Claim 5.2) |
| Active Post-Compromise Security | Mutual ML-DSA-65 update signatures ($\sigma_{\mathrm{init}}, \sigma_{\mathrm{resp}}$) + ephemeral ML-KEM-768 | §3.5.4, §4.5 (Theorem 4.17) |
| Passive Post-Compromise Security | Ephemeral ML-KEM-768 round-trip (machine-checked in ProVerif) | §4.4, §5.3 (Corollary 5.5) |
| Identity Binding / MITM Resistance | ML-DSA-65 bundle signatures + $M_0$ signature $\sigma_{M_0}$ | §3.4, §4.3, §5.1 (Claim 5.1) |
| Transcript Binding | Ephemeral public keys and ciphertexts bound into HKDF `info` | §3.4 |
| Forward Secrecy under State Reveal | Immediate zeroization of message keys and chain keys | §3.5.1, §4.3 |

### Cryptographic Assumptions (§4.1)

- **Assumption 4.1** — ML-KEM-768 is IND-CCA2 secure (Module-LWE hardness).
- **Assumption 4.2** — HKDF-SHA3-256 is PRF-secure (used in all game hops).
- **Assumption 4.3** — X25519 satisfies DDH / PRF-ODH against classical adversaries.
- **Assumption 4.4 / 4.11** — ML-DSA-65 is EUF-CMA secure (Module-LWE / Module-SIS hardness).
- **Assumption 4.5** — BLAKE3 is PRF-secure with domain separation.
- **Assumption 4.6 / Claim 5.1** — BLAKE3 and SHA3-256 are collision-resistant.

---

## 6. Implementation Status & Known Scope Gaps

| Feature | Rust PoC (`poc/rust/`) | Python PoC (`poc/python/`) | Production Target |
|---|---|---|---|
| **ML-DSA-65 Signatures** | **Real** (`ml-dsa` crate, FIPS 204 verified) | Stub (HMAC over key) | Hardware-isolated enclave |
| **ML-KEM-768 KEM** | **Real** (`ml-kem` crate, FIPS 203 verified) | Logic stub (random bytes) | Constant-time native FIPS 203 |
| **Classical X25519** | **Real** (`x25519-dalek`) | MODP-1024 stub | Constant-time RFC 7748 |
| **HKDF Hash** | **Real** (SHA3-256 via `sha3` crate) | SHA-256 (stdlib mismatch) | Hardware-accelerated Keccak |
| **Symmetric Ratchet** | **Real** (BLAKE3 via `blake3` crate) | SHA-256 stub (mismatch) | Vectorized BLAKE3 |
| **Handshake $M_0$ Auth** | **Real** (verifies $\sigma_{M_0}$) | Stub | Strict envelope parsing |
| **Ratchet Update Auth** | **Real** (verifies $\sigma_{\mathrm{init}}$ and $\sigma_{\mathrm{resp}}$) | Stub | Out-of-order KEM buffer |
| **AEAD Payload Encryption** | Evaluates keys directly (out-of-band GCM) | Evaluates keys directly | In-band AES-256-GCM |
| **Network Transport** | In-process simulation | In-process simulation | libp2p + Sphinx/Loopix mixnet |
| **DHT Distribution** | In-process map | In-process map | Kademlia DHT with batch validation |
| **OTPK Replenishment** | Fixed single bundle | Fixed single bundle | Proactive batch threshold replenishment |
