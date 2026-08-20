# Cryptographic Construction: Star-Mesh Protocol

> **Source of truth**: All formulas and claims in this document are derived directly from
> `paper/paper.tex`. Section references (§) map to that document's numbered sections.
> If there is any discrepancy between this file and `paper.tex`, the `.tex` wins.

---

## 1. Cryptographic Primitives (§2.4)

| Role | Primitive | Standard |
|---|---|---|
| Identity Signatures | ML-DSA-65 (Dilithium3) | FIPS 204 |
| Key Encapsulation | ML-KEM-768 (Kyber768) | FIPS 203 |
| Classical DH | X25519 | RFC 7748 |
| Key Derivation | **HKDF-SHA3-256** | RFC 5869 |
| Symmetric Ratchet KDF | BLAKE3-KDF | — |
| AEAD | AES-256-GCM | NIST |

> **Note on KDF instantiation:** The paper specifies **HKDF-SHA3-256** for all key derivation
> steps (§2.4, Assumption 4.2). The symmetric ratchet uses **BLAKE3** due to its lower
> per-message latency on constrained devices (§3.5.1). These are two separate, non-interchangeable
> instantiations — do not conflate them.

---

## 2. Key Generation and Identity (§3.2)

A node's **Identity Bundle** comprises:

1. `IK_DSA`: Long-term ML-DSA-65 signing keypair.
2. `IK_DH`: Long-term X25519 DH keypair.
3. `SPK`: Medium-term X25519 static pre-key.
4. `PQ_SPK`: Medium-term ML-KEM-768 static pre-key.

### Pre-Key Bundle Publication (§3.3)

Each node publishes a signed bundle to the Kademlia DHT:

```
Bundle_A = { IK_DSA_pk_A, IK_DH_pk_A, SPK_pk_A, PQ_SPK_pk_A,
             OTPK_pk_A, PQ_OTPK_pk_A, σ_A }
```

where `σ_A = ML-DSA-65.Sign(IK_DSA_sk_A, BundlePayload_A)` and
`BundlePayload_A` includes the protocol label, `IK_DSA_pk_A`, `IK_DH_pk_A`, and every
published pre-key (with batch hashes for OTPKs). A fetcher must also verify that the DHT
lookup key equals `SHA3_256(IK_DSA_pk_A)` from the signed bundle.

- `OTPK_pk_A` — batch of one-time X25519 pre-keys.
- `PQ_OTPK_pk_A` — batch of one-time ML-KEM-768 pre-keys (critical for per-session PQ-FS).

---

## 3. Hybrid PQ-X3DH Handshake (§3.4)

Alice verifies `σ_B` over Bob's bundle, then executes:

### Step 1 — Classical X3DH Component (4 DH values)

Alice generates a fresh ephemeral keypair `EK_A` and computes:

```
DH_1 = DH(IK_DH_sk_A,  SPK_pk_B)
DH_2 = DH(EK_sk_A,     IK_DH_pk_B)
DH_3 = DH(EK_sk_A,     SPK_pk_B)
DH_4 = DH(EK_sk_A,     OTPK_pk_B)   ← omitted if no OTPK available

SS_cl = DH_1 ‖ DH_2 ‖ DH_3 ‖ DH_4
```

### Step 2 — Post-Quantum KEM Component

```
(ct_1, SS_PQ1) ← ML-KEM-768.Encaps(PQ_SPK_pk_B)
(ct_2, SS_PQ2) ← ML-KEM-768.Encaps(PQ_OTPK_pk_B)
```

### Step 3 — Cryptographic Binding and Key Derivation

**Associated Data** (binds both DSA identities; prevents UKS/misbinding attacks):

```
AD = "StarMesh" ‖ len32(IK_DSA_pk_A) ‖ IK_DSA_pk_A
               ‖ len32(IK_DSA_pk_B) ‖ IK_DSA_pk_B
```

**Transcript binder** (satisfies IND-CCA2 precondition of Giacon et al. KEM combiner):

```
info = AD ‖ len32(EK_pk_A) ‖ EK_pk_A
          ‖ len32(ct_1) ‖ ct_1
          ‖ len32(ct_2) ‖ ct_2
```

**Hybrid IKM** with `0xFF` domain-separation prefix (Bindel et al. 2018):

```
SS_hybrid = 0xFF ‖ SS_cl ‖ SS_PQ1 ‖ SS_PQ2
```

**Output Keying Material** (64 bytes, using HKDF-SHA3-256):

```
OKM = HKDF-SHA3-256(ikm=SS_hybrid, salt=0^32, info=info, L=64)
```

- `OKM[0:32]` → Root Key `RK`
- `OKM[32:64]` → Sending Chain Key `CK_s`

Alice derives `K_conf = HKDF(OKM, 0^32, "StarMesh-Confirm" || info, 32)` and includes
`tag_A = HMAC-SHA3-256(K_conf, M0_core)` in `M_0`. Bob verifies `tag_A`, then returns
`tag_B = HMAC-SHA3-256(K_conf, "Bob" || M0_core)`. Alice verifies `tag_B` before treating the
session as mutually confirmed. The tag in `M_0` alone is one-sided explicit confirmation, not
mutual authentication.

Bob immediately zeroizes `PQ_OTPK_sk_B` after decapsulation, cementing per-session PQ-FS.

**Handshake message Alice transmits:**

```
M_0 = (IK_DSA_pk_A, IK_DH_pk_A, EK_pk_A, ct_1, ct_2, prekey_id, tag_A)
```

---

## 4. Ephemeral PQ Double Ratchet (§3.5)

### 4.1 Symmetric Ratchet (§3.5.1)

Per-message keys derived via BLAKE3-KDF with distinct domain bytes:

```
MK_i    = BLAKE3-KDF(CK_i, 0x01, "StarMesh-MK")
CK_i+1  = BLAKE3-KDF(CK_i, 0x02, "StarMesh-CK")
```

`MK_i` is zeroized immediately after use (per-message forward secrecy).

### 4.2 Classical DH Ratchet

X25519 ephemeral keys in message headers trigger a root-key update:

```
RK, CK_s = HKDF-SHA3-256(ikm=DH_new, salt=RK, info="StarMesh-RK", L=64)
```

### 4.3 Post-Quantum Ratchet — PCS Recovery (§3.5.3)

1. Alice generates fresh ephemeral ML-KEM keypair; sends `EPH_PQ_pk` in message header.
2. Bob encapsulates: `(ct_new, SS_PQ_new) ← ML-KEM-768.Encaps(EPH_PQ_pk)`; attaches `ct_new`.
3. Alice decapsulates using `EPH_PQ_sk`, which is then **immediately dropped** (one-time use via `Option<T>`).
4. Both parties update the root chain:

```
RK, CK_s = HKDF-SHA3-256(ikm=SS_PQ, salt=RK, info="StarMesh-PQ-RK", L=64)
```

This restores full confidentiality even if prior session state was compromised.

---

## 5. Security Properties (§4, §5)

### Provable Properties

| Property | Mechanism | Paper Section |
|---|---|---|
| PQ Forward Secrecy (handshake) | `PQ_OTPK_sk` zeroized after single decapsulation | §3.4, §5.2 |
| Post-Compromise Security | Ephemeral PQ ratchet; `EPH_PQ_sk` dropped after use | §3.5.3, §5.3 |
| UKS / identity-misbinding resistance | DSA identities bound into HKDF `info` | §3.4 |
| Transcript binding | `EK_pk`, `ct_1`, `ct_2` bound into `info` (Giacon et al.) | §3.4 |
| Active MITM resistance | ML-DSA-65 bundle signatures | §4.1, §5.1 |
| Metadata resistance | Mixnet / onion routing over DHT | §6 |

### Cryptographic Assumptions (§4.1)

- **Assumption 4.1** — ML-KEM-768 is IND-CCA2 secure (Module-LWE hardness).
- **Assumption 4.2** — HKDF-SHA3-256 is PRF-secure (used in all game-hop proofs H2→H3).
- **Assumption 4.3** — X25519 is computationally secure against classical adversaries.

---

## 6. Known PoC Scope Gaps

| Gap | Detail | Roadmap |
|---|---|---|
| OTPK exhaustion fallback | Falls back to `PQ_SPK` only; PQ-FS holds per rotation epoch, not per session (§3.3 Remark 3.1) | Proactive batch replenishment |
| DHT not implemented | Bundle distribution is in-process in the PoC | docs/roadmap.md |
| ML-DSA-65 stubs | Fixed-byte identity keys; real signatures not verified in Rust PoC | Future release |
| Classical DH ratchet | PoC exercises symmetric + PQ ratchet only | v0.4.0 |
| No AEAD layer | AES-256-GCM payload encryption out of scope | v0.4.0 |
