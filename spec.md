# StarMesh Protocol Specification

> **Revision:** v0.1 (synced with paper.tex draft, October 2026)
>
> **This is the single source of truth** for all byte-level formats, domain
> labels, and KDF inputs.  Every other document (`construction.md`, `ratchet.md`,
> `kem-buffer.md`, `reduction-tightness-and-entropy.md`) and every PoC
> (`poc/rust/src/main.rs`, `poc/python/poc.py`) must agree with this file.
> If there is a discrepancy, **this file wins**.  Update the revision tag when
> any byte-level detail changes.

---

## Table of Contents

1. [Primitives](#1-primitives)
2. [Domain Labels (complete catalogue)](#2-domain-labels-complete-catalogue)
3. [Key Types and Sizes](#3-key-types-and-sizes)
4. [Hybrid PQ-X3DH Handshake](#4-hybrid-pq-x3dh-handshake)
5. [Double Ratchet](#5-double-ratchet)
6. [KEM-Buffer State Machine](#6-kem-buffer-state-machine)
7. [Key-Deletion Schedule](#7-key-deletion-schedule)
8. [Security Assumptions](#8-security-assumptions)
9. [PoC Scope Gaps](#9-poc-scope-gaps)

---

## 1. Primitives

| Role | Primitive | Standard | Output size |
|---|---|---|---|
| Identity signatures | ML-DSA-65 (Dilithium3) | FIPS 204 | 3309-byte sig, 1952-byte pk |
| Key encapsulation | ML-KEM-768 (Kyber768) | FIPS 203 | 1088-byte ct, 32-byte SS |
| Classical DH | X25519 | RFC 7748 | 32-byte output |
| Handshake / ratchet KDF | HKDF-SHA3-256 | RFC 5869 + FIPS 202 | variable |
| Symmetric ratchet KDF | BLAKE3-KDF | -- | 32 bytes |
| KEM-ID hash / transcript | BLAKE3 | -- | 32 bytes |
| AEAD (payload) | AES-256-GCM | NIST SP 800-38D | -- |

**HKDF-SHA3-256** means the RFC 5869 construction with HMAC-SHA3-256 as the
underlying PRF.  It is used for all multi-output key derivation steps.

**BLAKE3-KDF** is `blake3::Hasher::new(); update(key); update(&[domain]); update(info)`,
read as a 32-byte XOF output.  It is used only for per-message symmetric ratchet
steps where low latency matters.

These two are **non-interchangeable**.

---

## 2. Domain Labels (complete catalogue)

Every label used anywhere in handshake, ratchet, or signature contexts.
An implementation that uses a label not listed here, or omits a label listed
here, is out of spec.

### 2.1 HKDF `info` strings

| Label (UTF-8 bytes) | Used in |
|---|---|
| `"StarMesh-v1"` | Handshake HKDF info prefix (section 4.4) |
| `"StarMesh-Confirm"` | Confirmation-key HKDF info prefix (section 4.5) |
| `"StarMesh-RK"` | Classical DH ratchet HKDF info (section 5.3) |
| `"StarMesh-v1-EntropyPool"` | PQ ratchet HKDF-Expand for entropy pool (section 5.4) |
| `"StarMesh-v1-PQ-RK"` | PQ ratchet HKDF-Expand for root + chains (section 5.4) |

### 2.2 BLAKE3 info strings (symmetric ratchet)

| Label | Domain byte | Used in |
|---|---|---|
| `"StarMesh-MK"` | `0x01` | Message-key derivation (section 5.2) |
| `"StarMesh-CK"` | `0x02` | Next chain-key derivation (section 5.2) |

### 2.3 BLAKE3 labels (hash contexts, no domain byte)

| Label | Used in |
|---|---|
| `"StarMesh-transcript-v1"` | Initial transcript hash value (section 6.4) |
| `"StarMesh-KEM-v1"` | kem_id derivation (section 6.1) |

### 2.4 Signature payload prefixes

| Label | Used in |
|---|---|
| `"StarMesh-Handshake-M0-Init-v1"` | M0 initiator signature (section 4.6) |
| `"StarMesh-UpdateAuth-Init-v1"` | Update-header initiator signature (section 6.2) |
| `"StarMesh-UpdateAuth-Resp-v1"` | Update-response responder signature (section 6.3) |

---

## 3. Key Types and Sizes

| Symbol | Type | Size |
|---|---|---|
| `IK_DSA_sk` | ML-DSA-65 signing key | -- |
| `IK_DSA_pk` | ML-DSA-65 verifying key | 1952 bytes |
| `IK_DH_sk` | X25519 static secret | 32 bytes |
| `IK_DH_pk` | X25519 public key | 32 bytes |
| `SPK_sk / SPK_pk` | X25519 signed pre-key | 32 bytes each |
| `OTPK_sk / OTPK_pk` | X25519 one-time pre-key | 32 bytes each |
| `PQ_SPK_sk / PQ_SPK_pk` | ML-KEM-768 static pre-key | 2400 / 1184 bytes |
| `PQ_OTPK_sk / PQ_OTPK_pk` | ML-KEM-768 one-time pre-key | 2400 / 1184 bytes |
| `EK_sk / EK_pk` | X25519 ephemeral (per-session) | 32 bytes each |
| `EPH_PQ_sk / EPH_PQ_pk` | ML-KEM-768 ephemeral (per-PQ-step) | 2400 / 1184 bytes |
| `RK` | Root key | 32 bytes |
| `CK_s / CK_r` | Chain keys (send / receive) | 32 bytes each |
| `MK` | Message key | 32 bytes |
| `EP` | Entropy pool | 32 bytes |
| `session_id` | BLAKE3(OKM) | 32 bytes |
| `kem_id` | BLAKE3("StarMesh-KEM-v1" || session_id || seq || pq_pk) | 32 bytes |
| `transcript_hash` | Running BLAKE3 transcript | 32 bytes |
| `SS_cl` | Concatenated X25519 outputs | 128 bytes (4x32) |
| `SS_PQ1`, `SS_PQ2` | ML-KEM-768 shared secrets | 32 bytes each |
| `SS_hybrid` | `0xFF || SS_cl || SS_PQ1 || SS_PQ2` | 193 bytes |
| `OKM` | HKDF output of handshake | 64 bytes |

---

## 4. Hybrid PQ-X3DH Handshake

### 4.1 Key Bundle

Each node publishes a pre-key bundle to the Kademlia DHT at lookup key
`SHA3-256(IK_DSA_pk)`:

```
Bundle = { IK_DSA_pk, IK_DH_pk, SPK_pk, PQ_SPK_pk,
           OTPK_pk[], PQ_OTPK_pk[], sigma_bundle }
```

`sigma_bundle = ML-DSA-65.Sign(IK_DSA_sk, BundlePayload)` where:

```
BundlePayload = "StarMesh-v1"
                || len32(IK_DSA_pk) || IK_DSA_pk
                || len32(IK_DH_pk)  || IK_DH_pk
                || len32(SPK_pk)    || SPK_pk
                || len32(PQ_SPK_pk) || PQ_SPK_pk
                || BLAKE3(all OTPK_pk concatenated)
                || BLAKE3(all PQ_OTPK_pk concatenated)
```

`len32(x)` is the 4-byte big-endian encoding of `len(x)`.

A verifier must check: (1) `sigma_bundle` is valid under `IK_DSA_pk`;
(2) the DHT lookup key equals `SHA3-256(IK_DSA_pk)`.

### 4.2 Initiator Computation

```
EK_sk, EK_pk <- X25519.KeyGen()

DH_1 = X25519(IK_DH_sk_A, SPK_pk_B)
DH_2 = X25519(EK_sk_A,    IK_DH_pk_B)
DH_3 = X25519(EK_sk_A,    SPK_pk_B)
DH_4 = X25519(EK_sk_A,    OTPK_pk_B)   # omit if no OTPK
SS_cl = DH_1 || DH_2 || DH_3 || DH_4  # 128 or 96 bytes

(ct_1, SS_PQ1) <- ML-KEM-768.Encaps(PQ_SPK_pk_B)
(ct_2, SS_PQ2) <- ML-KEM-768.Encaps(PQ_OTPK_pk_B)  # omit if no PQ_OTPK
```

Bob zeroizes `PQ_OTPK_sk_B` immediately after decapsulation.

### 4.3 Hybrid IKM Layout

```
SS_hybrid = 0xFF || SS_cl || SS_PQ1 || SS_PQ2
```

The `0xFF` byte is a fixed one-byte format marker.  It is NOT Signal's
32-byte F constant and has no XEdDSA role.  Security weight comes from
the `info` string via the `"StarMesh-v1"` version label.

### 4.4 HKDF Invocation (handshake)

```
# Associated Data (prevents UKS/misbinding):
AD = "StarMesh-v1"
     || len32(IK_DSA_pk_A) || IK_DSA_pk_A
     || len32(IK_DSA_pk_B) || IK_DSA_pk_B

# Transcript binder (commits all ephemeral and ciphertext material):
info = AD
       || len32(EK_pk_A) || EK_pk_A
       || len32(ct_1)    || ct_1
       || len32(ct_2)    || ct_2

# HKDF call:
OKM = HKDF-SHA3-256(ikm=SS_hybrid, salt=0x00*32, info=info, L=64)

RK   = OKM[0:32]
CK_s = OKM[32:64]   # Alice's initial send chain key; Bob's initial recv chain key

session_id = BLAKE3(OKM)   # 32 bytes
```

### 4.5 Confirmation Tags

```
confirm_info = "StarMesh-Confirm" || info
K_conf = HKDF-SHA3-256(ikm=OKM, salt=0x00*32, info=confirm_info, L=32)
tag_A  = HMAC-SHA3-256(K_conf, info)          # Alice sends in M0
tag_B  = HMAC-SHA3-256(K_conf, "Bob" || info) # Bob returns; Alice verifies
```

`tag_A` alone is one-sided explicit authentication.  Mutual confirmation
requires the round-trip (`tag_B`).

### 4.6 M0 Wire Structure and Signature

```
# Signed payload:
m_init = "StarMesh-Handshake-M0-Init-v1"
         || len32(IK_DSA_pk_A) || IK_DSA_pk_A
         || IK_DH_pk_A                          # 32 bytes, no length prefix
         || len32(IK_DSA_pk_B) || IK_DSA_pk_B
         || EK_pk_A                             # 32 bytes, no length prefix
         || len32(ct_1) || ct_1
         || len32(ct_2) || ct_2
         || len32(prekey_id) || prekey_id
         || tag_A                               # 32 bytes, no length prefix

sigma_M0 = ML-DSA-65.Sign(IK_DSA_sk_A, m_init)

# Wire message:
M0 = ( IK_DSA_pk_A, IK_DH_pk_A, EK_pk_A,
       ct_1, ct_2, prekey_id, tag_A, sigma_M0 )
```

---

## 5. Double Ratchet

### 5.1 Initialization

```
root_key      = OKM[0:32]
entropy_pool  = root_key                          # same at session start
transcript_hash = BLAKE3("StarMesh-transcript-v1") # 32 bytes
valid_predecessors = { transcript_hash }

# Initiator (Alice):
send_chain_key = OKM[32:64]
recv_chain_key = None

# Responder (Bob):
recv_chain_key = OKM[32:64]
send_chain_key = None
```

### 5.2 Symmetric-Key Ratchet (BLAKE3)

Per message sent (using `send_chain_key`; mirror for received):

```
MK      = BLAKE3-KDF(CK, domain=0x01, info="StarMesh-MK")
CK_next = BLAKE3-KDF(CK, domain=0x02, info="StarMesh-CK")
```

- `MK` is used once for AES-256-GCM, then **immediately zeroized**.
- `CK` is overwritten with `CK_next`; old value is zeroized.

### 5.3 Classical DH Ratchet (X25519)

Triggered by a new remote ephemeral `DH_pk` in the message header:

```
DH_new   = X25519(local_eph_sk, remote_eph_pk)
out      = HKDF-SHA3-256(ikm=DH_new, salt=RK, info="StarMesh-RK", L=64)
RK       = out[0:32]
CK_s     = out[32:64]
```

Old `RK` and old ephemeral secret are zeroized.

The salt is the current (secret) `RK`, so PRF security of HMAC-SHA3-256
applies directly; no dual-PRF assumption is needed.

### 5.4 PQ Ratchet (ML-KEM-768) -- PCS Recovery

Trigger: `pq_step_counter >= 50` or session age > 24 h.

```
# One extract (SS_PQ in key slot -- secret, 32 bytes):
PRK = HKDF-Extract(salt=SS_PQ, ikm=RK || EP)

# Two expands (kem_id and ct are public, used for domain separation):
EP'  = HKDF-Expand(PRK, "StarMesh-v1-EntropyPool" || kem_id || ct, L=32)
out  = HKDF-Expand(PRK, "StarMesh-v1-PQ-RK"       || kem_id || ct, L=96)

RK'   = out[0:32]
CK_i2r = out[32:64]   # initiator-to-responder chain key
CK_r2i = out[64:96]   # responder-to-initiator chain key
```

Directional assignment:

| Party | send_chain_key | recv_chain_key |
|---|---|---|
| Initiator (Alice) | `out[32:64]` | `out[64:96]` |
| Responder (Bob)   | `out[64:96]` | `out[32:64]` |

Notes:
- `SS_PQ` is in the **salt slot**.  Because it is a uniform 32-byte secret
  under ML-KEM IND-CCA2, pseudorandomness of PRK follows from plain PRF
  security of HMAC-SHA3-256 with no dual-PRF or extractor assumption.
- Old `RK`, `EP`, `CK_s`, `CK_r` are zeroized before being overwritten.
- `EPH_PQ_sk` is consumed exactly once via `Option::take()` and dropped.

---

## 6. KEM-Buffer State Machine

### 6.1 `kem_id` Derivation

```
kem_id = BLAKE3("StarMesh-KEM-v1" || session_id || seq_be64 || EPH_PQ_pk)
```

- `session_id` -- 32 bytes.
- `seq_be64` -- sequence counter as 8-byte big-endian.
- `EPH_PQ_pk` -- 1184-byte ML-KEM-768 encapsulation key.
- Output: 32 bytes.

`kem_id` is carried in the authenticated header; it is NOT inferred from
arrival order.

### 6.2 Update Header Wire Structure

```
# Signed payload (initiator, Alice):
m_init_upd = "StarMesh-UpdateAuth-Init-v1"
             || session_id       # 32 bytes
             || kem_id           # 32 bytes
             || seq_be64         # 8 bytes
             || epoch_be64       # 8 bytes  (= seq in current PoC)
             || predecessor      # 32 bytes (current transcript_hash)
             || EPH_PQ_pk        # 1184 bytes

sigma_init = ML-DSA-65.Sign(IK_DSA_sk_A, m_init_upd)

RecoveryUpdateHeader = {
    session_id, kem_id, sequence (u64), epoch (u64),
    predecessor (32 bytes), EPH_PQ_pk, IK_DSA_pk_A, sigma_init
}
```

### 6.3 Update Response Wire Structure

```
# Signed payload (responder, Bob):
m_resp = "StarMesh-UpdateAuth-Resp-v1"
         || session_id   # 32 bytes
         || kem_id       # 32 bytes
         || EPH_PQ_pk    # 1184 bytes (prevents key substitution)
         || ct           # 1088 bytes (ML-KEM-768 ciphertext)
         || epoch_be64   # 8 bytes
         || predecessor  # 32 bytes

sigma_resp = ML-DSA-65.Sign(IK_DSA_sk_B, m_resp)

RecoveryUpdateResponse = {
    kem_id, EPH_PQ_pk, ct, IK_DSA_pk_B, sigma_resp
}
```

### 6.4 Transcript Hash

```
# Initial value:
transcript_hash_0 = BLAKE3("StarMesh-transcript-v1")   # 32 bytes

# After each applied PQ step:
transcript_hash' = BLAKE3(transcript_hash || kem_id || ct)
```

Both `transcript_hash` and `transcript_hash'` are added to
`valid_predecessors`.  This allows pipelining: Alice may propose a new
update before Bob's response to the previous one has been applied.

---

## 7. Key-Deletion Schedule

| Key | Deleted when |
|---|---|
| `MK` | Immediately after one-time use (encrypt or decrypt) |
| `CK` | As soon as `CK_next` is derived |
| `RK` | As soon as a DH or PQ ratchet step updates it |
| `EP` | As soon as `EP'` is derived (PQ step) |
| `EPH_PQ_sk` | Consumed via `Option::take()` before decapsulation; not stored afterwards |
| `PQ_OTPK_sk` | Zeroized immediately after decapsulation in the handshake |
| Skipped `MK`s | After one-time use OR after 7-day TTL |
| Entire `RatchetState` | On session close, via `Drop` + `zeroize` |

---

## 8. Security Assumptions

| # | Assumption | Used in |
|---|---|---|
| A1 | ML-KEM-768 is IND-CCA2 secure (Module-LWE) | Handshake PQ-FS, PQ ratchet PCS |
| A2 | HKDF-SHA3-256 is PRF-secure (paper Assumption 4.2) | All HKDF steps |
| A3 | X25519 satisfies DDH / PRF-ODH against classical adversaries | Classical DH ratchet healing |
| A4 | ML-DSA-65 is EUF-CMA secure (Module-LWE / SIS) | Update authentication |
| A5 | BLAKE3 is a PRF in the symmetric ratchet | Per-message key uniqueness |
| A6 | BLAKE3 is collision-resistant (transcript hash / kem_id) | Replay / stale-proposal exclusion, Claim 5.1 |

Notes:
- A3 requires DDH or PRF-ODH explicitly; a raw CDH output is not
  pseudorandom without an additional extraction argument.
- A6 is needed for Claim 5.1 (bundle batch-hash collision resistance).
- The PCS bound includes adversary terms for A1, A2, A4, and A5.

---

## 9. PoC Scope Gaps

Python PoC now uses **real primitives** matching the Rust prototype.
The table below lists remaining gaps (not wrong implementations — just
features not yet exercised).

| Feature | Rust PoC | Python PoC |
|---|---|---|
| ML-DSA-65 | Real (`ml_dsa` crate, FIPS 204) | ✅ Real (`dilithium-py` v1.5, FIPS 204) |
| ML-KEM-768 | Real (`ml_kem` crate, FIPS 203) | ✅ Real (`kyber-py` v1.2, FIPS 203) |
| X25519 | Real (`x25519-dalek`) | ✅ Real (`cryptography` hazmat) |
| HKDF hash | HMAC-SHA3-256 | ✅ HMAC-SHA3-256 (`hmac` + `hashlib.sha3_256`) |
| BLAKE3 | Real (`blake3` crate) | ✅ Real (`blake3` Python, `derive_key` mode) |
| AES-256-GCM | Not wired to messages | ✅ Implemented, exercised in KAT |
| σ_M0 (initiator handshake sig) | ✅ | ✅ Real ML-DSA-65 |
| σ_init / σ_resp (PQ ratchet) | ✅ | ✅ Real ML-DSA-65 |
| Secret deletion (`dk = None`) | `zeroize` crate | ✅ `pending.dk = None` after decaps |
| KDF vectors match Rust | Ground truth | Cross-check targets printed at run time |
| Classical DH ratchet (X25519) | Not exercised in tests | Not exercised |
| DHT bundle distribution | Not implemented | Not implemented |
| OTPK batch replenishment | Not implemented | Not implemented |
| Constant-time | Yes (C / Rust libs) | **No** — pure Python, educational only |
| Audited | No | No |

### Cross-check procedure

The Python PoC prints two deterministic KDF vectors at the end of every run:

```
HKDF-SHA3-256 extract(0^32, range(32)) PRK = <hex>
HKDF-SHA3-256 expand(PRK, PQ-RK-info, 96)[0:32] RK' = <hex>
```

Add matching Rust unit tests with the same fixed inputs (`ikm = 0x00..0x1f`,
`salt = 0^32`, `info = b"StarMesh-v1-PQ-RK" + 0^32 + 0^{1088}`).  If the
two outputs agree, the KDF shape is in sync.  If they disagree, one side
has drifted from this spec.

---

*End of spec.md -- StarMesh v0.1*
