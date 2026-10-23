# Reduction Tightness and Entropy Recovery

> **Synced with spec.md / paper rev:** v0.1 (October 2026)
>
> **Source of truth**: Byte-level formats, domain labels, and KDF inputs are defined in
> [`spec.md`](../spec.md). Concrete security bounds, game hops, and theorem statements are in
> `paper/paper.tex`. If there is any discrepancy, [`spec.md`](../spec.md) and `paper.tex` win.

---

This note records the formal security improvements and derivation structure for the Star-Mesh protocol.

## 1. Concrete Bounds and Multi-Instance Accounting

### 1.1 Handshake PQ-FS Bound (Theorem 4.10)

The original PQ-FS proof embedded one IND-CCA2 challenge into one of two possible pre-key
encapsulations, paying a $1/2$ role/branch guessing factor. The multi-instance reduction receives
challenge instances for every KEM branch that can contribute to the target transcript ($PQ\_SPK$ and $PQ\_OTPK$)
and embeds them consistently:

```text
Adv_KEM(B) >= (Adv_PQ-FS(A) - negl(lambda)) / q_kem
```

For the two-encapsulation handshake, $q_{kem} = 2$ when both $PQ\_SPK$ and $PQ\_OTPK$ are present.
The reduction handles decapsulation-oracle restrictions and adaptive session selection without
paying an artificial $1/2$ branch-selection penalty.

### 1.2 Post-Compromise Security (PCS) Concrete Bound (Theorem 4.17)

The post-compromise confidentiality bound accounts for all cryptographic components exercised in
the recovery round-trip:

$$
\Adv_{\mathrm{StarMesh}}^{\mathrm{pcs}}(\mathcal{A}) \le
2 \cdot \Adv_{\mathrm{ML-KEM-768}}^{\mathrm{ind-cca2}}(\mathcal{B}_{\mathrm{KEM}})
+ 2 \cdot \Adv_{\mathrm{HKDF}}^{\mathrm{prf}}(\mathcal{B}_{\mathrm{HKDF}})
+ 2 \cdot \Adv_{\mathrm{BLAKE3}}^{\mathrm{prf}}(\mathcal{B}_{\mathrm{B3}})
+ 2 \cdot Q_{\mathrm{upd}} \cdot \Adv_{\mathrm{ML-DSA-65}}^{\mathrm{euf-cma}}(\mathcal{B}_{\mathrm{DSA}})
+ \negl(\lambda)
$$

Key aspects of this accounting:
1. **BLAKE3 PRF Term:** Accounts for the symmetric ratchet's per-message key derivation ($MK_i$).
2. **ML-DSA-65 EUF-CMA Term:** Accounts for active adversary exclusion on update headers ($\sigma_{\mathrm{init}}$) and responses ($\sigma_{\mathrm{resp}}$) over $Q_{\mathrm{upd}}$ updates.
3. **HKDF-SHA3-256 PRF Term:** Follows directly from HMAC-SHA3-256 pseudorandomness because the ML-KEM secret $SS_{PQ}$ occupies the salt (key) slot.
4. **Classical Ratchet Assumption:** Ephemeral classical healing relies on DDH / PRF-ODH (Assumption 4.3), not plain CDH, ensuring pseudorandom output without requiring non-standard random-oracle or extractor assumptions on Curve25519.

---

## 2. Continuous Entropy-Pool Recovery (§3.5.3)

Star-Mesh maintains an `entropy_pool` ($EP$) alongside the root key ($RK$) and updates it after
every completed PQ ratchet step:

```text
PRK  = HKDF-Extract(salt = SS_PQ, ikm = RK || EP)
EP'  = HKDF-Expand(PRK, "StarMesh-v1-EntropyPool" || kem_id || ct, L = 32)
out  = HKDF-Expand(PRK, "StarMesh-v1-PQ-RK"       || kem_id || ct, L = 96)

RK'    = out[0:32]
CK_i2r = out[32:64]    # Initiator-to-responder chain key
CK_r2i = out[64:96]    # Responder-to-initiator chain key
```

### Cryptographic Rationale

1. **Secret Salt ($SS_{PQ}$):**
   In HKDF, when the salt is a secret, uniformly random 32-byte key (guaranteed under ML-KEM-768
   IND-CCA2), the extraction step operates as HMAC with a secret key. Thus, pseudorandomness of
   $PRK$ follows from **plain PRF security** of HMAC-SHA3-256. This eliminates any reliance on
   dual-PRF assumptions (which do not formally transfer from Merkle–Damgård HMAC to Keccak/SHA3
   sponge constructions).

2. **Entropy Preservation:**
   Because $ikm = RK \parallel EP$, any uncompromised entropy from prior classical DH ratchet steps
   or previous PQ epochs is mixed into the new state. If the post-quantum KEM was compromised
   (e.g., side-channel or future cryptanalytic weakness), but past root state was secure,
   confidentiality is preserved through standard HMAC extraction.

3. **Public Context Binding:**
   The `kem_id` and `ct` strings are included in the HKDF-Expand info strings. They provide strict
   transcript domain separation; they are not treated as entropy sources. Freshness comes solely
   from the ML-KEM shared secret.

### Implementation Status

The Rust reference implementation (`poc/rust/src/main.rs`) implements this exact derivation in
`RatchetState::mix_pq_secret`. Both endpoints derive identical root keys, entropy pools, and
directional chain keys upon applying matching sequence updates.
