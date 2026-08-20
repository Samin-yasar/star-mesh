# Reduction Tightness and Entropy Recovery

This note records two security improvements to the Star-Mesh analysis.

## Multi-instance KEM reduction

The original PQ-FS proof embeds one IND-CCA2 challenge into one of two possible pre-key
encapsulations and pays a `1/2` role/branch guessing factor. A multi-instance reduction should
instead receive challenge instances for every KEM branch that can contribute to the target
transcript, embed them all, and answer the adversary's view consistently.

If `q_kem` independent ML-KEM challenge instances are used, a conservative reduction has the form

```text
Adv_KEM(B) >= (Adv_PQ-FS(A) - negl(lambda)) / q_kem
```

and does not pay an additional `1/2` branch-selection loss. For the current two-encapsulation
handshake, `q_kem = 2` is the honest accounting when both `PQ_SPK` and `PQ_OTPK` are present. The
reduction must still handle pre-key reuse, decapsulation-oracle restrictions, adaptive session
selection, and any loss from guessing the target session. A multi-instance theorem is therefore
tighter, but not loss-free or automatically “bulletproof.”

The PCS round-trip has one fresh KEM keypair by definition, so it does not need the handshake's
branch guess. Its reduction still needs a precise multi-session accounting bound.

## Entropy-pool recovery

The prototype now maintains an `entropy_pool` and updates it after a successful PQ ratchet:

```text
pool' = HKDF-Extract(entropy_pool, SS_PQ,
                     "StarMesh-EntropyPool" || ciphertext)
RK'   = HKDF-Expand(pool', "StarMesh-PQ-RK", 64)
```

Both endpoints derive the same value because both know `SS_PQ` and the ciphertext. The ciphertext
is public transcript context and domain separation; it is not treated as an entropy source. The
freshness comes from the ML-KEM shared secret, assuming the KEM security condition holds.

This construction improves recovery after a state compromise when a fresh PQ exchange succeeds,
even if the old pool and root key were exposed. It does **not** repair a compromised RNG before
the fresh ML-KEM keypair is generated, and it does not create entropy from a known root key plus a
public ciphertext. If the adversary controls the key-generation randomness, the PQ recovery step
must be considered non-fresh. A production design should combine this pool with an independent
local entropy source, continuous health tests, and explicit zeroization.

The Rust proof-of-concept implements the pool update in `RatchetState::mix_pq_secret`. The formal
models and paper proof still need a dedicated entropy-source model before this is a theorem.
