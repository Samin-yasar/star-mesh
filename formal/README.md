# Symbolic Verification of Star-Mesh (ProVerif)

Symbolic models for the **Star-Mesh** protocol, corresponding to [`paper/paper.tex`](../paper/paper.tex). These are *symbolic* (Dolev-Yao) models with stated gaps, not computational proofs. Read §5 before citing any result.

## 1. Files

| File | Component | Paper reference |
| :--- | :--- | :--- |
| [`pq_x3dh.pv`](pq_x3dh.pv) | Hybrid PQ-X3DH handshake | §3.3, §3.4, §5.1, §5.2 |
| [`ratchet.pv`](ratchet.pv) | One signed PQ ratchet (healing) step after state compromise | §3.5, §5.3 |
| [`run_mutations.sh`](run_mutations.sh) | Generates and runs the sanity-check mutants | evidence for the claims below |

## 2. Running

ProVerif 2.04+ (`brew install proverif`, `apt-get install proverif`, or `opam install proverif`). From this directory:

```bash
proverif pq_x3dh.pv
proverif ratchet.pv
./run_mutations.sh      # main models + all mutants
```

> **Status:** these revisions were written without a ProVerif binary available. Syntax (notably `query ... phase 1`) and every expected result below are **unconfirmed until you run them**. A result that differs from this table is a bug in the model or this README, not something to explain away.

## 3. `pq_x3dh.pv` — handshake

**Attacker:** Dolev-Yao with a fully attacker-writable network/DHT (`pub`), plus a **CRQC** (`dlog` destructor: all X25519 secrets are computable from public keys for the whole run). ML-DSA and ML-KEM are not broken. In **phase 1** the attacker additionally learns `spkSkB`, `pqSpkSkB`, `ikDhSkA`, `ikDhSkB`. One-time keys (`otpkSkB`, `pqOtpkSkB`) are generated fresh in every Bob session and never revealed, which models single use and erasure.

| # | Query | Expected | Meaning |
| :-- | :--- | :--- | :--- |
| Q1 | `attacker(sess_key_witness) phase 1` | **false** | With classical crypto broken and semi-static keys leaked later, the session key is still secret because of the PQ_OTPK shared secret. |
| Q2 | `AliceUsedBundle(b,spk,otpk,pqspk,pqotpk) ==> BobPublished(same)` | **true** | **Bundle authenticity** (exact pre-keys, from ML-DSA alone). *Not* session authentication; Bob's `tag_B` reply is not modelled. |
| Q3 | `inj-event BobAcceptedM0(a,b,ik,ek,ct1,ct2) ==> inj-event AliceSentM0(same)` | **true** | Initiator authentication with transcript data. |

**Mutants (evidence the queries are not vacuous):**

| Mutant | Change | Must show |
| :--- | :--- | :--- |
| `nokem` | KEM shared secrets replaced by a constant | Q1 **true** (key is exposed) |
| `nosigma0` | `sigma_0` verification removed | Q3 **false** |

**Not modelled:** ML-DSA key compromise / KCI, `tag_B`, pre-key rotation, a no-OTPK variant (which would show session-level FS only), implicit rejection in ML-KEM. `sigma_0` now carries the `StarMesh-M0` label, Bob's identity and the pre-key identifiers, and `K_conf` has its own HKDF symbol, `tag_A` covers `M0^core`; check these against the paper text.

## 4. `ratchet.pv` — one healing step

Alice and Bob are separate processes communicating only through an attacker-controlled channel. The attacker first receives the full state (`RK`, `EP`, next chain key, and a stale PQ secret key). Healing is one signed exchange: `Alice -> Bob: (epoch, pk_A, Sig_A)`, `Bob -> Alice: (ct, Sig_B)`, then `PRK = Extract(SS_PQ, (RK, EP))` with `kem_id || ct` as expand info. Alice→Bob traffic uses a chain-key message key; Bob→Alice traffic uses a key derived from the healed `(RK', EP')`.

| # | Query | Expected |
| :-- | :--- | :--- |
| Q1 | `attacker(w_pre_comp)` | false (pre-compromise message; only a one-way KDF check) |
| Q2 | `attacker(w_post_heal)` | false |
| Q3 | `attacker(w_post_heal_B)` | false (exercises `RK'` and `EP'`) |
| Q4 | `BobReceivedPostHeal(m) ==> AliceSentPostHeal(m)` | true (Bob accepts any ciphertext from `pub`; `m` is fresh per message) |
| Q5 | `AliceReceivedPostHeal(m) ==> BobSentPostHeal(m)` | true |

**Mutants — these carry the argument for the signature design:**

| Mutant | Change | Must show |
| :--- | :--- | :--- |
| `unsigned` | signature checks removed | attack: active MITM on the PQ update breaks healing |
| `nostale` | epoch check removed | Q3 fails: replay of an old signed proposal whose secret key was in the leaked state |
| `rng` | `seed_pq` leaked | Q2/Q3 fail: healing needs clean randomness at `t_rec` |

**Scope limits.** The healing result is for **one epoch, one session, signed updates, signing keys uncompromised**. It is not a full ratchet model: there is no DH ratchet, a single chain rather than two, and no kem_id negotiation, concurrency, staged commit or retry.

## 5. Assumptions and caveats (read before citing)

1. **Skipped-key cache (paper Corollary 5.5, Caveat 2)** is **recorded as an assumption**, not proved. The earlier query was true by construction (the key was handed to the attacker) and has been removed.
2. **"PCS healing"** here means *healing against an active network attacker, with signed updates, after a state reveal that excludes signing keys and RNG state*. The unsigned mutant shows it does not hold otherwise.
3. **ML-KEM** is an IND-CCA2 black box (cf. Bhargavan, Blanchet, Kobeissi, IEEE S&P 2017, please verify the citation); **HKDF** is uninterpreted with domain-separated symbols.
4. No DHT/Sybil-resistance assumption is used; authentication rests on ML-DSA signatures only.
5. Paper §3.6 and any list that repeats the old claims should be updated to match this README.
