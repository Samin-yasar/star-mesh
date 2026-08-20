# Mechanized Verification of Star-Mesh (ProVerif)

This directory contains the formal symbolic verification models for the **Star-Mesh** protocol, corresponding to the constructions and proofs in [`paper/paper.tex`](../paper/paper.tex).

---

## 1. Structure

| File | Protocol Component | Paper Reference |
| :--- | :--- | :--- |
| [`pq_x3dh.pv`](pq_x3dh.pv) | **Hybrid PQ-X3DH Handshake** | §3.3 (Bundle), §3.4 (Handshake), §5.1 (Claim 5.1 Identity Binding / MITM), §5.2 (Claim 5.2 PQ-FS) |
| [`ratchet.pv`](ratchet.pv) | **Ephemeral PQ Double Ratchet** | §3.5 (Ratchet State Machine), §4.4 (PCS Game), §5.3 (Claim 5.3 & Corollary 5.4/5.5 PCS Healing & Caveats) |

---

## 2. Prerequisites & Installation

ProVerif 2.04+ is required.

### macOS (Homebrew)
```bash
brew install proverif
```

### Ubuntu / Debian
```bash
sudo apt-get install proverif
```

### From Source / OPAM
```bash
opam install proverif
```

---

## 3. Running Verification

Execute the models directly from the repository root:

```bash
# Verify PQ-X3DH Handshake
proverif formal/pq_x3dh.pv

# Verify PQ Double Ratchet (FS, PCS Healing, and Caveats)
proverif formal/ratchet.pv
```

---

## 4. Summary of Verification Goals & Results

### A. Handshake Model (`pq_x3dh.pv`)

- **Attacker Model:** Dolev-Yao adversary with fully writable network/DHT channel (`pub`), active injection/dropping/reordering, and adaptive long-term key reveals ($\mathcal{O}^{\mathrm{RevealLTK}}$).
- **Core Security Claims Checked:**
  1. **Post-Quantum Forward Secrecy (PQ-FS, Def 4.10, Claim 5.2):** `query attacker(sess_key_witness)` $\implies$ **`RESULT ... is false`** (Key remains confidential against quantum-active adversary even with long-term key compromise).
  2. **Identity Binding / MITM Resistance (Claim 5.1):** `query event(AliceFinished(...)) ==> event(BobPublished(...))` $\implies$ **`RESULT ... is true`** (ML-DSA signature over the batch bundle payload guarantees authentic peer pairing independent of DHT Sybil assumptions).
  3. **Anti-Replay / Injective Correspondence:** `query inj-event(AliceFinished(...)) ==> inj-event(BobPublished(...))` $\implies$ **`RESULT ... is true`**.
  4. **Key Agreement & Convergence (§3.4):** `query event(AliceFinished(a,b,rk)) ==> event(BobFinished(a,b,rk))` $\implies$ **`RESULT ... is true`**.

### B. Ratchet Model (`ratchet.pv`)

- **State Evolution & Compromise Model:** Exercises 4 distinct operational phases:
  - **Epoch 0 (Pre-Compromise):** Message encryption with immediate symmetric key erasure.
  - **Epoch 1 (State Compromise at $t_{\mathrm{comp}}$):** Adversary learns full active session state ($\mathcal{O}^{\mathrm{Reveal}}$).
  - **Epoch 2 (PQ Healing Step):** Fresh ML-KEM exchange after recovery time $t_{\mathrm{rec}}$ (Assumption 4.6).
  - **Epoch 3 (Post-Healing):** Encrypted communication under the refreshed root chain.
- **Core Security Claims Checked:**
  1. **Forward Secrecy under State Reveal (§3.5.6, Claim 5.2):** `query attacker(w_pre_comp)` $\implies$ **`RESULT ... is false`** (Prior epochs survive state compromise).
  2. **PCS Healing (Claim 5.3, Corollary 5.4/5.5):** `query attacker(w_post_heal)` $\implies$ **`RESULT ... is false`** (Confidentiality is restored after 1 complete PQ round-trip).
  3. **Skipped-Key Caveat Machine-Check (Corollary 5.5 Caveat #2):** `query attacker(w_skipped_pre)` $\implies$ **`RESULT ... is true`** (Formally proves the stated limitation: keys cached prior to $t_{\mathrm{rec}}$ remain compromised).
  4. **Post-Healing Integrity:** `query event(BobReceivedPostHeal(m)) ==> event(AliceSentPostHeal(m))` $\implies$ **`RESULT ... is true`**.

---

## 5. Reviewer Note on Assumptions & Reductions

1. **IND-CCA2 KEM Axiomatisation:** ML-KEM-768 is abstracted as an IND-CCA2 compliant oracle interface following standard symbolic methods (Bhargavan et al., CCS 2017).
2. **HKDF as PRF:** Modeled as an uninterpreted cryptographic function (Assumption 4.2), enforcing domain separation via distinct function symbols.
3. **No Hidden DHT Assumptions:** The bundle transmission channel is attacker-writable; authentication relies purely on ML-DSA-65 signatures, eliminating circular dependencies on unproven DHT Sybil-resistance assumptions.
