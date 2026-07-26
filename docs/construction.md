# Cryptographic Construction: Star-Mesh (StarConnect) Protocol

This document outlines the formal cryptographic construction of the Star-Mesh (StarConnect) protocol, specifically designed to meet the rigorous standards for acceptance at the IACR ePrint archive. The protocol provides robust forward secrecy and post-quantum resilience against both passive and active quantum adversaries in a fully decentralized, zero-cost P2P environment.

## 1. Preliminaries and Cryptographic Primitives

The Star-Mesh protocol relies on standardized, expert-vetted post-quantum cryptographic primitives (NIST FIPS standards), hybridized with classical curves for defense-in-depth against $Adv_{Net}$ (Classical Network Adversary) and $Adv_{Quant}$ (Active Quantum-Capable Adversary).

*   **Digital Signatures (Identity):** ML-DSA-65 (Dilithium3) for fully post-quantum, long-term identity verification, preventing active quantum MITM attacks.
*   **Key Encapsulation (KEM):** ML-KEM-768 (Kyber768), targeting NIST Security Level 3.
*   **Classical Key Exchange (Hybrid fallback):** X25519 for static and ephemeral Diffie-Hellman operations.
*   **Key Derivation & Hash Functions:** HKDF-SHA3-256 for key derivation and BLAKE3 for symmetric ratchet chains.
*   **Authenticated Encryption (AEAD):** AES-256-GCM for ciphertext payloads.

---

## 2. Key Generation and Identity Representation

A node's identity is self-sovereign and deterministically derived from a high-entropy master seed. 

An **Identity Bundle** comprises the following key material:

1.  $IK$: Long-term ML-DSA-65 signing keypair ($IK_{sk}, IK_{pk}$).
2.  $SPK$: Medium-term X25519 static Diffie-Hellman keypair.
3.  $PQ\_SPK$: Medium-term ML-KEM-768 static keypair.

### 2.1 Pre-Key Bundle Publication

To facilitate asynchronous key exchange over the Kademlia DHT without centralized servers, each node publishes a signed **Pre-Key Bundle**. For a node $A$ (Alice), the bundle is defined as:

$$ Bundle_A = \{ IK_{pk}^A, SPK_{pk}^A, PQ\_SPK_{pk}^A, OTPK_{pk}^A, PQ\_OTPK_{pk}^A, Sig_{IK^A}(Payload) \} $$

Where:
*   $OTPK_{pk}^A$: A set of One-Time X25519 Pre-Keys.
*   $PQ\_OTPK_{pk}^A$: A set of **One-Time ML-KEM-768 Pre-Keys**. These are critical to guaranteeing Post-Quantum Forward Secrecy (PQ-FS) for the initial handshake if the static key $PQ\_SPK$ is ever compromised.

---

## 3. Hybrid Post-Quantum Key Exchange (PQ-X3DH)

To establish an initial Shared Secret ($SS$) with Bob ($B$), Alice ($A$) performs a hybrid handshake encapsulating classical ECDH and Post-Quantum KEM, utilizing Bob's One-Time Pre-Keys.

### 3.1 Protocol Execution

1.  **Classical ECDH Component:**
    Alice generates an ephemeral X25519 keypair ($EPH_{sk}^A, EPH_{pk}^A$) and computes the classical shared secret against Bob's static and one-time keys (standard X3DH).
    $$ SS_{classical} = \text{X3DH}(EPH_{sk}^A, SPK_{pk}^B, OTPK_{pk}^B) $$

2.  **Post-Quantum KEM Encapsulation Component:**
    Alice encapsulates against Bob's static PQ key and one of his one-time PQ keys:
    $$ (ct_1, SS_{PQ1}) \leftarrow \text{ML-KEM-768.Encapsulate}(PQ\_SPK_{pk}^B) $$
    $$ (ct_2, SS_{PQ2}) \leftarrow \text{ML-KEM-768.Encapsulate}(PQ\_OTPK_{pk}^B) $$

3.  **Cryptographic Binding and Secret Derivation:**
    The secrets are concatenated and bound to the post-quantum identities of both communicating parties to prevent Unknown Key-Share (UKS) and Identity Misbinding attacks.
    $$ AD = \text{"StarMesh"} \parallel |IK_{pk}^A| \parallel IK_{pk}^A \parallel |IK_{pk}^B| \parallel IK_{pk}^B $$
    $$ SS_{hybrid} = SS_{classical} \parallel SS_{PQ1} \parallel SS_{PQ2} $$
    $$ OKM = \text{HKDF-SHA3-256}(SS_{hybrid}, AD, 64) $$

    The $OKM$ initializes the Double Ratchet root chain. Bob immediately deletes the private key corresponding to $PQ\_OTPK_{pk}^B$ upon successful decapsulation, cementing PQ-FS.

---

## 4. Post-Quantum Double Ratchet Engine

The protocol achieves Post-Compromise Security (PCS) against quantum adversaries by transmitting ephemeral KEM keys within message headers.

### 4.1 The Hash Chain (Symmetric Ratchet)
Message keys ($MK$) are derived using BLAKE3:
$$ MK_i = \text{KDF}(ChainKey_i, \text{0x01}) $$
To ensure strict forward secrecy, intermediate states are aggressively zeroized from memory using zeroize routines.

### 4.2 The Classical & Post-Quantum Ephemeral Ratchet
Standard X25519 ephemeral keys are exchanged in the headers of encrypted messages. To maintain Post-Compromise Security (PCS) against $Adv_{Quant}$, a **PQ Ratchet Step** is enforced dynamically:

1.  Alice generates a new ephemeral ML-KEM keypair: $(EPH\_PQ_{sk}^A, EPH\_PQ_{pk}^A)$.
2.  Alice transmits $EPH\_PQ_{pk}^A$ in the header of her message to Bob.
3.  When Bob replies, he performs a new encapsulation against Alice's ephemeral key:
    $$ (ct_{new}, SS_{PQ\_new}) \leftarrow \text{ML-KEM-768.Encapsulate}(EPH\_PQ_{pk}^A) $$
4.  Bob attaches $ct_{new}$ to his reply.
5.  Both parties mix $SS_{PQ\_new}$ into their Root Key via HKDF to advance the chain, mathematically restoring confidentiality even if the state was previously compromised.

---

## 5. Security Model and Provable Properties

### 5.1 Adversary Models
*   **$Adv_{Net}$:** Controls the network, can delay, drop, or inject messages, and can compromise classical cryptographic primitives given sufficient time.
*   **$Adv_{Quant}$ (Active):** Possesses a Cryptographically Relevant Quantum Computer (CRQC). Can break ECDLP (Shor's Algorithm) and actively forge classical signatures. 

### 5.2 Asserted Properties
1.  **Post-Quantum Forward Secrecy (PQ-FS):** Guaranteed by the consumption and immediate deletion of ML-KEM One-Time Pre-Keys ($PQ\_OTPK$).
2.  **Post-Compromise Security (PCS):** If $Adv_{Quant}$ compromises the state at time $t$, full security is restored after a full round trip of the Ephemeral PQ Ratchet.
3.  **Active Quantum Integrity:** The use of ML-DSA-65 (Dilithium) for the identity key prevents $Adv_{Quant}$ from forging Pre-Key bundles or initiating Man-In-The-Middle (MITM) attacks.
4.  **Metadata Obfuscation (Cover Traffic & Onion Routing):** To prevent statistical intersection attacks on the P2P DHT, mailbox queries are routed through a lightweight mixnet (or an overlay like Tor/I2P/Nym) combined with constant-rate dummy polling. This severs the link between the node's IP address and the queried identity hash, achieving zero-cost metadata resistance.
