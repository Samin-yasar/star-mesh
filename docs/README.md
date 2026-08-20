# Documentation map

This directory contains the primary technical documentation for the Star-Mesh protocol and its supporting implementation work. The writing should be read in sequence rather than as a set of isolated notes.

## Reading order

1. [construction.md](construction.md) — protocol construction and cryptographic design.
2. [ratchet.md](ratchet.md) — session state machine and key evolution logic.
3. [kem-buffer.md](kem-buffer.md) — concurrent KEM state machine and out-of-order KEM identifier handling.
4. [roadmap.md](roadmap.md) — engineering and validation roadmap.
5. [research-notes.md](research-notes.md) — design commentary, trade-offs, and open issues.
6. [reduction-tightness-and-entropy.md](reduction-tightness-and-entropy.md) — reduction tightness bounds and entropy recovery.
7. [mixnet-simulation.md](mixnet-simulation.md) — empirical mixnet queue and packetization simulation.
8. [d-mls-design.md](d-mls-design.md) — decentralized MLS group messaging architecture.
9. [uc-formulation.md](uc-formulation.md) — candidate UC ideal functionality and proof target.

## Scope

The documents in this directory are intended to support a research-grade understanding of the project, not a user-facing product manual. They emphasize formal reasoning, implementation constraints, and security boundaries rather than marketing language or generalized protocol boilerplate.

## What is covered

- Cryptographic assumptions and hybrid construction (ML-KEM-768, X25519, ML-DSA-65, HKDF-SHA3-256, BLAKE3),
- Session state evolution, symmetric ratcheting, and out-of-order KEM identifier (`kem_id`) buffer management,
- Mechanized formal verification in ProVerif (identity binding, forward secrecy, and PCS healing),
- Empirical mixnet queue and MTU packetization simulation under traffic load and churn,
- Decentralized MLS (D-MLS) operation-set CRDT architecture and epoch consistency,
- Reduction tightness bounds and continuous entropy-pool recovery,
- The candidate UC ideal functionality ($\mathcal{F}_{\mathrm{SM}}$) and realization proof target,
- Law-of-the-system assumptions for decentralized messaging,
- Engineering milestones, validation targets, and research roadmap.

## Research posture

The project is best interpreted as a specification and demonstrator for a specific class of post-quantum messaging protocols. The repository deliberately privileges verifiability, conceptual clarity, and correct security framing over broad feature scope or polished interfaces.

The documents here are intended to be technically honest about the current maturity of the design. In particular, they distinguish between:

- protocol-level claims,
- proof-of-concept evidence,
- and a broader production roadmap.

This distinction matters. The protocol can be specified and demonstrated in a compact form without implying an end-to-end deployable system in the same step.
