# Star-Mesh — Hybrid Post-Quantum Decentralized Messaging Protocol

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Star-Mesh is a research-grade, decentralized peer-to-peer secure messaging protocol providing **hybrid post-quantum confidentiality, forward secrecy, and post-compromise security**. It is described in the accompanying academic paper (see `paper/`), which is submitted / to be submitted to IACR ePrint.

Unlike centralized architectures, Star-Mesh operates over a Kademlia Distributed Hash Table (DHT) for key distribution and uses a mixnet-based onion-routing overlay for metadata obfuscation.

---

## Repository Structure

```
Star-Mesh/
├── docs/                      # Architectural & Cryptographic Specifications
│   ├── construction.md        # Cryptographic construction and hybrid primitives
│   ├── ratchet.md             # Ephemeral PQ Double Ratchet state machine spec
│   └── roadmap.md             # Phased engineering roadmap and risk analysis
├── paper/                     # Academic Paper (LaTeX source)
│   ├── Makefile               # Builds paper.pdf with latexmk
│   └── paper.tex              # Authoritative IACR ePrint draft (revised)
├── poc/                       # Proof-of-Concept Implementations
│   ├── python/
│   │   └── poc.py             # Zero-dependency Python 3 PoC (verified working)
│   └── rust/
│       ├── Cargo.toml         # ml-kem, x25519-dalek, blake3, hkdf, zeroize
│       └── src/
│           └── main.rs        # High-fidelity Rust PoC
├── LICENSE                    # Apache License 2.0
├── Makefile                   # Top-level: delegates to paper/Makefile
└── README.md                  # This file
```

---

## Running the Proof-of-Concept

### Python (zero dependencies — verified)

Uses the pinned `.venv` virtual environment:

```bash
.venv/bin/python3 poc/python/poc.py
```

Expected output confirms four phases:
1. **Phase 1** — Key generation for Alice and Bob
2. **Phase 2** — Hybrid PQ-X3DH handshake OKM convergence ✅
3. **Phase 3** — Symmetric ratchet message-key match ✅
4. **Phase 4** — PQ ratchet round-trip and root-key convergence ✅

### Rust (requires Rust/Cargo)

```bash
cd poc/rust
cargo run
```

Uses real cryptographic crates: `ml-kem` (FIPS 203), `x25519-dalek` (RFC 7748), `blake3`, `hkdf`, and `zeroize`.

---

## Compiling the Paper

Requires a LaTeX distribution with `latexmk` and `pdflatex`:

```bash
make          # builds paper/paper.pdf
make clean    # removes auxiliary files
```

---

## Cryptographic Construction

Star-Mesh is a *hybrid* post-quantum protocol combining classical curves and NIST-standardized post-quantum primitives:

| Layer | Primitive | Role |
|---|---|---|
| Identity | ML-DSA-65 (FIPS 204) | Post-quantum signatures |
| Handshake | X25519 + ML-KEM-768 (FIPS 203) | Hybrid PQ-X3DH key agreement |
| Ratchet (PQ) | ML-KEM-768 ephemeral | Post-compromise security |
| Ratchet (DH) | X25519 ephemeral | Classical forward secrecy |
| Key Derivation | HKDF-SHA3-256, BLAKE3 | Chain/root key derivation |
| AEAD | AES-256-GCM | Message encryption |

For the full formal treatment, see [`paper/paper.tex`](paper/paper.tex) and the specifications in [`docs/`](docs/).

---

## License

Copyright 2026 Samin Yasar.

Licensed under the [Apache License, Version 2.0](LICENSE).
