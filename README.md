# Star-Mesh

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21908681-blue?logo=doi)](https://doi.org/10.5281/zenodo.21908681)

Star-Mesh is a protocol and systems research project investigating hybrid post-quantum message security in decentralized settings. The repository contains the conceptual protocol specification, the cryptographic state-machine design, a reference proof-of-concept, and the corresponding LaTeX manuscript.

The project is intentionally narrow in scope: it focuses on the core security model rather than a full user-facing application. The design combines a hybrid key agreement layer, a double-ratchet session state, and a DHT-backed mailbox abstraction in order to evaluate how post-quantum confidentiality and forward secrecy interact with decentralized metadata exposure.

## Research framing

This work sits at the intersection of applied cryptography and distributed systems. The design emphasizes:

- hybrid classical/post-quantum key establishment,
- explicit forward secrecy and post-compromise recovery,
- session state continuity under asynchrony,
- metadata minimization through decentralized routing rather than centralized service assumptions.

The repository is organized to support three primary uses:

1. reading the protocol and design rationale,
2. reproducing the core cryptographic demonstration,
3. extending the manuscript and implementation artifacts in a consistent way.

---

## Repository map

```text
Star-Mesh/
├── README.md                  # Project overview and entry point
├── spec.md                    # Byte-level protocol specification (single source of truth)
├── LICENSE                    # Apache License 2.0
├── Makefile                   # Primary build and execution entry points
├── docs/                      # Research notes and protocol documentation
│   ├── README.md              # Documentation index and reading guide
│   ├── construction.md        # Hybrid cryptographic construction
│   ├── ratchet.md             # Ratchet state machine specification
│   ├── kem-buffer.md          # Concurrent KEM buffer state machine
│   ├── roadmap.md             # Engineering roadmap and milestones
│   └── ...                    # additional design notes and research records
├── formal/                    # Formal symbolic models (ProVerif)
│   ├── README.md              # Formal verification guide and results
│   ├── pq_x3dh.pv             # Handshake model
│   └── ratchet.pv             # Ratchet model (passive healing & skipped-key caveat)
├── paper/                     # LaTeX source for the paper
│   ├── Makefile               # Paper build pipeline
│   ├── paper.tex              # Main manuscript source
│   ├── paper.md               # Generated Markdown export of paper.tex
│   └── ...                    # auxiliary LaTeX artifacts
├── poc/                       # Reference implementations
│   ├── python/
│   │   └── poc.py             # Self-contained protocol demonstration
│   └── rust/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
├── .venv/                     # Local Python environment for reproducible demo runs
├── .gitignore
└── convert.py                 # LaTeX-to-Markdown conversion helper
```

---

## Reproducible workflow

The repository is intended to be read and exercised in a small number of standard ways.

### Python reference implementation

```bash
python3 -m venv .venv
.venv/bin/pip install kyber-py dilithium-py blake3 cryptography
.venv/bin/python3 poc/python/poc.py
```

This exercises the full protocol using real post-quantum primitives:
- **ML-KEM-768** via [`kyber-py`](https://github.com/GiacomoPope/kyber-py) (pure-Python FIPS 203)
- **ML-DSA-65** via [`dilithium-py`](https://github.com/GiacomoPope/dilithium-py) (pure-Python FIPS 204)
- **X25519 and AES-256-GCM** via [`cryptography`](https://cryptography.io)
- **HKDF-SHA3-256** via `hmac` + `hashlib.sha3_256` (one-extract / two-expand shape matching the paper)
- **BLAKE3** via [`blake3`](https://github.com/oconnor663/blake3) in `derive_key` mode

Key sizes match the paper's tables exactly (ML-KEM-768: 1184 B pk, 1088 B ct, 32 B ss; ML-DSA-65: 1952 B pk, 3309 B sig).

> **Scope note.** These libraries are pure-Python, unaudited, and not constant-time.
> They are correct reference implementations for studying message flow and catching
> spec drift between the Python and Rust code. They must not be used in production.

### Rust reference implementation

```bash
cargo run --manifest-path poc/rust/Cargo.toml
```

The Rust prototype uses production RustCrypto crates (`ml-kem` v0.3, `ml-dsa` v0.1.1, `x25519-dalek`, `blake3`, `hkdf`/`sha3`, `aes-gcm`, `zeroize`). It is the closest artifact to a production-grade implementation and is the source of all timing benchmarks cited in the paper.

### Paper build

```bash
make paper
```

or, from the project root:

```bash
make
```

The paper pipeline produces the manuscript PDF and regenerates `paper/paper.md` from
`paper/paper.tex` and the current LaTeX labels. The LaTeX source and PDF are the archival
manuscript artifacts; the Markdown file is a generated reading/export format.

To regenerate only the Markdown export after a successful LaTeX build:

```bash
make paper-md
```

### Build and maintenance helpers

```bash
make help
make clean
```

---

## Research reading path

For a focused reading sequence, the repository is designed to be traversed in this order:

1. [README.md](README.md) — project framing and entry point.
2. [spec.md](spec.md) — byte-level protocol specification and source of truth.
3. [docs/README.md](docs/README.md) — documentation map and narrative structure.
4. [docs/construction.md](docs/construction.md) — cryptographic construction.
5. [docs/ratchet.md](docs/ratchet.md) — ratchet state machine.
6. [docs/kem-buffer.md](docs/kem-buffer.md) — concurrent KEM buffer state machine.
7. [docs/roadmap.md](docs/roadmap.md) — engineering phases and validation targets.
8. [paper/paper.tex](paper/paper.tex) — formal manuscript.

This ordering reflects the research flow: protocol specification first, then operational engineering, then the formal write-up.

---

## Current status

This repository is best understood as a research prototype and specification artifact rather than a shipping application. The code is intentionally compact and explanatory, with a clear emphasis on protocol correctness and cryptographic reasoning over deployment polish.

The immediate objective is to maintain a clean, defensible line between:

- the protocol specification,
- the proof-of-concept implementation,
- and the paper-level claims.

---

## License

Copyright 2026 Samin Yasar.

Licensed under the [Apache License, Version 2.0](LICENSE).
