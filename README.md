# Star-Mesh

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

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
├── LICENSE                    # Apache License 2.0
├── Makefile                   # Primary build and execution entry points
├── docs/                      # Research notes and protocol documentation
│   ├── README.md              # Documentation index and reading guide
│   ├── construction.md        # Hybrid cryptographic construction
│   ├── ratchet.md             # Ratchet state machine specification
│   ├── roadmap.md             # Engineering roadmap and milestones
│   └── research-notes.md      # Additional design observations and open questions
├── paper/                     # LaTeX source for the paper
│   ├── Makefile               # Paper build pipeline
│   ├── paper.tex              # Main manuscript source
│   ├── paper.md               # Markdown export / draft companion
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
└── convert.py                 # Compatibility helper for LaTeX-to-Markdown conversion
```

---

## Reproducible workflow

The repository is intended to be read and exercised in a small number of standard ways.

### Python demonstration

```bash
python3 -m venv .venv
.venv/bin/python3 poc/python/poc.py
```

This creates a fresh local virtual environment on the host machine so the executable does not depend on a machine-specific Xcode Python path. The reference walk-through verifies the essential protocol behavior: key generation, hybrid handshake convergence, symmetric ratchet agreement, and PQ ratchet recovery.

### Rust reference implementation

```bash
cargo run --manifest-path poc/rust/Cargo.toml
```

This path exercises the same protocol logic using concrete cryptographic crates. It is the closest implementation artifact to a production-grade prototype.

### Paper build

```bash
make paper
```

or, from the project root:

```bash
make
```

The paper pipeline produces the manuscript under the paper directory and is intended as the canonical archival artifact for the design.

### Build and maintenance helpers

```bash
make help
make clean
```

---

## Research reading path

For a focused reading sequence, the repository is designed to be traversed in this order:

1. [README.md](README.md) — project framing and entry point.
2. [docs/README.md](docs/README.md) — documentation map and narrative structure.
3. [docs/construction.md](docs/construction.md) — cryptographic construction.
4. [docs/ratchet.md](docs/ratchet.md) — ratchet state machine.
5. [docs/roadmap.md](docs/roadmap.md) — engineering phases and validation targets.
6. [paper/paper.tex](paper/paper.tex) — formal manuscript.

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
