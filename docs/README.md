# Documentation map

This directory contains the primary technical documentation for the Star-Mesh protocol and its supporting implementation work. The writing should be read in sequence rather than as a set of isolated notes.

## Reading order

1. [construction.md](construction.md) — protocol construction and cryptographic design.
2. [ratchet.md](ratchet.md) — session state machine and key evolution logic.
3. [roadmap.md](roadmap.md) — engineering and validation roadmap.
4. [research-notes.md](research-notes.md) — design commentary, trade-offs, and open issues.

## Scope

The documents in this directory are intended to support a research-grade understanding of the project, not a user-facing product manual. They emphasize formal reasoning, implementation constraints, and security boundaries rather than marketing language or generalized protocol boilerplate.

## What is covered

- cryptographic assumptions and hybrid construction,
- law-of-the-system assumptions for decentralized messaging,
- state evolution and message-key derivation,
- engineering milestones and validation targets,
- operational caveats relevant to a research prototype.

## Research posture

The project is best interpreted as a specification and demonstrator for a specific class of post-quantum messaging protocols. The repository deliberately privileges verifiability, conceptual clarity, and correct security framing over broad feature scope or polished interfaces.

The documents here are intended to be technically honest about the current maturity of the design. In particular, they distinguish between:

- protocol-level claims,
- proof-of-concept evidence,
- and a broader production roadmap.

This distinction matters. The protocol can be specified and demonstrated in a compact form without implying an end-to-end deployable system in the same step.
