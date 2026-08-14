# Research notes

This note collects the main design observations that guide the current implementation and future work. It is intentionally brief and explicit about assumptions, trade-offs, and unresolved questions.

## 1. Research objective

The central aim is to evaluate whether a decentralized messaging protocol can provide meaningful post-quantum confidentiality and forward secrecy without depending on a trusted central authority. The project therefore tests a specific architectural compromise: hybrid cryptography at the session layer, decentralized key publication through a DHT, and metadata minimization through asynchronous relay patterns.

## 2. Design principles

The protocol follows several principles that are useful to keep in view during implementation and analysis.

### Stronger session guarantees than transport guarantees

A message protocol must be evaluated primarily on the security of its session state, not only on the security of the underlying transport. In practice, this means the protocol must be designed to maintain confidentiality across state compromise, message reordering, and asynchronous delivery.

### Hybridization as a defensive measure, not a replacement for sound protocol design

The classical and post-quantum components are not treated as interchangeable. They serve distinct purposes: the classical layer provides a familiar continuity and operational compatibility surface, while the PQ layer addresses the long-term risk of quantum-capable adversaries. The protocol is therefore hybrid by construction, but the security argument remains rooted in session design, key derivation discipline, and key erasure.

### Metadata exposure is a first-class protocol concern

Many secure messaging designs understate the privacy cost of metadata. In a decentralized setting, the routing structure and lookup pattern itself can reveal significant information. The mailbox abstraction and DHT interactions are therefore part of the cryptographic and systems design, not merely networking details.

## 3. Security assumptions

The current design assumes the following:

- adversaries can observe or manipulate network traffic,
- classical public-key assumptions may eventually fail under sufficiently strong quantum adversaries,
- a node compromise does not necessarily imply the simultaneous exposure of all historical session secrets,
- DHT nodes are not fully trusted and should be treated as untrusted storage infrastructure.

These assumptions are consistent with the project goal: to reason about confidentiality and resilience in a non-centralized environment rather than to guarantee absolute anonymity under all traffic-analysis models.

## 4. Practical trade-offs

A few practical limits are worth enumerating clearly.

### Simplicity over full-feature completeness

The present repository is built around a protocol core and proof-of-concept logic. It is not yet structured as a complete application stack with user identity management, key directories, or production-quality networking.

### Proof-of-concept fidelity versus deployment fidelity

The Python and Rust reference implementations are deliberately compact and explanatory. They are useful for validating the cryptographic ideas, but they do not resolve system-level concerns such as deployment latency, churn handling, or global operational coordination.

### Architectural honesty

The roadmap is intentionally explicit that performance and security optimization remain open engineering work. This matters because protocol research often overstates maturity when it is still only an abstract construction or a limited prototype.

## 5. Open questions

The following items are the main open questions for further work.

1. What is the appropriate metadata-minimization mechanism for real-world DHT querying without a centralized coordinator?
2. How should ephemeral key state be handled under churn and reordering at scale?
3. What is the minimum viable key-rotation policy that preserves both security and operational simplicity?
4. Which MLE/HKDF choices are most defensible under a formal adversarial model that also accounts for implementation leakage?

## 6. Publication perspective

The manuscript and the accompanying implementation should be read as a research artifact rather than an industrial product declaration. The repository is useful in a publication context because it makes the mechanism and the reasoning transparent, while keeping the scope finite enough to remain internally coherent.

The project is most compelling when presented as a rigorous attempt to bridge a protocol specification with a concrete, inspectable reference implementation. That is the role this repository is intended to serve.
