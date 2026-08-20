# UC Formulation for Star-Mesh

This document sketches a Canetti-style ideal functionality for Star-Mesh. It is a specification
and proof plan, not a UC realization theorem. The current ProVerif models are symbolic and do not
establish this formulation.

## Ideal functionality `F_SM`

`F_SM` maintains a set of users, pairwise sessions, ratchet epochs, and an abstract mixnet.
Each user has an identity handle and a corruption status.

### Registration

On `(Register, sid, uid, identity_key)` from a party, record `uid` and its identity binding. A
second registration for the same `(sid, uid)` is rejected. The functionality does not expose a
user's private keys to the adversary unless that user is corrupted.

### Session establishment

On `(Start, sid, sender, receiver, context)` from an honest sender, create a session if the
receiver is registered and the context is valid. Return `(Established, sid, session_id)` to both
honest endpoints when the delivery condition is met. The adversary learns only the leakage record
specified below; it does not receive the session secret or the message contents.

If a sender or receiver is corrupted, `F_SM` forwards the corresponding request and response to
the adversary, subject to the corruption interface. This models the fact that UC confidentiality
cannot be promised for a corrupted endpoint.

### Messages and epochs

On `(Send, sid, session_id, message, epoch)` from an honest sender, accept the message only for the
current epoch and atomically advance the sender's message state. Store the message in an abstract
mailbox until the receiver is online or a delivery request is made. On `(Receive, sid, session_id)`
from the receiver, deliver the next accepted message in order and erase the ideal copy after
acknowledgement.

For a ratchet update, `F_SM` samples a fresh epoch secret and replaces the old epoch secret. The
following guarantees are part of the ideal behavior:

- **Pre-compromise forward secrecy:** a later `Reveal` does not reveal messages accepted in erased
  earlier epochs.
- **Post-compromise recovery:** after a clean endpoint performs a successful fresh update and the
  update is delivered, later epochs are confidential again.
- **State-compromise boundary:** messages sent while an endpoint is corrupted, or messages whose
  delivery state was exposed by the corruption query, are not protected retroactively.
- **Asynchrony:** delayed, duplicated, reordered, and dropped delivery requests affect availability
  but do not reveal accepted plaintexts.

### Corruption

On `(Corrupt, sid, uid)`, mark the endpoint corrupted and return its current session state,
current epoch secret, active randomness state, and pending skipped-message state to the adversary.
The functionality does not return erased message keys or erased plaintexts. On
`(Recover, sid, uid, clean_rng)` from the environment, mark the endpoint recovered only if the
recovery condition is satisfied. A fresh update after recovery is the event that enables PCS.

The adversary can continue to delay, inject, reorder, or drop network deliveries after recovery.
It cannot force the functionality to accept an unauthenticated epoch transition.

## Mixnet leakage interface

Perfect traffic-flow hiding is not a realistic ideal for a network controlled by an active
adversary. `F_SM` therefore sends the simulator an explicit leakage token for each accepted
network transmission:

```text
Leak = (sid, direction, padded_length_class, send_time_window)
```

The ideal functionality reveals no sender/receiver association beyond what the configured leakage
profile permits. A concrete profile may reveal packet timing, fixed length, delivery success, and
a fraction of compromised ingress/egress observations. The simulator can then be parameterized by
Loopix-style assumptions such as honest mix fraction, cover traffic, batching, churn, and MTU.

This boundary matters: a realizer cannot claim UC anonymity if the environment is allowed to observe
all ingress and egress events with exact timing and no cover traffic. The mixnet realization theorem
must state the leakage profile and the network assumption separately from message confidentiality.

## Real-world protocol interface

The protocol instance exposes these abstract operations to the environment:

```text
Register(uid, identity_bundle)
FetchBundle(uid)
Start(sender, receiver, transcript)
Send(session_id, plaintext)
Receive(session_id)
Corrupt(uid)
Recover(uid, clean_rng_evidence)
```

The simulator `S` must emulate the DHT, mixnet, and cryptographic transcript for an ideal-world
adversary. It may use simulated bundles, ciphertexts, ratchet headers, and padded packets until an
ideal delivery or leakage event is requested. It must not know honest plaintexts or fresh ideal
epoch secrets.

## Realization theorem target

The intended theorem is a computational indistinguishability statement:

```text
REAL_StarMesh, A, Z  ≈  IDEAL_F_SM, S, Z
```

for every quantum-polynomial-time real adversary `A` and environment `Z`, under explicitly stated
assumptions for ML-KEM, ML-DSA, X25519 in the hybrid setting, AEAD, KDFs, secure erasure, DHT
availability, and the mixnet leakage profile.

A proof should be decomposed into at least these hybrids:

1. replace authenticated bundle contents with ideal authenticated records;
2. replace handshake and ratchet secrets with fresh ideal epoch secrets using the KEM combiner and
   ratchet reductions;
3. simulate erased state and post-compromise recovery after a clean fresh PQ update;
4. simulate DHT storage and mixnet packets while preserving only the declared leakage;
5. reduce any remaining environment distinguisher to authentication, KEM, AEAD, or mixnet failure.

The theorem must quantify security loss over the number of sessions, epochs, corruptions, and
network transmissions. It must also specify whether UC composition is plain, generalized, or
quantum-UC, and define the setup assumptions needed for identity authentication and DHT/mixnet
infrastructure.

## Current gap

The repository's games test pairwise secrecy and PCS under selected freshness conditions. They do
not provide an environment/simulator pair, composable interfaces, a UC corruption interface, or a
formal mixnet leakage functionality. The UC claim should therefore remain a future theorem until
those artifacts and a computational proof are added.
