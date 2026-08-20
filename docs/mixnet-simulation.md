# Empirical Mixnet Simulation

`poc/python/mixnet_sim.py` is a small, deterministic queue simulation for the Star-Mesh
Sphinx/Loopix integration. It uses only the Python standard library and is intended to expose
packetization and queueing assumptions before a full network implementation exists.

Run it with:

```bash
make mixnet-sim
```

The default experiment sweeps offered load from 1 to 60 packets per slot and churn from 0%
to 30%, using 30 mix nodes, three hops, two packets of service capacity per node per slot, and a
1,500-byte MTU. Category 3 ratchet packet sizes are calculated as:

```text
normal = 192-byte payload + 96-byte Sphinx framing = 288 B
PQ public-key packet = 288 B + 1184 B ML-KEM key = 1472 B
PQ ciphertext packet = 288 B + 1088 B ML-KEM ciphertext = 1376 B
```

The run writes:

- `artifacts/mixnet/results.csv`: one row per load/churn point.
- `artifacts/mixnet/linkability.svg`: empirical entry-exit proxy curves.

The linkability value is the fraction of delivered application messages for which both the first
and last hops are compromised. It is deliberately described as a proxy: it does not model a
global passive observer, timing correlation, batching policy, packet cryptography, route
selection from a live topology, or real transport behavior. It therefore cannot establish the
Loopix anonymity theorem or replace an event-driven network experiment.

The simulator also reports packet-size violations directly. Changing `--mtu`,
`--base-payload`, or `--sphinx-overhead` is useful for testing whether a proposed payload format
still fits the constant-size packet budget.
