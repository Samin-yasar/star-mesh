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
1,500-byte MTU. Category 3 ratchet packet sizes for the signed design (Theorem 4.17) are calculated as:

```text
normal conversational message = 192-byte payload + 96-byte Sphinx framing = 288 B (1 packet)
signed PQ public-key update   = 192 B payload + 1184 B ML-KEM + 3309 B ML-DSA = 4685 B -> 4 Sphinx packets (<= 1500 B)
signed PQ ciphertext reply    = 192 B payload + 1088 B ML-KEM + 3309 B ML-DSA = 4589 B -> 4 Sphinx packets (<= 1500 B)
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

## Queueing Dynamics and Saturation Mechanism

In the simulation results (Table 1 in the paper, comprising 13 evaluation runs across four churn regimes), delivery collapses sharply between offered load $\lambda = 5$ and $\lambda = 20$ pkts/slot (falling from $100.0\%$ to $31.3\%$). This drop is an expected queueing artifact of the simulation parameters rather than a protocol flaw:

- **Ingress Traffic:** Each slot generates $\text{Poisson}(\lambda)$ application packets and $\text{Poisson}(\lambda_{\mathrm{cover}})$ cover packets. With the default `cover_rate = load`, the total ingress arrival rate is $2\lambda$.
- **Hop Demand:** Each packet traverses $H = 3$ mix hops. Consequently, every arriving packet demands 3 independent forwarding operations across the network, creating an aggregate service demand of $3 \times 2\lambda = 6\lambda$ packet-services per slot.
- **Network Service Capacity:** With $N = 30$ mix nodes and a service capacity $C = 2$ packets/node/slot, the network's maximum aggregate service throughput is strictly $N \times C = 60$ packet-services per slot.
- **Utilization Breakdown:**
  - At $\lambda = 5$: Service demand is $30$ pkts/slot ($50\%$ network utilization, $\rho = 0.50$). Queues remain stable and clear quickly (p95 delay is 4 slots).
  - At $\lambda = 10$: Service demand is $60$ pkts/slot ($100\%$ network utilization, $\rho = 1.0$). This represents the queue saturation boundary; queues grow and delay increases to p95 = 152 slots.
  - At $\lambda = 20$: Service demand is $120$ pkts/slot ($200\%$ overload, $\rho = 2.0$). Arrivals arrive at twice the rate the network can process them. Queues grow monotonically throughout the 5,000-slot run, and packets remaining unserved in node queues when the run finishes are tallied as undelivered.

## Slot Calibration Note

The discrete-event simulation models time in abstract "slots" rather than physical milliseconds. In production mixnets (such as Loopix or Nym), mix nodes run as high-throughput servers capable of processing thousands of Sphinx packets per second per node, and per-hop Poisson delay parameters are tuned to physical millisecond distributions. Thus, the $C = 2$ capacity limit and discrete slot progression are benchmarking abstractions to verify packet sizes and queue behavior under controlled stress, not upper bounds on Star-Mesh's real-world throughput.

