#!/usr/bin/env python3
"""Small reproducible Sphinx/Loopix queue simulation for Star-Mesh.

This is a systems experiment, not a cryptographic proof. The linkability metric is
only the fraction of delivered messages observed at both a compromised entry and
compromised exit; it is a lower-bound proxy for a global passive adversary.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from dataclasses import dataclass
from pathlib import Path


MLKEM_PK_BYTES = 1184
MLKEM_CT_BYTES = 1088
MLDSA_SIG_BYTES = 3309
DEFAULT_MTU = 1500
DEFAULT_BASE_PAYLOAD = 192
DEFAULT_SPHINX_OVERHEAD = 96


@dataclass
class Packet:
    packet_id: int
    msg_id: int
    kind: str
    size: int
    entry: int
    exit: int
    enqueue_time: int
    frag_index: int = 0
    frag_total: int = 1
    hop: int = 0


@dataclass
class Result:
    load: float
    churn: float
    mtu_violations: int
    generated: int
    delivered: int
    dropped: int
    delivery_rate: float
    p95_delay: float
    entry_exit_linkability: float


def percentile(values: list[int], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)
    return float(ordered[index])


def packet_sizes(base_payload: int, sphinx_overhead: int, signed: bool = True) -> dict[str, int]:
    if not signed:
        return {
            "normal": base_payload + sphinx_overhead,
            "pq_pk": base_payload + sphinx_overhead + MLKEM_PK_BYTES,
            "pq_ct": base_payload + sphinx_overhead + MLKEM_CT_BYTES,
        }
    return {
        "normal": base_payload + sphinx_overhead,
        "pq_pk_signed_total": base_payload + sphinx_overhead + MLKEM_PK_BYTES + MLDSA_SIG_BYTES,
        "pq_ct_signed_total": base_payload + sphinx_overhead + MLKEM_CT_BYTES + MLDSA_SIG_BYTES,
        "fragment_mtu": DEFAULT_MTU,
    }


def poisson(rng: random.Random, mean: float) -> int:
    threshold = math.exp(-mean)
    product = 1.0
    count = 0
    while product > threshold:
        count += 1
        product *= rng.random()
    return count - 1


def simulate(
    *,
    load: float,
    churn: float,
    seed: int,
    slots: int,
    mix_nodes: int,
    hops: int,
    capacity: int,
    compromised_fraction: float,
    cover_rate: float,
    mtu: int,
    base_payload: int,
    sphinx_overhead: int,
    signed: bool = True,
) -> Result:
    rng = random.Random(seed)
    compromised = {
        node for node in range(mix_nodes)
        if rng.random() < compromised_fraction
    }
    queues: list[list[Packet]] = [[] for _ in range(mix_nodes)]
    delays: list[int] = []
    generated = delivered = dropped = violations = 0
    next_packet_id = 0
    next_msg_id = 0

    # Tracking per-message fragment delivery for signed multi-packet trains
    msg_frags_delivered: dict[int, int] = {}
    msg_linkable: dict[int, bool] = {}
    linkable_delivered = 0

    max_payload_per_frag = mtu - sphinx_overhead

    for now in range(slots):
        online = [rng.random() >= churn for _ in range(mix_nodes)]

        # New application and cover packets enter the first mix hop.
        arrivals = poisson(rng, load)
        covers = poisson(rng, cover_rate)

        # Application arrivals
        for _ in range(arrivals):
            msg_id = next_msg_id
            next_msg_id += 1
            generated += 1

            is_kem_update = rng.random() < (1.0 / 50.0)
            if not signed or not is_kem_update:
                n_frags = 1
                pkt_size = base_payload + sphinx_overhead
                if not signed and is_kem_update:
                    pkt_size += MLKEM_PK_BYTES if rng.random() < 0.5 else MLKEM_CT_BYTES
            else:
                # Signed update: ML-KEM + ML-DSA-65 signature + base payload
                kem_bytes = MLKEM_PK_BYTES if rng.random() < 0.5 else MLKEM_CT_BYTES
                total_payload = base_payload + kem_bytes + MLDSA_SIG_BYTES
                n_frags = math.ceil(total_payload / max_payload_per_frag)
                pkt_size = mtu  # Each Sphinx packet in the train is formatted to MTU

            msg_frags_delivered[msg_id] = 0
            msg_linkable[msg_id] = True

            path = rng.sample(range(mix_nodes), hops)
            for f_idx in range(n_frags):
                # Check MTU violation per transmitted packet
                violations += pkt_size > mtu
                packet = Packet(
                    packet_id=next_packet_id,
                    msg_id=msg_id,
                    kind="normal",
                    size=pkt_size,
                    entry=path[0],
                    exit=path[-1],
                    enqueue_time=now,
                    frag_index=f_idx,
                    frag_total=n_frags,
                )
                next_packet_id += 1
                if online[path[0]]:
                    queues[path[0]].append(packet)

        # Cover packets (always single Sphinx packet)
        for _ in range(covers):
            path = rng.sample(range(mix_nodes), hops)
            pkt_size = base_payload + sphinx_overhead
            violations += pkt_size > mtu
            packet = Packet(
                packet_id=next_packet_id,
                msg_id=-1,
                kind="cover",
                size=pkt_size,
                entry=path[0],
                exit=path[-1],
                enqueue_time=now,
                frag_index=0,
                frag_total=1,
            )
            next_packet_id += 1
            if online[path[0]]:
                queues[path[0]].append(packet)

        # Each hop serves a bounded number of packets.
        for node, queue in enumerate(queues):
            if not online[node]:
                queue.clear()
                continue
            serving = queue[:capacity]
            del queue[:capacity]
            for packet in serving:
                if packet.hop + 1 >= hops:
                    if packet.kind == "normal":
                        mid = packet.msg_id
                        msg_frags_delivered[mid] += 1
                        if not (packet.entry in compromised and packet.exit in compromised):
                            msg_linkable[mid] = False
                        if msg_frags_delivered[mid] == packet.frag_total:
                            delivered += 1
                            delays.append(now - packet.enqueue_time + 1)
                            if msg_linkable[mid]:
                                linkable_delivered += 1
                    continue
                next_node = packet.exit if packet.hop + 1 == hops - 1 else rng.randrange(mix_nodes)
                if not online[next_node]:
                    continue
                packet.hop += 1
                queues[next_node].append(packet)

    dropped = generated - delivered
    total = generated
    return Result(
        load=load,
        churn=churn,
        mtu_violations=violations,
        generated=generated,
        delivered=delivered,
        dropped=dropped,
        delivery_rate=delivered / total if total else 0.0,
        p95_delay=percentile(delays, 0.95),
        entry_exit_linkability=(
            linkable_delivered / delivered if delivered else 0.0
        ),
    )


def write_svg(results: list[Result], output: Path) -> None:
    width, height = 900, 520
    margin = 70
    max_load = max(result.load for result in results)
    max_link = max(result.entry_exit_linkability for result in results) or 1.0
    churn_values = sorted({result.churn for result in results})
    colors = ["#0b7285", "#d9480f", "#5f3dc4", "#2b8a3e", "#c2255c"]

    def x(load: float) -> float:
        return margin + load / max_load * (width - 2 * margin)

    def y(value: float) -> float:
        return height - margin - value / max_link * (height - 2 * margin)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#fff"/>',
        '<text x="70" y="30" font-family="sans-serif" font-size="18" font-weight="bold">Empirical entry-exit linkability proxy</text>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="#333"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="#333"/>',
        f'<text x="{width/2-35}" y="{height-18}" font-family="sans-serif" font-size="13">offered load (packets/slot)</text>',
        f'<text x="15" y="{height/2}" transform="rotate(-90 15 {height/2})" font-family="sans-serif" font-size="13">proxy fraction</text>',
    ]
    for index, churn in enumerate(churn_values):
        points = [result for result in results if result.churn == churn]
        points.sort(key=lambda result: result.load)
        path = " ".join(f"{x(result.load):.1f},{y(result.entry_exit_linkability):.1f}" for result in points)
        color = colors[index % len(colors)]
        lines.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="3"/>')
        legend_x = width - 180
        legend_y = 55 + index * 22
        lines.append(f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x+22}" y2="{legend_y}" stroke="{color}" stroke-width="3"/>')
        lines.append(f'<text x="{legend_x+28}" y="{legend_y+5}" font-family="sans-serif" font-size="12">churn={churn:.2f}</text>')
    lines.append("</svg>")
    output.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/mixnet"))
    parser.add_argument("--seed", type=int, default=20260819)
    parser.add_argument("--slots", type=int, default=5000)
    parser.add_argument("--mix-nodes", type=int, default=30)
    parser.add_argument("--hops", type=int, default=3)
    parser.add_argument("--capacity", type=int, default=2)
    parser.add_argument("--compromised-fraction", type=float, default=0.2)
    parser.add_argument("--mtu", type=int, default=DEFAULT_MTU)
    parser.add_argument("--base-payload", type=int, default=DEFAULT_BASE_PAYLOAD)
    parser.add_argument("--sphinx-overhead", type=int, default=DEFAULT_SPHINX_OVERHEAD)
    parser.add_argument("--unsigned", action="store_true", help="Simulate unsigned baseline without ML-DSA signatures")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    is_signed = not args.unsigned
    for churn in (0.0, 0.1, 0.2, 0.3):
        for load in (1.0, 5.0, 10.0, 20.0, 40.0, 60.0):
            results.append(simulate(
                load=load,
                churn=churn,
                seed=args.seed + int(churn * 1000) + int(load * 100),
                slots=args.slots,
                mix_nodes=args.mix_nodes,
                hops=args.hops,
                capacity=args.capacity,
                compromised_fraction=args.compromised_fraction,
                cover_rate=load,
                mtu=args.mtu,
                base_payload=args.base_payload,
                sphinx_overhead=args.sphinx_overhead,
                signed=is_signed,
            ))

    csv_path = args.output_dir / "results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(Result.__dataclass_fields__)
        writer.writerows(result.__dict__.values() for result in results)
    write_svg(results, args.output_dir / "linkability.svg")

    sizes = packet_sizes(args.base_payload, args.sphinx_overhead, signed=is_signed)
    mode_str = "signed (Theorem 4.17 PCS, 4-packet Sphinx trains)" if is_signed else "unsigned baseline"
    print(f"mode: {mode_str}")
    print(f"packet sizes: {sizes} bytes; MTU: {args.mtu} bytes")
    print(f"MTU violations: {sum(result.mtu_violations for result in results)}")
    print(f"wrote {csv_path} and {args.output_dir / 'linkability.svg'}")


if __name__ == "__main__":
    main()
