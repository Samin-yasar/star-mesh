#!/usr/bin/env bash
# Generates mutants from the marker comments (*@M:...*) and runs ProVerif on each.
# Usage: ./run_mutations.sh      (run from the formal/ directory)
set -euo pipefail
OUT=${OUT:-mutants}
mkdir -p "$OUT"

echo "=== main models (expected results are in each file header) ==="
proverif pq_x3dh.pv | grep -E '^(RESULT|Query)' || true
proverif ratchet.pv | grep -E '^(RESULT|Query)' || true

echo "=== pq_x3dh: nokem  (Q1 must become TRUE) ==="
sed -E \
  -e 's/^.*@M:pqA1.*$/    let ssPQ1 = zero in/' \
  -e 's/^.*@M:pqA2.*$/    let ssPQ2 = zero in/' \
  -e 's/^.*@M:pqB1.*$/    let ssPQ1 = zero in/' \
  -e 's/^.*@M:pqB2.*$/    let ssPQ2 = zero in/' \
  pq_x3dh.pv > "$OUT/pq_x3dh_nokem.pv"
proverif "$OUT/pq_x3dh_nokem.pv" | grep -E '^RESULT' || true

echo "=== pq_x3dh: nosigma0  (Q3 must become FALSE) ==="
sed '/@M:sigma0check/d' pq_x3dh.pv > "$OUT/pq_x3dh_nosigma0.pv"
proverif "$OUT/pq_x3dh_nosigma0.pv" | grep -E '^RESULT' || true

echo "=== ratchet: unsigned  (healing must break against an active attacker) ==="
sed -e '/@M:aliceverify/d' -e '/@M:bobverify/d' ratchet.pv > "$OUT/ratchet_unsigned.pv"
proverif "$OUT/ratchet_unsigned.pv" | grep -E '^RESULT' || true

echo "=== ratchet: nostale  (Q3 must fail: replay of old signed proposal) ==="
sed '/@M:epoch/d' ratchet.pv > "$OUT/ratchet_nostale.pv"
proverif "$OUT/ratchet_nostale.pv" | grep -E '^RESULT' || true

echo "=== ratchet: rng  (Q2/Q3 must fail: seed_pq leaked) ==="
sed 's/(\*@M:rng_insert\*)/out(pub, seed_pq);/' ratchet.pv > "$OUT/ratchet_rng.pv"
proverif "$OUT/ratchet_rng.pv" | grep -E '^RESULT' || true
