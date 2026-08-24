from __future__ import annotations

import time
from typing import Callable, Dict, List, Tuple

from genesis_puzzle.addresses import (
    derive_standard_addresses,
    p2pkh_from_pubkey,
    p2wpkh_from_compressed_pubkey,
)
from genesis_puzzle.crypto import derive_pubkeys
from genesis_puzzle.hashing import sha256
from genesis_puzzle.parser import ParsedBlock


def _throughput(fn: Callable[[], object], iterations: int) -> Tuple[float, float]:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    rate = iterations / elapsed if elapsed > 0 else 0.0
    return elapsed, rate


def run_benchmark(block: ParsedBlock) -> List[str]:
    header = block.header.raw
    uncompressed, compressed = derive_pubkeys(1)

    measurements: Dict[str, Tuple[int, float, float]] = {}

    def bench(name: str, iterations: int, fn: Callable[[], object]) -> None:
        elapsed, rate = _throughput(fn, iterations)
        measurements[name] = (iterations, elapsed, rate)

    bench("SHA256(80-byte header)", 20000, lambda: sha256(header))
    bench("scalar-to-pubkey (coincurve, k=1)", 200, lambda: derive_pubkeys(1))
    bench("P2PKH(uncompressed G)", 4000, lambda: p2pkh_from_pubkey(uncompressed))
    bench("P2WPKH(compressed G)", 4000, lambda: p2wpkh_from_compressed_pubkey(compressed))

    def pipeline() -> None:
        pubs = derive_pubkeys(1)
        derive_standard_addresses(pubs[0], pubs[1])

    bench("full pipeline (k=1 -> three addresses)", 100, pipeline)

    lines = ["local throughput (measured, not hard-coded):"]
    for name, (iterations, elapsed, rate) in measurements.items():
        lines.append(f"  {name}: {iterations} iters in {elapsed:.4f}s -> {rate:.1f} /s")
    lines.append(
        "Stage A+B+C+D deterministic sequential/offline stages do not need pause/resume; "
        "these numbers are laptop-local."
    )
    return lines
