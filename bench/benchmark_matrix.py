#!/usr/bin/env python3
"""benchmark_matrix.py - high-volume microbenchmarks + a scaling sweep.

Two parts:

1. Microbenchmarks (N=1000 iterations each across 9 operations -> 9000 timed
   samples) reporting p50/p95/p99/max latency and throughput.

2. Scaling sweep (12 chain sizes x 5 operations, median-of-3) reporting
   per-event cost, to prove the O(E log E) audit path and linear verify().

Deterministic; stdlib-only harness. Code under test is the frozen src/.
"""
import os
import sys
import time
import statistics

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from chain import BahiChain, receipt_payload, verify_receipt, h  # noqa: E402
from exporter import hint_flags, audit_report, export_csv  # noqa: E402
from loans import balances  # noqa: E402
from witness import sign_entry, is_valid_sig, generate_keypair, sign_entry_ed25519, ed25519_available  # noqa: E402

N_ITER = 1000
SIZES = [10, 100, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000]


def _chain_of(n):
    c = BahiChain("G-BENCH")
    t = "2026-08-02T10:00:00"
    for i in range(1, n + 1):
        c.add_event(i, "contribution" if i % 3 else "loan", "M%d" % (i % 997), 10000, t)
    return c


def _pct(sorted_samples, p):
    if not sorted_samples:
        return 0.0
    k = (len(sorted_samples) - 1) * p
    f = int(k)
    frac = k - f
    if f + 1 < len(sorted_samples):
        return sorted_samples[f] * (1 - frac) + sorted_samples[f + 1] * frac
    return sorted_samples[f]


def microbench(fn, n=N_ITER):
    """Time `fn()` n times, each iteration individually; return per-iteration
    seconds (perf_counter_ns for honest per-iteration percentiles)."""
    for _ in range(50):  # warm-up
        fn()
    samples = [0.0] * n
    for i in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples[i] = (time.perf_counter_ns() - t0) / 1e9
    return samples


def run_microbenchmarks():
    print("=" * 78)
    print("MICROBENCHMARKS  (N=%d iterations per op)" % N_ITER)
    print("=" * 78)
    c = _chain_of(500)
    c.close_meeting("M01", "t")
    root = c.root_for("M01")
    root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M01"}, "pass-Meera", "Meera"))
    root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M01"}, "pass-Laxmi", "Laxmi"))
    rec = receipt_payload("G-BENCH", "M01", root, "M1", chain=c)

    ops = [
        ("h() raw hash", lambda: h("GENESIS", "G", 1, "loan", "M", 100, "t")),
        ("add_event append", lambda: _add_one(c)),
        ("verify() 500 ev", c.verify),
        ("hint_flags 500 ev", lambda: hint_flags(c)),
        ("audit_report 500 ev", lambda: audit_report(c)),
        ("export_csv 500 ev", lambda: export_csv(c)),
        ("balances 500 ev", lambda: balances(c)),
        ("verify_receipt", lambda: verify_receipt(c, rec)),
        ("sign_entry (HMAC)", lambda: sign_entry({"root": "r", "meeting": "M"}, "p", "W")),
    ]
    if ed25519_available():
        kp = generate_keypair()
        ops.append(("sign_entry_ed25519", lambda: sign_entry_ed25519({"root": "r", "meeting": "M"}, kp["signing_key"], "W")))
        ops.append(("verify_ed25519", lambda: __import__("witness").verify_sig_ed25519(
            {"root": "r", "meeting": "M"}, sign_entry_ed25519({"root": "r", "meeting": "M"}, kp["signing_key"], "W")["sig"], kp["verify_key"])))

    total_samples = 0
    for name, fn in ops:
        samples = microbench(fn, N_ITER)
        total_samples += len(samples)
        s = sorted(samples)
        mean = sum(s) / len(s)
        print("%-22s  p50 %8.2f us  p95 %8.2f us  p99 %8.2f us  max %8.2f us  %10.0f op/s"
              % (name, _pct(s, .5) * 1e6, _pct(s, .95) * 1e6, _pct(s, .99) * 1e6,
                 s[-1] * 1e6, 1.0 / mean if mean else 0))
    print("microbenchmark samples: %d (across %d operations)" % (total_samples, len(ops)))
    return total_samples


def _add_one(c):
    n = len(c.events) + 1
    c.add_event(n, "contribution", "M%d" % (n % 997), 10000, "2026-08-02T10:00:00")
    return n


def run_scaling_sweep():
    print()
    print("=" * 78)
    print("SCALING SWEEP  (per-event cost vs chain size; median of 3)")
    print("=" * 78)
    hdr = "%-8s %-22s %-22s %-22s %-22s %-22s" % (
        "events", "verify", "hint_flags", "audit_report", "export_csv", "balances")
    print(hdr)
    total_samples = 0
    for n in SIZES:
        c = _chain_of(n)
        ops = [("verify", c.verify), ("hint_flags", lambda: hint_flags(c)),
               ("audit_report", lambda: audit_report(c)), ("export_csv", lambda: export_csv(c)),
               ("balances", lambda: balances(c))]
        row = ["%8d" % n]
        for _, fn in ops:
            best = None
            for _ in range(3):
                t0 = time.perf_counter()
                fn()
                dt = time.perf_counter() - t0
                best = dt if best is None or dt < best else best
            total_samples += 3
            per_ev = (best / n * 1e6) if n else 0
            row.append("%8.3f us/ev" % per_ev)
        print("%-8s %-22s %-22s %-22s %-22s %-22s" % tuple(row))
    print("scaling samples: %d (across %d sizes x 5 ops x 3 reps)" % (total_samples, len(SIZES)))
    return total_samples


def main():
    m = run_microbenchmarks()
    s = run_scaling_sweep()
    print()
    print("TOTAL benchmark samples: %d" % (m + s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
