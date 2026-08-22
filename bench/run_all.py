#!/usr/bin/env python3
"""run_all.py - run the whole BAHI battery and capture output to output/.

Usage:  python3 run_all.py

Runs attacks.py, stress_tests.py, benchmarks.py, attack_fuzz.py,
benchmark_matrix.py in order, echoes each to the terminal, and writes the raw
output to output/*.txt. Returns non-zero if stress_tests or attack_fuzz reports
any FAIL (attacks.py "EXPLOITED" is expected and does not fail the run).
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "output")
os.makedirs(OUT, exist_ok=True)

SUITES = [
    ("attacks.py", "attacks.txt", False),           # 25 findings, EXPLOITED is expected
    ("stress_tests.py", "stress.txt", True),        # 12 robustness probes
    ("benchmarks.py", "benchmarks.txt", False),     # throughput + scaling
    ("attack_fuzz.py", "fuzz.txt", True),           # 10k+ seeded fuzz probes
    ("benchmark_matrix.py", "bench_matrix.txt", False),  # 11k+ timed samples
]

exit_code = 0
for fname, outname, fail_on_nonzero in SUITES:
    path = os.path.join(HERE, fname)
    print("\n" + "=" * 78)
    print("RUNNING %s" % fname)
    print("=" * 78)
    r = subprocess.run([sys.executable, path], cwd=HERE, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    with open(os.path.join(OUT, outname), "w", encoding="utf-8") as f:
        f.write(r.stdout)
        if r.stderr:
            f.write("\n--- STDERR ---\n" + r.stderr)
    if fail_on_nonzero and r.returncode != 0:
        print("!! %s exited %d (FAIL)" % (fname, r.returncode))
        exit_code = 1
    else:
        print("-- %s exited %d" % (fname, r.returncode))

print("\nAll suites done. Output saved to %s" % OUT)
sys.exit(exit_code)
