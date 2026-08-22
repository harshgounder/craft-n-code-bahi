#!/usr/bin/env python3
"""run_all.py - BAHI ATTACK SUITE: run every attack matrix + fuzz + bench.
Usage: python3 attack/run_all.py [fuzz-iters] [seed]
Exit 0 = every expectation met. Writes attack/results.json.
"""
import importlib, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

MODULES = ["t_chain", "t_receipt", "t_witness", "t_loans", "t_exporter", "t_server", "t_v2", "t_stress", "fuzz", "bench"]


def main():
    t0 = time.time()
    all_rows = []
    summaries = {}
    failures = []
    for name in MODULES:
        print("\n=== %s ===" % name)
        mod = importlib.import_module(name)
        rows = mod.run()
        if name == "bench":
            summaries[name] = {"bench": rows}
            print("  benchmarks: %d metrics captured" % len(rows))
            continue
        all_rows.extend(rows)
        ok = sum(1 for _, o, _ in rows if o)
        fail = len(rows) - ok
        print("  %s: %d cases, %d ok, %d failed" % (name, len(rows), ok, fail))
        for tid, o, detail in rows:
            if not o:
                failures.append((tid, detail))
    # global stats
    vuln_c = sum(1 for tid, o, _ in all_rows if tid.startswith("VULN.") and o)
    safe_b = sum(1 for tid, o, _ in all_rows if tid.startswith("SAFE.") and not o)
    print("\n=== SUMMARY ===")
    print("total cases : %d" % len(all_rows))
    print("VULN confirmed (flaws reproduced): %d" % vuln_c)
    print("SAFE broken (defense failed): %d" % safe_b)
    print("failed expectations: %d" % len(failures))
    for tid, detail in failures[:40]:
        print("  FAIL %s :: %s" % (tid, detail[:160]))
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "total": len(all_rows), "vuln_confirmed": vuln_c, "safe_broken": safe_b,
           "failed": len(failures), "benchmarks": next((s["bench"] for s in summaries.values() if "bench" in s), {}),
           "rows": [{"tid": t, "ok": o, "detail": d} for t, o, d in all_rows]}
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("results -> attack/results.json (%.1fs)" % (time.time() - t0))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()