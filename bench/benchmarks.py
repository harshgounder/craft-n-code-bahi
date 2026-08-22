#!/usr/bin/env python3
"""benchmarks.py - BAHI performance + scaling benchmarks, against frozen src/.

Measures the real cost of the core operations at federation-relevant scale.
Pure stdlib. Timings are indicative of THIS machine, not portable absolutes.

Run:  python3 benchmarks.py

Sections:
  A. micro   - h() hash, add_event, witness sign/verify
  B. verify  - full-recompute O(N) scaling (1k .. 1M events)
  C. derived - balances(), export_csv() scaling
  D. hints   - hint_flags() meeting-count scaling (still O(meetings*events))
  E. io      - save()/load() round-trip, verify_receipt latency
  F. memory  - peak bytes to build + verify a chain (tracemalloc)
"""
import json, os, sys, tempfile, time, tracemalloc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from chain import BahiChain, h, receipt_payload, verify_receipt  # noqa: E402
from witness import sign, verify as wverify, derive_key  # noqa: E402
from loans import balances  # noqa: E402
from exporter import hint_flags, export_csv, audit_report  # noqa: E402

TS = "2026-08-02T10:00:00"

def sec(fn, *a, **k):
    t0 = time.perf_counter(); r = fn(*a, **k); return time.perf_counter() - t0, r

def build(n, meetings=1):
    """n events split across `meetings` close points. Returns chain."""
    c = BahiChain("G-BENCH")
    ev_per = n // meetings
    for m in range(meetings):
        base = m * ev_per
        for i in range(ev_per):
            seq = base + i + 1
            if i % 5 == 0:
                c.add_event(seq, "loan", "M%d" % (i % 100), 50000 + i, TS)
            elif i % 7 == 0:
                c.add_event(seq, "repayment", "M%d" % (i % 100), 10000 + i, TS)
            else:
                c.add_event(seq, "contribution", "M%d" % (i % 100), 1000 + (i % 50), TS)
        c.close_meeting("M%03d" % m, TS)
    return c

def fmt(n):
    if n >= 1e6: return "%.2fM" % (n / 1e6)
    if n >= 1e3: return "%.1fk" % (n / 1e3)
    return str(int(n))

print("=" * 72)
print("BAHI BENCHMARKS  (%s, Python %s)" % (sys.platform, sys.version.split()[0]))
print("=" * 72)

print("\n[A] MICRO")
N = 200_000
t, _ = sec(lambda: [h("P", i, "loan", "Asha", 50000, TS) for i in range(N)])
print("  h() hash                     %8.0f ops/s   (%s ops in %.3fs)" % (N / t, fmt(N), t))

N = 100_000
c = BahiChain("G-BENCH")
def appends():
    for i in range(N):
        c.add_event(i + 1, "contribution", "M%d" % (i % 50), 1000, TS)
t, _ = sec(appends)
print("  add_event append             %8.0f ev/s    (%s events in %.3fs)" % (N / t, fmt(N), t))

N = 20_000
t, _ = sec(lambda: [sign({"root": "x" * 64, "meeting": "M07"}, "pass-Meera", "Meera") for _ in range(N)])
print("  witness sign (HMAC)          %8.0f sig/s   (%s sigs in %.3fs)" % (N / t, fmt(N), t))
t, _ = sec(lambda: [wverify({"root": "x" * 64, "meeting": "M07"}, "s" * 64, "pass-Meera", "Meera") for _ in range(N)])
print("  witness verify (HMAC)        %8.0f ver/s   (%s verifs in %.3fs)" % (N / t, fmt(N), t))

print("\n[B] VERIFY (full recompute, O(N))")
for n in (1_000, 10_000, 100_000, 1_000_000):
    c = build(n)
    t, (ok, bad, why) = sec(c.verify)
    print("  verify(%s events)            %8.3fs   ok=%s" % (fmt(n), t, ok))

print("\n[C] DERIVED VIEWS")
for n in (1_000, 10_000, 100_000):
    c = build(n)
    t, _ = sec(balances, c)
    print("  balances(%s events)          %8.3fs" % (fmt(n), t))
    t, _ = sec(export_csv, c)
    print("  export_csv(%s events)        %8.3fs" % (fmt(n), t))

print("\n[D] HINT_FLAGS (meeting-scaling at FIXED event count; still O(M*E))")
E = 4000
for M in (1, 10, 50, 100, 200, 500):
    c = build(E, meetings=M)
    t, flags = sec(hint_flags, c)
    print("  hint_flags(events=%s, meetings=%3d)  %8.3fs   (%d flags)"
          % (fmt(E), M, t, len(flags)))

print("\n[E] IO")
c = build(100_000)
tmp = os.path.join(tempfile.gettempdir(), "bahi-bench.json")
t, _ = sec(c.save, tmp)
sz = os.path.getsize(tmp)
print("  save(100k events)            %8.3fs   (%s bytes + .bak)" % (t, fmt(sz)))
t, c2 = sec(BahiChain.load, tmp)
print("  load(100k events)            %8.3fs   (events=%d)" % (t, len(c2.events)))
root = c2.roots.get("M000")
r = receipt_payload("G-BENCH", "M000", root, "M0", chain=c2)
t, (ok, det) = sec(verify_receipt, c2, r)
print("  verify_receipt               %8.4fs   (%s)" % (t, det))
os.remove(tmp)

print("\n[F] MEMORY (tracemalloc, 500k events)")
tracemalloc.start()
c = build(500_000)
cur, peak = tracemalloc.get_traced_memory()
print("  build 500k events            peak %s MB" % fmt(peak / 1e6))
t, _ = sec(c.verify)
cur2, peak2 = tracemalloc.get_traced_memory()
print("  verify()                     %.3fs   peak %s MB" % (t, fmt(peak2 / 1e6)))
tracemalloc.stop()

print("\n" + "=" * 72)
print("DONE")
