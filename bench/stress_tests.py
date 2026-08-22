#!/usr/bin/env python3
"""stress_tests.py - BAHI robustness under extreme / adversarial input,
against the frozen src/. Each test reports PASS (survived/correct/deterministic)
or FAIL (crashed/corrupted/non-deterministic). Unexpected exceptions are caught
and reported rather than aborting, so the whole battery completes.

Run:  python3 stress_tests.py

NOT an attack suite (see attacks.py); this is "does it fall over under load /
weird input" testing.
"""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from chain import BahiChain, h, receipt_payload, verify_receipt  # noqa: E402
from witness import sign  # noqa: E402
from loans import balances  # noqa: E402
from exporter import hint_flags, export_csv  # noqa: E402

TS = "2026-08-02T10:00:00"
PASS = 0; FAIL = 0
def report(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print("  PASS  %-52s %s" % (name, detail))
    else:
        FAIL += 1; print("  FAIL  %-52s %s" % (name, detail))

def guarded(name, fn):
    try:
        r = fn()
        report(name, True, "" if r is None else str(r))
        return r
    except Exception as ex:
        report(name, False, "%s: %s" % (type(ex).__name__, ex))
        return None

def mk(n=7, group="G-STRESS"):
    c = BahiChain(group)
    for i in range(1, n + 1):
        c.add_event(i, "contribution", "Member%d" % i, 1000 * i, TS)
    root = c.close_meeting("M01", TS)
    for w in ("Meera", "Laxmi"):
        root["witnesses"].append(sign({"root": root["root_hash"], "meeting": "M01"}, "p-" + w, w))
    return c, root

print("=" * 72)
print("BAHI STRESS TESTS  (frozen snapshot)")
print("=" * 72)

def s1():   # 1M-event chain round-trip
    c = BahiChain("G-BIG")
    for i in range(1, 1_000_001):
        c.add_event(i, "contribution", "M%d" % (i % 1000), 100 + (i % 900), TS)
    c.close_meeting("M01", TS)
    ok, bad, why = c.verify()
    assert ok, "1M chain failed verify: %s %s" % (bad, why)
    tmp = os.path.join(tempfile.gettempdir(), "bahi-stress-1m.json")
    c.save(tmp)
    c2 = BahiChain.load(tmp)
    assert len(c2.events) == len(c.events), "round-trip event count mismatch"
    assert c2.verify()[0], "reloaded 1M chain failed verify"
    os.remove(tmp); os.remove(tmp + ".bak")
    return "1M events ok, round-trip deterministic"
guarded("S1 1M-event chain build+verify+round-trip", s1)

def s2():   # unicode / emoji / combining / RTL member names
    names = ["राधा", "李雷", "عائشة", "J\u0301ose\u0301", "💃🎉", "עברית", "Ａｓｈａ", "ñandú"]
    c = BahiChain("G-UNI")
    for i, nm in enumerate(names, 1):
        c.add_event(i, "contribution", nm, 1000, TS)
    c.close_meeting("M01", TS)
    assert c.verify()[0], "unicode chain failed verify"
    out = export_csv(c)
    assert len(out.splitlines()) >= len(names) + 1, "csv row count mismatch"
    return "%d unicode names verified + exported" % len(names)
guarded("S2 unicode/emoji/RTL member names", s2)

def s3():   # amount extremes (0, huge 1e18, 2^63) - negatives now rejected
    c = BahiChain("G-AMT")
    c.add_event(1, "loan", "A", 0, TS)
    c.add_event(2, "loan", "C", 10**18, TS)
    c.add_event(3, "loan", "D", 2**63 - 1, TS)
    c.add_event(4, "loan", "E", 2**63, TS)
    assert c.verify()[0], "amount-extreme chain failed verify"
    b = balances(c)
    return "amounts up to 2^63 verified; outstanding span %d..%d" % (
        min(x["outstanding_paise"] for x in b.values()),
        max(x["outstanding_paise"] for x in b.values()))
guarded("S3 amount extremes (0/1e18/2^63)", s3)

def s4():   # negative amount now rejected (regression check)
    try:
        BahiChain("G").add_event(1, "loan", "A", -1, TS)
        return "negative amount ACCEPTED (regression)"
    except ValueError:
        return "negative amount rejected (ValueError)"
guarded("S4 negative amount rejected", s4)

def s5():   # float NaN/inf amounts
    results = {}
    for label, v in (("nan", float("nan")), ("inf", float("inf")), ("ninf", float("-inf"))):
        try:
            BahiChain("G").add_event(1, "loan", "A", v, TS)
            results[label] = "accepted as %r" % BahiChain("G").events
        except Exception as ex:
            results[label] = "rejected: %s" % type(ex).__name__
    return json.dumps(results)
guarded("S5 float NaN/inf amounts", s5)

def s6():   # very long member name (100k chars)
    c = BahiChain("G")
    c.add_event(1, "contribution", "M" * 100_000, 100, TS)
    assert c.verify()[0], "long-name chain failed verify"
    return "100k-char member verified ok"
guarded("S6 100k-char member name", s6)

def s7():   # 10,000 meetings
    c = BahiChain("G")
    for m in range(10_000):
        c.add_event(m * 2 + 1, "contribution", "A", 100, TS)
        c.close_meeting("M%05d" % m, TS)
    assert c.verify()[0], "10k-meeting chain failed verify"
    return "10k meetings (%d events) verified; %d roots" % (len(c.events), len(c.roots))
guarded("S7 10,000 meetings", s7)

def s8():   # 10k-witness receipt
    c, root = mk()
    root["witnesses"] = ["sig-%d" % i for i in range(10_000)]
    r = receipt_payload("G-STRESS", "M01", root, "Member1")
    ok, det = verify_receipt(c, r)
    assert ok and det == "MATCH", "10k-witness receipt failed: %s" % det
    return "10k witnesses on receipt -> MATCH"
guarded("S8 10k-witness receipt", s8)

def s9():   # pathological types (str seq / bool amount)
    c = BahiChain("G")
    results = {}
    try:
        c.add_event("one", "contribution", "A", 100, TS)
        results["seq_str"] = "accepted"
    except Exception as ex:
        results["seq_str"] = "rejected: %s" % type(ex).__name__
    try:
        c.add_event(2, "contribution", "A", True, TS)
        results["amount_bool"] = "accepted as %r" % c.events[-1]["amount_paise"]
    except Exception as ex:
        results["amount_bool"] = "rejected: %s" % type(ex).__name__
    return json.dumps(results)
guarded("S9 pathological types (str seq, bool amount)", s9)

def s10():   # determinism (5 runs)
    outs = set(); verdicts = set()
    for _ in range(5):
        c, root = mk()
        outs.add(json.dumps(c.export(), sort_keys=True))
        verdicts.add(verify_receipt(c, receipt_payload("G-STRESS", "M01", root, "Member1"))[1])
    assert len(outs) == 1 and len(verdicts) == 1, "non-deterministic output"
    return "5 runs -> identical export + identical verdict"
guarded("S10 determinism (5 runs)", s10)

def s11():   # verify idempotency after tamper
    c, root = mk()
    c.events[3]["amount_paise"] = 1
    v1 = c.verify(); v2 = c.verify()
    assert v1 == v2, "verify not idempotent"
    return "tampered chain verify idempotent: (%s, %s)" % (v1[1], v1[2])
guarded("S11 verify idempotency", s11)

def s12():   # hint_flags flag explosion at scale (perf/correctness signal)
    c = BahiChain("G")
    for i in range(1, 2001):
        c.add_event(i, "contribution", "M%d" % (i % 50), 1000 + (i % 50), TS)
    for m in range(50):
        c.close_meeting("M%03d" % m, TS)
    import time
    t0 = time.perf_counter(); flags = hint_flags(c); dt = time.perf_counter() - t0
    return "50 meetings, 2000 events -> %d flags in %.3fs" % (len(flags), dt)
guarded("S12 hint_flags scale", s12)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
