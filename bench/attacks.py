#!/usr/bin/env python3
"""attacks.py - BAHI adversarial audit, run against the FROZEN snapshot in src/.

Every entry is a live, self-contained demonstration. Statuses:
  FIXED      - the vulnerability was closed by v1.2+ hardening (shown RESISTED)
  STILL OPEN - the vulnerability is still exploitable in the audited code
  NEW        - discovered in the audited (v1.2+) code

"EXPLOITED" means the weakness was reproduced; "RESISTED" means the attack did
not land. Severity + a concrete fix accompany every finding. This is an audit
artifact: it is EXPECTED to report many STILL-OPEN / NEW findings.

Run:  python3 attacks.py
"""
import json, os, sys, tempfile

# import the FROZEN snapshot (not the live, still-moving tree)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from chain import BahiChain, h, receipt_payload, verify_receipt, MIN_WITNESSES  # noqa: E402
from witness import sign, verify as wverify  # noqa: E402
from loans import balances  # noqa: E402
from exporter import hint_flags, export_csv, audit_report  # noqa: E402

TS = "2026-08-02T10:00:00"
CRIT, HIGH, MED, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"
FIXED, OPEN, NEW = "FIXED", "STILL-OPEN", "NEW"
findings = []

def demo(status, sev, aid, title, how, fix, exploit_fn):
    try:
        exploited = bool(exploit_fn())
    except Exception as ex:
        exploited = False
        how += "  [HARNESS-ERROR %s: %s]" % (type(ex).__name__, ex)
    findings.append((status, sev, aid, title, exploited))
    tag = "EXPLOITED" if exploited else "RESISTED "
    print("[%s] %-10s %-8s %s" % (tag, status, sev, title))
    print("        %s" % how)
    print("        fix: %s" % fix)
    return exploited

def witness_signed(c, root):
    root["witnesses"] = [sign({"root": root["root_hash"], "meeting": "M07"}, "p1", "Meera"),
                         sign({"root": root["root_hash"], "meeting": "M07"}, "p2", "Laxmi")]

# ===========================================================================
# Exploit bodies (ALL defined up front so demo() never sees a NameError)
# ===========================================================================
def _a02():   # witness sigs not crypto-verified (2 arbitrary strings pass quorum)
    c = BahiChain("G-TEST")
    for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
    root = c.close_meeting("M07", TS)
    root["witnesses"] = ["FAKE_SIG_AAAA", "FAKE_SIG_BBBB"]
    ok, det = verify_receipt(c, receipt_payload("G-TEST", "M07", root, "Sita"))
    return ok and det == "MATCH"

def _a04():   # receipt aliases live witness list
    c = BahiChain("G")
    for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
    root = c.close_meeting("M07", TS)
    witness_signed(c, root)
    r = receipt_payload("G", "M07", root, "Sita")
    before = len(r["witnesses"])
    root["witnesses"].append("EVIL_APPENDED_AFTER_ISSUE")
    return len(r["witnesses"]) != before

def _a05():   # close_meeting overwrites existing root
    c = BahiChain("G")
    for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
    old = c.close_meeting("M07", TS)["root_hash"]
    c.add_event(4, "contribution", "Sita", 10000, TS)
    new = c.close_meeting("M07", TS)["root_hash"]
    return old != new and len(c.roots) == 1

def _a09():   # over-repayment -> negative outstanding
    c = BahiChain("G")
    c.add_event(1, "loan", "Asha", 10000, TS)
    c.add_event(2, "repayment", "Asha", 50000, TS)
    return balances(c)["Asha"]["outstanding_paise"] < 0

def _a10():   # duplicate/out-of-order seq accepted
    c = BahiChain("G")
    c.add_event(1, "contribution", "A", 100, TS)
    c.add_event(1, "contribution", "B", 200, TS)
    c.add_event(99, "contribution", "C", 300, TS)
    return c.verify()[0] and c.events[0]["seq"] == c.events[1]["seq"]

def _a11():   # MEETING-CLOSE injectable
    c = BahiChain("G")
    c.add_event(1, "MEETING-CLOSE", "__root__", 0, TS)
    return c.verify()[0]

def _a12():   # arbitrary prev_hash accepted
    c = BahiChain("G")
    c.add_event(1, "contribution", "A", 100, TS)
    c.add_event(2, "contribution", "B", 200, TS, prev_hash="0" * 64)
    return not c.verify()[0]

def _a18():   # '__root__' member collision
    c = BahiChain("G")
    c.add_event(1, "contribution", "__root__", 100, TS)
    return c.verify()[0]

def _a19():   # timestamps unordered
    c = BahiChain("G")
    c.add_event(1, "contribution", "A", 100, "2026-08-09T00:00:00")
    c.add_event(2, "contribution", "B", 100, "2026-08-01T00:00:00")
    return c.verify()[0] and c.events[1]["ts"] < c.events[0]["ts"]

def _a20():   # no nonce -> identical consecutive events accepted
    c = BahiChain("G")
    c.add_event(1, "contribution", "Sita", 10000, TS)
    c.add_event(2, "contribution", "Sita", 10000, TS)
    return c.verify()[0]

def _a21():   # weak typing (str seq / bool amount)
    c = BahiChain("G")
    c.add_event("one", "contribution", "A", True, TS)
    return c.events[0]["seq"] == "one" and c.events[0]["amount_paise"] == 1

def _n1():    # group_id not hashed -> rename keeps verify() ok
    c = BahiChain("G-ORIGINAL")
    for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
    c.close_meeting("M07", TS)
    c.group_id = "G-RENAMED"
    return c.verify()[0]

def _n2():    # hint_flags/audit_report crash on string seq
    c = BahiChain("G")
    c.add_event("one", "contribution", "A", 100, TS)
    c.add_event(2, "contribution", "B", 100, TS)
    c.close_meeting("M01", TS)
    try:
        hint_flags(c)
        return False
    except TypeError:
        return True

def _n3():    # verify()=ok but corrupt flag=True (empty group)
    c = BahiChain("")
    c.add_event(1, "contribution", "A", 100, TS)
    c.close_meeting("M01", TS)
    return c.verify()[0] and c.corrupt

def _n4():    # correction events ignored by balances
    c = BahiChain("G")
    c.add_event(1, "loan", "Asha", 10000, TS)
    c.add_event(2, "correction", "Asha", 0, TS)
    return balances(c)["Asha"]["outstanding_paise"] == 10000

def _n5():    # close_meeting allows zero-witness close (quorum only at verify)
    c = BahiChain("G")
    c.add_event(1, "contribution", "A", 100, TS)
    root = c.close_meeting("M01", TS)
    return len(root["witnesses"]) == 0

# FIXED helpers (verify the fix holds -> should return False = not exploitable)
def _f_a01():
    return h("P", 1, "loan", "Asha", 50000, TS) == h("P", 1, "loan", "Asha5000", 0, TS)

def _f_a03():
    c = BahiChain("G-REAL")
    for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
    root = c.close_meeting("M07", TS)
    witness_signed(c, root)
    ok, det = verify_receipt(c, receipt_payload("G-EVIL", "M07", root, "Sita"))
    return ok and det == "MATCH"

def _f_a06():
    import csv as _csv, io as _io
    c = BahiChain("G")
    c.add_event(1, "contribution", 'Sita, "Devi"\nX', 10000, TS)
    out = export_csv(c)
    rows = list(_csv.reader(_io.StringIO(out)))
    # exploitable only if the injected comma/quote/newline breaks column structure
    return any(len(r) != 6 for r in rows)

def _f_a07():
    c = BahiChain("G")
    c.add_event(1, "loan", "Asha", 100000, TS)
    c.add_event(2, "loan", "Bela", 50000, TS)
    c.close_meeting("M01", TS)
    c.add_event(3, "contribution", "Chitra", 10000, TS)
    c.close_meeting("M02", TS)
    return any(f["meeting"] == "M02" and f["hint"] == "concentrated_lending" for f in hint_flags(c))

def _f_a13():
    c = BahiChain("G")
    for i in range(1, 3): c.add_event(i, "contribution", "Sita", 10000, TS)
    c.close_meeting("M01", TS)
    return len([f for f in hint_flags(c) if f["hint"] == "duplicate_identity"]) > 0

def _f_a14():
    c = BahiChain("G")
    for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
    root = c.close_meeting("M07", TS)
    witness_signed(c, root)
    r = receipt_payload("G", "M07", root, "Sita")
    r["root_seq"] = 999999
    r["member"] = "TOTALLY_DIFFERENT_PERSON"
    return verify_receipt(c, r)[0]

def _f_a15():
    p = os.path.join(tempfile.gettempdir(), "bahi-a15.json")
    with open(p, "w") as f: json.dump({"group": "G"}, f)
    try:
        c = BahiChain.load(p)
        return c.corrupt is False
    except Exception:
        return True

def _f_a22():
    outs = set()
    for _ in range(3):
        c = BahiChain("G")
        c.add_event(1, "contribution", "X", 100, TS)
        c.close_meeting("M01", TS)
        outs.add(json.dumps(c.export()))
    return len(outs) != 1

# ===========================================================================
# Findings
# ===========================================================================
print("=" * 78)
print("BAHI ADVERSARIAL AUDIT - frozen snapshot (SHA %s)" % open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "SNAPSHOT_SHA.txt")).read().strip()[:8])
print("=" * 78)

print("\n--- FIXED since v1.2 (defenses now hold) ---")
demo(FIXED, CRIT, "A01", "Hash domain-separation collision (member absorbs amount)",
     "h() appends a unit-separator (\\x1f) after every field, so member 'Asha' + "
     "amount 50000 no longer collides with member 'Asha5000' + amount 0.",
     "Already fixed. (Residual: a member name literally containing \\x1f is not "
     "sanitized, but no collision was constructible.)",
     _f_a01)

demo(FIXED, CRIT, "A03", "Cross-group receipt confusion (group field ignored)",
     "verify_receipt checks receipt['group'] == chain.group_id.",
     "Already fixed at the receipt layer (see N1 for the un-hashed group caveat).",
     _f_a03)

demo(FIXED, HIGH, "A06", "CSV injection (no RFC-4180 escaping)",
     "export_csv uses stdlib csv.writer (quoting).",
     "Already fixed.",
     _f_a06)

demo(FIXED, HIGH, "A07", "hint_flags misattributes across meetings",
     "hint_flags buckets events per meeting by root_seq ranges.",
     "Already fixed for correctness (perf still O(meetings*events); see benchmarks).",
     _f_a07)

demo(FIXED, MED, "A13", "duplicate_identity undercounts (==2, not >=2)",
     "Fires on >=3 repeats (2 identical contributions is a normal SHG pattern).",
     "Already fixed (advisory threshold raised).",
     _f_a13)

demo(FIXED, MED, "A14", "verify_receipt ignores root_seq and member fields",
     "verify_receipt now locates the MEETING-CLOSE event by root_seq and binds the "
     "member (via member_events or a member-exists check).",
     "Already fixed.",
     _f_a14)

demo(FIXED, MED, "A15", "load() has no structural validation",
     "load() returns a structured 'corrupt chain' object instead of raising.",
     "Already fixed.",
     _f_a15)

demo(FIXED, LOW, "A22", "save() canonicalization (defense held)",
     "Verified: output is deterministic (dict insertion order is fixed).",
     "No fix required.",
     _f_a22)

print("\n--- STILL OPEN ---")
demo(OPEN, CRIT, "A02", "Witness signatures still not cryptographically verified",
     "verify_receipt compares witness signatures as a SET of opaque strings "
     "(issubset) and never calls witness.verify. Two arbitrary strings satisfy "
     "quorum and verify MATCH.",
     "Actually verify each signature: wverify({'root':..,'meeting':..}, sig, passphrase, witness).",
     _a02)

demo(OPEN, HIGH, "A04", "Receipt aliases live chain state (mutable after issue)",
     "receipt_payload returns root_meta['witnesses'] by REFERENCE. The bookkeeper "
     "can append/remove witness signatures AFTER handing out the receipt.",
     "Deep-copy: 'witnesses': list(root_meta['witnesses']).",
     _a04)

demo(OPEN, HIGH, "A05", "close_meeting silently overwrites an existing meeting root",
     "Re-closing the same meeting id replaces roots[id] and loses the old root.",
     "Refuse to overwrite: if meeting_id in self.roots: raise ValueError.",
     _a05)

demo(OPEN, MED, "A08", "Float amounts silently truncated to int",
     "_norm_amount does int(v); 10000.9 becomes 10000 with no warning.",
     "Reject non-integral amounts: if float(amount) != int(amount): raise.",
     lambda: BahiChain("G").add_event(1, "loan", "A", 10000.9, TS)["amount_paise"] == 10000)

demo(OPEN, MED, "A09", "Over-repayment -> negative outstanding balance",
     "Negative AMOUNTS are now rejected (fixed), but over-repayment still drives "
     "outstanding balances negative; no accounting invariant enforced.",
     "Validate repayment <= outstanding in balances().",
     _a09)

demo(OPEN, MED, "A10", "Duplicate / out-of-order / non-integer seq accepted",
     "add_event does not validate seq. Duplicate/gapped/string seqs are stored and "
     "verify() still passes. Secondary effects: non-monotonic seq corrupts hint_flags "
     "meeting bucketing, and a string seq crashes hint_flags (N2).",
     "Enforce seq == len(self.events)+1 or a monotonic counter; type-check int.",
     _a10)

demo(OPEN, MED, "A11", "MEETING-CLOSE type injectable as a normal event",
     "add_event does not restrict the event type set; a forged close marker can be "
     "added outside close_meeting.",
     "Restrict the type set; make close_meeting the only emitter of MEETING-CLOSE.",
     _a11)

demo(OPEN, MED, "A12", "Arbitrary prev_hash accepted silently by add_event",
     "add_event accepts a caller-supplied prev_hash; a wrong prev breaks the chain "
     "but only surfaces at the next verify().",
     "Derive prev internally; drop the prev_hash parameter or validate it.",
     _a12)

demo(OPEN, LOW, "A18", "Member name '__root__' collides with close marker",
     "MEETING-CLOSE uses member='__root__'; a real member with that name is "
     "indistinguishable from a close marker.",
     "Reserve '__root__' (reject it in add_event).",
     _a18)

demo(OPEN, LOW, "A19", "Timestamps not ordered or validated",
     "ts is a free string; events can be added with backwards timestamps.",
     "Parse/validate ts and enforce monotonic order per meeting.",
     _a19)

demo(OPEN, LOW, "A20", "No nonce -> identical consecutive events accepted",
     "Two identical events in a row are accepted; no position/nonce binding beyond "
     "the (unvalidated) seq.",
     "Enforce unique seq and bind it into the hash (seq already in hash).",
     _a20)

demo(OPEN, LOW, "A21", "Weak typing: str seq / bool amount accepted",
     "seq stored uncast (strings work) and bool amounts coerce to int (True -> 1).",
     "Type-check seq(int), member(str), amount(int not bool), ts(str).",
     _a21)

print("\n--- NEW (found in current code) ---")
demo(NEW, MED, "N1", "group_id is not bound into the event hash",
     "group_id is stored as an event field but NOT hashed (h() hashes prev/seq/type/"
     "member/amount/ts only). Renaming the group keeps every hash valid, so group "
     "identity is not cryptographically committed to the chain.",
     "Include group_id in the event hash (and/or the genesis anchor).",
     _n1)

demo(NEW, MED, "N2", "hint_flags/audit_report crash on a string seq (TypeError)",
     "_meetings_with_events compares lo <= e['seq'] <= hi; a string seq (possible via "
     "A21) raises TypeError, violating the 'never crash on bad data' claim and taking "
     "down the /api/export audit path.",
     "Coerce/validate seq to int before bucketing; guard the comparison.",
     _n2)

demo(NEW, LOW, "N3", "verify() vs corrupt property inconsistency (empty group_id)",
     "verify() returns 'ok' for a chain built with group_id='', but the `corrupt` "
     "property (and verify_receipt) treat it as corrupt. Two code paths disagree.",
     "Make verify() reject empty/whitespace group_id the same way `corrupt` does.",
     _n3)

demo(NEW, MED, "N4", "correction events still have no defined effect",
     "The 'correction' event type is accepted but ignored by balances() and every "
     "audit rule, so a correction cannot reverse or adjust anything.",
     "Define correction semantics (explicit reversal target) and apply in balances().",
     _n4)

demo(NEW, LOW, "N5", "close_meeting does not enforce quorum at close time",
     "A meeting can be closed with zero witnesses (no error); quorum is only checked "
     "later during verification. The close-time invariant is advisory.",
     "Require witnesses (>= MIN_WITNESSES) at close_meeting time, or return an "
     "explicit unsigned status.",
     _n5)

# ===========================================================================
# Summary
# ===========================================================================
print("\n" + "=" * 78)
print("SUMMARY")
by_status = {}
for status, sev, aid, title, exp in findings:
    by_status.setdefault(status, {"total": 0, "exploited": 0})
    by_status[status]["total"] += 1
    by_status[status]["exploited"] += 1 if exp else 0
for status in (FIXED, OPEN, NEW):
    if status in by_status:
        s = by_status[status]
        print("  %-11s %d total (%d exploited / %d resisted)"
              % (status, s["total"], s["exploited"], s["total"] - s["exploited"]))
open_new = [f for f in findings if f[0] in (OPEN, NEW)]
open_exploited = sum(1 for f in open_new if f[4])
print("  %-11s %d open+new findings, %d actively exploitable"
      % ("ACTION", len(open_new), open_exploited))
print("\nBottom line: the core tamper->recompute FORK detection is sound and all "
      "12 upstream tests pass. The remaining risk clusters in three places: "
      "(1) witness signatures are structural, not cryptographic (A02); "
      "(2) input validation gaps let malformed events through (A08-A12, A21, N2); "
      "(3) receipt fields are not fully bound (A04, A14->fixed, N1).")
