#!/usr/bin/env python3
"""tests.py - BAHI protocol tests. Each must PASS. Exit 0 = all green.
Pure stdlib. Covers: honest MATCH, attack classes, determinism, quorum,
group binding, corrupt-file handling, and the v1.3 hardening fixes."""
import sys
from chain import BahiChain, receipt_payload, verify_receipt, MIN_WITNESSES, h
from witness import sign_entry

PASS = 0
FAIL = 0

def t(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, detail))

def raises(name, exc, fn):
    try:
        fn()
        t(name, False, "no exception raised")
    except exc:
        t(name, True)
    except Exception as ex:
        t(name, False, "wrong exception: %s" % type(ex).__name__)

def make_chain():
    c = BahiChain("G-RAJ-042")
    ts = "2026-08-02T10:00:00"
    c.add_event(1, "contribution", "Sita", 10000, ts)
    c.add_event(2, "contribution", "Geeta", 10000, ts)
    c.add_event(3, "contribution", "Reema", 10000, ts)
    c.add_event(4, "repayment", "Kavita", 10000, ts)
    c.add_event(5, "loan", "Asha", 50000, ts)
    c.add_event(6, "contribution", "Sita", 10000, ts)
    c.add_event(7, "contribution", "Sita", 10000, ts)
    root = c.close_meeting("M07", ts)
    for w in ("Meera", "Laxmi"):
        root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    return c, root

def receipt(c, root):
    return receipt_payload("G-RAJ-042", "M07", root, "Sita")

t("honest chain -> MATCH", verify_receipt(*[make_chain()[0], receipt(*make_chain())])[0])

# 1. edit past amount
c, root = make_chain()
c.events[6]["amount_paise"] = 1000
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita"))
t("edit past amount -> FORK", not ok and "event-hash-mismatch" in det, det)

# 2. delete event
c, root = make_chain()
del c.events[3]
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita"))
t("delete event -> FORK", not ok and "FORK" in det, det)

# 3. reorder events
c, root = make_chain()
c.events[4], c.events[5] = c.events[5], c.events[4]
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita"))
t("reorder events -> FORK", not ok and "FORK" in det, det)

# 4. tamper meeting root while member already holds original receipt
c, root = make_chain()
r = receipt(c, root)
root["root_hash"] = "0" * 64
ok, det = verify_receipt(c, r)
t("tamper meeting root -> FORK", not ok and "FORK" in det, det)

# 5. witness removed from chain after receipt issued
c, root = make_chain()
r = receipt(c, root)
root["witnesses"] = [root["witnesses"][0]]
ok, det = verify_receipt(c, r)
t("missing witness sig -> quorum-fail", not ok and "quorum-fail" in det, det)

# 6. forged receipt root
c, root = make_chain()
r = receipt(c, root)
r["root"] = "f" * 64
ok, det = verify_receipt(c, r)
t("forged receipt root -> FORK", not ok and "FORK" in det, det)

# 7. ghost meeting id
c, root = make_chain()
ok, det = verify_receipt(c, {"group": "G-RAJ-042", "meeting": "M99", "root": "0"*64, "witnesses": []})
t("ghost meeting -> meeting-root-missing", not ok and "meeting-root-missing" in det, det)

# 8. determinism: two identical chains give identical verdicts
c1, r1 = make_chain()
c2, r2 = make_chain()
v1 = verify_receipt(c1, receipt_payload("G-RAJ-042", "M07", r1, "Sita"))
v2 = verify_receipt(c2, receipt_payload("G-RAJ-042", "M07", r2, "Sita"))
t("determinism -> identical verdicts", v1 == v2 and v1[0] is True, (v1, v2))

# 9. quorum: zero-witness close must FAIL
c = BahiChain("G-RAJ-042")
c.add_event(1, "contribution", "Sita", 10000, "t")
root0 = c.close_meeting("M1", "t", witnesses=[])
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M1", root0, "Sita"))
t("zero-witness close -> quorum-fail", not ok and "quorum-fail" in det, det)

# 10. group binding: receipt for another group must FAIL
c, root = make_chain()
ok, det = verify_receipt(c, receipt_payload("G-OTHER", "M07", root, "Sita"))
t("wrong group receipt -> group-mismatch", not ok and "group-mismatch" in det, det)

# 11. corrupt chain file: load must not raise, verify reports corruption
import json, tempfile, os
c, root = make_chain()
d = c.export()
del d["events"][2]["prev"]
fp = tempfile.mktemp(suffix=".json")
with open(fp, "w") as f:
    json.dump(d, f)
c2 = BahiChain.load(fp)
ok, det = verify_receipt(c2, receipt(c, root))
t("corrupt chain -> structured fail (no crash)", not ok and ("corrupt" in det or "FORK" in det), det)
os.unlink(fp)

# 12. delete the MEETING-CLOSE event but keep roots[] metadata
c, root = make_chain()
r12 = receipt_payload("G-RAJ-042", "M07", root, "Sita")
c.events = [e for e in c.events if e.get("type") != "MEETING-CLOSE"]
ok, det = verify_receipt(c, r12)
t("delete MEETING-CLOSE -> meeting-close-missing", not ok and "meeting-close-missing" in det, det)

# 13. append a fake entry AFTER the close event (hand-edited file: add_event
#     now blocks this at write time, but a tampered file can still smuggle it)
c, root = make_chain()
r13 = receipt_payload("G-RAJ-042", "M07", root, "Sita")
ghost = {"seq": 9, "group": "G-RAJ-042", "type": "contribution", "member": "Ghost",
         "amount_paise": 10000, "ts": "2026-08-02T10:00:00", "prev": c.events[-1]["hash"]}
ghost["hash"] = h(ghost["prev"], "G-RAJ-042", 9, "contribution", "Ghost", 10000, "2026-08-02T10:00:00")
c.events.append(ghost)
ok, det = verify_receipt(c, r13)
t("append after close -> events-after-close", not ok and "events-after-close" in det, det)

# 14. member binding: a CONSISTENT rewrite (attacker re-links all hashes) is
#     caught only by the member receipt binding
c, root = make_chain()
r14 = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
c.events[0]["amount_paise"] = 5000
prev = h("GENESIS", c.group_id)
for ev in c.events:
    ev["prev"] = prev
    ev["hash"] = h(ev["prev"], c.group_id, ev["seq"], ev["type"], ev["member"], ev["amount_paise"], ev["ts"])
    prev = ev["hash"]
ok, det = verify_receipt(c, r14)
t("consistent rewrite caught by member binding -> member-event-missing-or-tampered",
  not ok and "member-event-missing-or-tampered" in det, det)

# 15. member binding: receipt bound to a member with no events fails
c, root = make_chain()
r15 = receipt_payload("G-RAJ-042", "M07", root, "Nobody", chain=c)
ok, det = verify_receipt(c, r15)
t("member with no events -> member-not-in-chain", not ok and "member-" in det, det)

# ---------------------------------------------------------------- v1.3 fixes
# 16. duplicate seq rejected (A10/A20)
c = BahiChain("G")
c.add_event(1, "contribution", "A", 100, "t")
raises("duplicate seq rejected", ValueError, lambda: c.add_event(1, "contribution", "B", 200, "t"))

# 17. out-of-order seq rejected (A10)
c = BahiChain("G")
c.add_event(1, "contribution", "A", 100, "t")
raises("out-of-order seq rejected", ValueError, lambda: c.add_event(99, "contribution", "C", 300, "t"))

# 18. string / bool seq rejected (A21)
raises("string seq rejected", ValueError, lambda: BahiChain("G").add_event("one", "contribution", "A", 100, "t"))
raises("bool seq rejected", ValueError, lambda: BahiChain("G").add_event(True, "contribution", "A", 100, "t"))

# 19. float amount truncation rejected (A08)
raises("float amount rejected", ValueError, lambda: BahiChain("G").add_event(1, "loan", "A", 10000.9, "t"))

# 20. bool amount rejected (A21)
raises("bool amount rejected", ValueError, lambda: BahiChain("G").add_event(1, "loan", "A", True, "t"))

# 21. MEETING-CLOSE injection rejected (A11)
raises("MEETING-CLOSE injection rejected", ValueError, lambda: BahiChain("G").add_event(1, "MEETING-CLOSE", "__root__", 0, "t"))

# 22. reserved member '__root__' rejected (A18)
raises("__root__ member rejected", ValueError, lambda: BahiChain("G").add_event(1, "contribution", "__root__", 100, "t"))

# 23. re-closing a meeting rejected (A05)
def _reclose():
    c = BahiChain("G"); c.add_event(1, "contribution", "A", 100, "t")
    c.close_meeting("M01", "t"); c.close_meeting("M01", "t")
raises("re-close meeting rejected", ValueError, _reclose)

# 24. group rename detected (N1)
c = BahiChain("G-ORIG")
c.add_event(1, "contribution", "Sita", 10000, "t")
c.close_meeting("M07", "t")
c.group_id = "G-RENAMED"
t("group rename -> verify fails", not c.verify()[0], c.verify()[2])

# 25. empty group rejected at write + verify (N3)
raises("empty group add_event rejected", ValueError, lambda: BahiChain("").add_event(1, "contribution", "A", 100, "t"))
t("empty group verify -> corrupt", BahiChain("").verify()[0] is False and BahiChain("").corrupt)

# 26. over-repayment clamped, excess surfaced (A09)
from loans import balances
c = BahiChain("G"); c.add_event(1, "loan", "Asha", 10000, "t"); c.add_event(2, "repayment", "Asha", 50000, "t")
b = balances(c)["Asha"]
t("over-repayment -> outstanding clamped >= 0", b["outstanding_paise"] == 0 and b["over_repaid_paise"] == 40000, b)

# 27. correction reduces outstanding (N4)
c = BahiChain("G"); c.add_event(1, "loan", "Asha", 10000, "t"); c.add_event(2, "correction", "Asha", 3000, "t")
b = balances(c)["Asha"]
t("correction -> outstanding reduced", b["outstanding_paise"] == 7000, b)

# 28. arbitrary witness strings rejected (A02)
c = BahiChain("G")
for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, "t")
root = c.close_meeting("M07", "t")
root["witnesses"] = ["FAKE_SIG_AAAA", "FAKE_SIG_BBBB"]
ok, det = verify_receipt(c, receipt_payload("G", "M07", root, "Sita"))
t("arbitrary witness strings -> quorum-fail", not ok and "quorum-fail" in det, det)

# 29. witness crypto verification: correct keys -> MATCH (A02)
c, root = make_chain()
r29 = receipt(c, root)
ok, det = verify_receipt(c, r29, witness_keys={"Meera": "pass-Meera", "Laxmi": "pass-Laxmi"})
t("witness crypto verify (correct keys) -> MATCH", ok and det == "MATCH", det)

# 30. witness crypto verification: wrong key -> invalid (A02)
c, root = make_chain()
r30 = receipt(c, root)
ok, det = verify_receipt(c, r30, witness_keys={"Meera": "WRONG", "Laxmi": "pass-Laxmi"})
t("witness crypto verify (wrong key) -> invalid", not ok and "witness-signature-invalid" in det, det)

# 31. receipt is a deep copy (A04): mutating the chain does not rewrite it
c, root = make_chain()
r31 = receipt(c, root)
before = len(r31["witnesses"])
root["witnesses"].append({"witness": "EVIL", "sig": "0" * 64})
t("receipt deep copy (A04)", len(r31["witnesses"]) == before, "aliased: %d -> %d" % (before, len(r31["witnesses"])))

print("\n%d/%d PASSED (%d failed)" % (PASS, PASS + FAIL, FAIL))
sys.exit(0 if FAIL == 0 else 1)
