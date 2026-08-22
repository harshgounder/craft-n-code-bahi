#!/usr/bin/env python3
"""tests.py - BAHI protocol tests. Each must PASS. Exit 0 = all green.
Pure stdlib. Covers: honest MATCH, 7 attack classes, determinism,
quorum enforcement, group binding, corrupt-file handling."""
import sys
from chain import BahiChain, receipt_payload, verify_receipt, MIN_WITNESSES
from witness import sign

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

def make_chain():
    c = BahiChain("G-RAJ-042")
    t = "2026-08-02T10:00:00"
    c.add_event(1, "contribution", "Sita", 10000, t)
    c.add_event(2, "contribution", "Geeta", 10000, t)
    c.add_event(3, "contribution", "Reema", 10000, t)
    c.add_event(4, "repayment", "Kavita", 10000, t)
    c.add_event(5, "loan", "Asha", 50000, t)
    c.add_event(6, "contribution", "Sita", 10000, t)
    c.add_event(7, "contribution", "Sita", 10000, t)
    root = c.close_meeting("M07", t)
    for w in ("Meera", "Laxmi"):
        root["witnesses"].append(sign({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    return c, root

def receipt(c, root):
    return receipt_payload("G-RAJ-042", "M07", root, "Sita", c)

t("honest chain -> MATCH", verify_receipt(*[make_chain()[0], receipt(*make_chain())])[0])

# 1. edit past amount
c, root = make_chain()
c.events[6]["amount_paise"] = 1000
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita", c))
t("edit past amount -> FORK", not ok and "event-hash-mismatch" in det, det)

# 2. delete event
c, root = make_chain()
del c.events[3]
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita", c))
t("delete event -> FORK", not ok and "FORK" in det, det)

# 3. reorder events
c, root = make_chain()
c.events[4], c.events[5] = c.events[5], c.events[4]
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita", c))
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
v1 = verify_receipt(c1, receipt_payload("G-RAJ-042", "M07", r1, "Sita", c1))
v2 = verify_receipt(c2, receipt_payload("G-RAJ-042", "M07", r2, "Sita", c2))
t("determinism -> identical verdicts", v1 == v2 and v1[0] is True, (v1, v2))

# 9. quorum: zero-witness close must FAIL (was MATCH before v1.2)
c = BahiChain("G-RAJ-042")
c.add_event(1, "contribution", "Sita", 10000, "t")
root0 = c.close_meeting("M1", "t", witnesses=[])
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M1", root0, "Sita", c))
t("zero-witness close -> quorum-fail", not ok and "quorum-fail" in det, det)

# 10. group binding: receipt for another group must FAIL (was MATCH)
c, root = make_chain()
ok, det = verify_receipt(c, receipt_payload("G-OTHER", "M07", root, "Sita", c))
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

# 12. delete the MEETING-CLOSE event but leave roots[] metadata (was MATCH)
c, root = make_chain()
r = receipt(c, root)
c.events.pop()                      # remove the MEETING-CLOSE event
ok, det = verify_receipt(c, r)
t("delete meeting-close -> meeting-close-missing",
  not ok and "meeting-close-missing" in det, det)

# 13. swap the member identity on a receipt (receipts are now member-bound)
c, root = make_chain()
r = receipt(c, root)
r["member"] = "Geeta"               # Sita's events claimed by Geeta
ok, det = verify_receipt(c, r)
t("swap member identity -> member-event-missing-or-tampered",
  not ok and "member-event" in det, det)

# 14. legacy receipt (no member_events) for a non-member must fail
c, root = make_chain()
legacy = {"group": "G-RAJ-042", "meeting": "M07", "root": root["root_hash"],
          "root_seq": root["root_seq"], "member": "Ghost",
          "witnesses": root["witnesses"]}
ok, det = verify_receipt(c, legacy)
t("non-member legacy receipt -> member-not-in-chain",
  not ok and "member-not-in-chain" in det, det)

print("\n%d/%d PASSED (%d failed)" % (PASS, PASS + FAIL, FAIL))
sys.exit(0 if FAIL == 0 else 1)