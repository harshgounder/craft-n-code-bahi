#!/usr/bin/env python3
"""tests.py - BAHI protocol tests. Each must PASS. Exit 0 = all green.
Pure stdlib. Covers: honest MATCH, 7 attack classes, determinism,
quorum enforcement, group binding, corrupt-file handling."""
import sys
from chain import BahiChain, receipt_payload, verify_receipt, MIN_WITNESSES
from witness import sign_entry, new_key

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
    payload = {"root": root["root_hash"], "meeting": "M07"}
    root["witnesses"] = [sign_entry(payload, new_key(), w) for w in ("Meera", "Laxmi")]
    return c, root

def receipt(c, root):
    return receipt_payload("G-RAJ-042", "M07", root, "Sita")

c, root = make_chain()
ok, det = verify_receipt(c, receipt(c, root))
t("honest chain -> MATCH", ok and det == "MATCH", det)

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

# 9. quorum: zero-witness close must FAIL (was MATCH before v1.2)
c = BahiChain("G-RAJ-042")
c.add_event(1, "contribution", "Sita", 10000, "t")
root0 = c.close_meeting("M1", "t", witnesses=[])
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M1", root0, "Sita"))
t("zero-witness close -> quorum-fail", not ok and "quorum-fail" in det, det)

# 10. group binding: receipt for another group must FAIL (was MATCH)
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

# 12. delete the MEETING-CLOSE event but keep roots[] metadata (PR2 gap A)
c, root = make_chain()
r12 = receipt_payload("G-RAJ-042", "M07", root, "Sita")
c.events = [e for e in c.events if e.get("type") != "MEETING-CLOSE"]
ok, det = verify_receipt(c, r12)
t("delete MEETING-CLOSE -> meeting-close-missing", not ok and "meeting-close-missing" in det, det)

# 13. append a fake entry AFTER the close event (PR2 gap C)
c, root = make_chain()
r13 = receipt_payload("G-RAJ-042", "M07", root, "Sita")
c.add_event(99, "contribution", "Ghost", 10000, "2026-08-02T10:00:00")
ok, det = verify_receipt(c, r13)
t("append after close -> events-after-close", not ok and "events-after-close" in det, det)

# 14. member binding: a CONSISTENT rewrite (attacker re-links all hashes so
# the chain still verifies) is caught only by the member receipt binding
from chain import h
c, root = make_chain()
r14 = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
c.events[0]["amount_paise"] = 5000   # Sita's first contribution edited
prev = h("GENESIS", c.group_id)
for ev in c.events:                  # attacker re-links the whole chain
    ev["prev"] = prev
    ev["hash"] = h(ev["prev"], ev["seq"], ev["type"], ev["member"], ev["amount_paise"], ev["ts"])
    prev = ev["hash"]
ok, det = verify_receipt(c, r14)
t("consistent rewrite caught (close-hash recompute fires first)",
  not ok and ("member-event-missing-or-tampered" in det or "close hash recompute" in det), det)

# 15. member binding: receipt bound to a member with no events fails
c, root = make_chain()
r15 = receipt_payload("G-RAJ-042", "M07", root, "Nobody", chain=c)
ok, det = verify_receipt(c, r15)
t("member with no events -> member-no-events-or-missing",
  not ok and ("member-" in det), det)

# 16. THE PR9 CRITICAL: close-swap + ghost insert + reclose at SAME seq.
#     Attacker keeps Sita's events byte-identical, injects a ghost
#     contribution, replaces the close at the original seq, relinks all.
from chain import h as _h
c, root = make_chain()
r16 = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
orig = root["root_seq"]
c2 = BahiChain("G-RAJ-042")
c2.roots = dict(c.roots)                                   # stale metadata kept
c2.events = [dict(e) for e in c.events]
c2.events = [e for e in c2.events if not (e["type"] == "MEETING-CLOSE" and e["seq"] == orig)]
ghost = {"seq": 99, "type": "contribution", "member": "Ghost", "amount_paise": 10000000,
         "ts": "2026-08-02T10:00:00", "group": "G-RAJ-042", "prev": c2.events[-1]["hash"],
         "hash": _h(c2.events[-1]["hash"], 99, "contribution", "Ghost", 10000000, "2026-08-02T10:00:00")}
c2.events.append(ghost)
nc = {"seq": orig, "type": "MEETING-CLOSE", "member": "__root__", "amount_paise": 0,
      "ts": "2026-08-02T10:00:00", "group": "G-RAJ-042", "prev": ghost["hash"],
      "hash": _h(ghost["hash"], orig, "MEETING-CLOSE", "__root__", 0, "2026-08-02T10:00:00")}
c2.events.append(nc)
okc, _, _ = c2.verify()
ok, det = verify_receipt(c2, r16)
t("close-swap+ghost (PR9 critical) -> FORK via close-hash recompute",
  okc and not ok and "close hash recompute" in det, det)

# ---- security-hardening regression tests (v1.3) ----
from chain import MAX_AMOUNT_PAISE
from exporter import hint_flags, export_csv
from loans import balances, format_rupees
from witness import sign as _wsign, verify as _wverify

# 17. quorum must count DISTINCT signatures (one sig duplicated twice must
#     NOT satisfy the two-witness requirement)
c, root = make_chain()
root["witnesses"] = [root["witnesses"][0], dict(root["witnesses"][0])]
ok, det = verify_receipt(c, receipt_payload("G-RAJ-042", "M07", root, "Sita"))
t("duplicate witness sig -> quorum-fail (unique count)", not ok and "quorum-fail" in det, det)

# 18. witness keys are randomly generated, distinct, and not from source
t("witness keys are distinct random keys", new_key() != new_key())

# 19. witness signature is cryptographically verified: swapping a key in the
#     chain (keeping the sig) breaks verification
c, root = make_chain()
r = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
for w in root["witnesses"]:
    if w["name"] == "Meera":
        w["key"] = new_key()          # substitute a different key
ok, det = verify_receipt(c, r)
t("witness key tampered -> witness-signature-invalid", not ok and "invalid" in det, det)

# 20. h() delimiter ambiguity fixed (field containing the delimiter no longer collides)
t("h() delimiter ambiguity fixed", h("A" + chr(31), "B") != h("A", chr(31) + "B"))

# 21. h() type confusion fixed (int 1 vs str '1' vs bool True all distinct)
t("h() type confusion fixed", h(1) != h("1") and h(1) != h(True))

# 22. genesis anchored: floating first-event prev is detected even when re-hashed
c, root = make_chain()
c.events[0]["prev"] = h("GENESIS", "OTHER")
c.events[0]["hash"] = h(c.events[0]["prev"], c.events[0]["seq"], c.events[0]["type"],
                       c.events[0]["member"], c.events[0]["amount_paise"], c.events[0]["ts"])
ok, bad_seq, why = c.verify()
t("genesis anchored -> prev-hash-mismatch", not ok and "prev-hash-mismatch" in why, why)

# 23. event group field bound: tampered group is a corruption verdict
c, root = make_chain()
c.events[0]["group"] = "G-EVIL"
ok, bad_seq, why = c.verify()
t("event group field mismatch -> corrupt-file", not ok and "group mismatch" in why, why)

# 24. reserved meeting id rejected (was a corrupt-chain sentinel collision)
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, "t")
try:
    c.close_meeting("__corrupt__", "t")
    t("reserved meeting_id -> rejected", False, "no exception")
except ValueError:
    t("reserved meeting_id -> rejected", True)

# 25. corruption tracked in a dedicated attribute (not a roots sentinel):
#     loading a malformed file sets _corrupt without polluting roots
import json as _json, tempfile as _tf, os as _os
fp = _tf.mktemp(suffix=".json")
with open(fp, "w") as f:
    f.write("{not json")
c = BahiChain.load(fp)
t("corrupt load uses _corrupt attr (no sentinel in roots)",
  c.corrupt and "__corrupt__" not in c.roots and c._corrupt is not None)
_os.unlink(fp)

# 26. event type must be a known enum (case/spelling spoof rejected)
c = BahiChain("G")
try:
    c.add_event(1, "Loan", "Sita", 10000, "t")
    t("invalid event type -> rejected", False, "no exception")
except ValueError:
    t("invalid event type -> rejected", True)

# 27. whitespace-only member rejected
c = BahiChain("G")
try:
    c.add_event(1, "contribution", "   ", 10000, "t")
    t("whitespace-only member -> rejected", False, "no exception")
except ValueError:
    t("whitespace-only member -> rejected", True)

# 28. control-char member rejected (delimiter/control byte in a name)
c = BahiChain("G")
try:
    c.add_event(1, "contribution", "Sita" + chr(31), 10000, "t")
    t("control-char member -> rejected", False, "no exception")
except ValueError:
    t("control-char member -> rejected", True)

# 29. duplicate seq rejected
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, "t")
try:
    c.add_event(1, "loan", "Asha", 50000, "t")
    t("duplicate seq -> rejected", False, "no exception")
except ValueError:
    t("duplicate seq -> rejected", True)

# 30. non-positive / non-integer seq rejected
for bad_seq in (0, -1, "1", 1.5, True):
    c = BahiChain("G")
    try:
        c.add_event(bad_seq, "contribution", "Sita", 10000, "t")
        t("bad seq %r -> rejected" % bad_seq, False, "no exception")
    except ValueError:
        t("bad seq %r -> rejected" % bad_seq, True)

# 31. amount above bound and bool amount rejected
c = BahiChain("G")
try:
    c.add_event(1, "contribution", "Sita", MAX_AMOUNT_PAISE + 1, "t")
    t("amount above bound -> rejected", False, "no exception")
except ValueError:
    t("amount above bound -> rejected", True)
c = BahiChain("G")
try:
    c.add_event(1, "contribution", "Sita", True, "t")
    t("bool amount -> rejected", False, "no exception")
except ValueError:
    t("bool amount -> rejected", True)

# 32. NFC normalization: combining-accent form maps to the precomposed form
c = BahiChain("G")
c.add_event(1, "contribution", "Se\u0301ta", 10000, "t")   # e + combining acute
t("NFC normalization maps combining to precomposed", c.events[0]["member"] == "S\u00e9ta", c.events[0]["member"])

# 33. receipt witnesses are deep-copied, not aliased to live chain metadata
c, root = make_chain()
r = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
before = len(r["witnesses"])
root["witnesses"].append({"name": "Evil", "key": "0" * 64, "sig": "0" * 64})
t("receipt witnesses deep-copied (not aliased)", before == 2 and len(r["witnesses"]) == 2, len(r["witnesses"]))

# 34. balances() is safe on a malformed event (never crashes)
c, root = make_chain()
c.events[0]["member"] = None
try:
    b = balances(c)
    t("balances safe on malformed event (no crash)", isinstance(b, dict))
except Exception as e:
    t("balances safe on malformed event (no crash)", False, "%s: %s" % (type(e).__name__, e))

# 35. format_rupees is integer-exact (no float precision loss)
t("format_rupees integer-exact", format_rupees(123456) == "Rs 1234.56", format_rupees(123456))

# 36. CSV formula injection neutralized
c = BahiChain("G")
c.add_event(1, "contribution", "=1+1", 10000, "t")
c.close_meeting("M1", "t")
import csv as _csv, io as _io
rows = list(_csv.reader(_io.StringIO(export_csv(c))))
t("CSV formula injection neutralized", rows[1][2].startswith("'="), rows[1][2])

# 37. hint_flags is safe on a malformed event (never crashes)
c, root = make_chain()
c.events[0].pop("member")
try:
    flags = hint_flags(c)
    t("hint_flags safe on malformed event (no crash)", isinstance(flags, list))
except Exception as e:
    t("hint_flags safe on malformed event (no crash)", False, "%s: %s" % (type(e).__name__, e))

# 38. cross-meeting repayment is NOT a false arithmetic_mismatch (whole-chain net)
c = BahiChain("G")
c.add_event(1, "loan", "Kavita", 20000, "t")
c.close_meeting("M06", "t")
c.add_event(3, "repayment", "Kavita", 20000, "t")
c.close_meeting("M07", "t")
t("cross-meeting repayment -> no arithmetic_mismatch FP",
  not any(f["hint"] == "arithmetic_mismatch" for f in hint_flags(c)))

print("\n%d/%d PASSED (%d failed)" % (PASS, PASS + FAIL, FAIL))
sys.exit(0 if FAIL == 0 else 1)