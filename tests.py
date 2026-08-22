#!/usr/bin/env python3
"""tests.py - BAHI attack scenarios. Each test must PASS (detect the attack).
Exit 0 = all green. Deterministic, pure stdlib."""
import sys
from chain import BahiChain, receipt_payload, verify_receipt
from witness import sign

PASS = 0

def t(name, cond, detail=""):
    global PASS
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        print(f"  FAIL {name} {detail}")
        sys.exit(1)

def make_chain(witnesses=("Meera", "Laxmi")):
    c = BahiChain("G-TEST")
    for i in range(1, 8):
        c.add_event(i, "contribution", "Sita", 10000, "2026-08-02T10:00:00")
    root = c.close_meeting("M07", "2026-08-02T10:00:00")
    sigs = []
    for w in witnesses:
        sigs.append(sign({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    root["witnesses"] = sigs
    return c, root

def receipt(c, root, member="Sita"):
    return receipt_payload("G-TEST", "M07", root, member)

# 1. honest chain verifies
c, root = make_chain()
ok, det = verify_receipt(c, receipt(c, root))
t("honest chain -> MATCH", ok and det == "MATCH", det)

# 2. edit amount (the classic Rs 100 -> Rs 10)
c, root = make_chain()
c.events[6]["amount_paise"] = 1000
ok, det = verify_receipt(c, receipt(c, root))
t("edit past amount -> FORK", not ok and "FORK" in det, det)

# 3. delete an event
c, root = make_chain()
del c.events[2]
ok, det = verify_receipt(c, receipt(c, root))
t("delete event -> FORK", not ok and "FORK" in det, det)

# 4. reorder two events (swap seq + amounts)
c, root = make_chain()
c.events[3], c.events[4] = c.events[4], c.events[3]
ok, det = verify_receipt(c, receipt(c, root))
t("reorder events -> FORK", not ok and "FORK" in det, det)

# 5. change the meeting root itself (root metadata tampered on the chain FILE,
#    while the member ALREADY holds the original receipt)
c, root = make_chain()
r = receipt(c, root)                        # member's printed receipt (original)
root["root_hash"] = "0" * 64                # bookkeeper tampers the chain file
ok, det = verify_receipt(c, r)
t("tamper meeting root -> FORK", not ok and "FORK" in det, det)

# 6. witness signature missing on the checked chain (bookkeeper claims only
#    one witness signed; the member's receipt still lists both)
c, root = make_chain()
r = receipt(c, root)                        # member's receipt (two witnesses)
root["witnesses"] = [root["witnesses"][0]]   # chain file claims only W1 signed
ok, det = verify_receipt(c, r)
t("missing witness sig -> witness-signature-differs",
  not ok and "witness-signature" in det, det)

# 7. receipt forged with a different root
c, root = make_chain()
bad_receipt = dict(receipt(c, root))
bad_receipt["root"] = "f" * 64
ok, det = verify_receipt(c, bad_receipt)
t("forged receipt root -> FORK", not ok and "FORK" in det, det)

# 8. receipt from a meeting that does not exist
c, root = make_chain()
ghost = dict(receipt(c, root))
ghost["meeting"] = "M99"
ok, det = verify_receipt(c, ghost)
t("ghost meeting -> meeting-root-missing", not ok and "missing" in det, det)

# 9. deterministic: same input twice -> same verdict
c, root = make_chain()
_, d1 = verify_receipt(c, receipt(c, root))
_, d2 = verify_receipt(c, receipt(c, root))
t("determinism -> identical verdicts", d1 == d2 == "MATCH", (d1, d2))

print(f"\n{PASS}/9 PASSED")
sys.exit(0)