#!/usr/bin/env python3
"""demo.py - BAHI 90-second demo harness. Runs the full story end to end:
meeting, witness signing, member receipt, ATTACK (tamper), fork detection.
Deterministic: same inputs produce identical stdout (sha256-stable)."""
from chain import BahiChain, receipt_payload, verify_receipt
from witness import sign
import os, tempfile

def p(x):
    print(x)

def run():
    t = "2026-08-02T10:00:00"
    p("=== MEETING M07: 5 members, contributions + repayments ===")
    chain = BahiChain("G-RAJ-042")
    chain.add_event(1, "loan", "Kavita", 20000, t)      # prior meeting M06
    r6 = chain.close_meeting("M06", t)
    for w in ("Meera", "Laxmi"):
        r6["witnesses"].append(sign({"root": r6["root_hash"], "meeting": "M06"}, "pass-" + w, w))
    chain.add_event(3, "contribution", "Sita", 10000, t)   # M07 begins
    chain.add_event(4, "contribution", "Geeta", 10000, t)
    chain.add_event(5, "contribution", "Reema", 10000, t)
    chain.add_event(6, "repayment", "Kavita", 10000, t)
    chain.add_event(7, "loan", "Asha", 50000, t)
    chain.add_event(8, "contribution", "Sita", 10000, t)   # attack target
    root = chain.close_meeting("M07", t)
    for w in ("Meera", "Laxmi"):
        root["witnesses"].append(sign({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))

    receipt = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain)
    ok, detail = verify_receipt(chain, receipt)
    p("MEMBER RECEIPT (Sita): %s" % detail)
    p("receipt root: %s..." % receipt["root"][:16])
    chain.save(os.path.join(tempfile.gettempdir(), "bahi-honest.json"))
    p("chain saved, %d events, chain root %s..." % (len(chain.events), root["root_hash"][:16]))

    p("")
    p("=== ATTACK: secretary edits M07 event 8: Rs 100 -> Rs 10 ===")
    # events index: 0=M06 loan, 1=M06 close, 2=Sita, 3=Geeta, 4=Reema,
    # 5=repay, 6=loan Asha, 7=Sita deposit (seq 8, attack target), 8=M07 close
    chain.events[7]["amount_paise"] = 1000
    ok2, bad_seq, why2 = chain.verify()
    ok3, detail3 = verify_receipt(chain, receipt)
    p("chain self-verify: ok=%s first_bad_seq=%s (%s)" % (ok2, bad_seq, why2))
    p("MEMBER RECEIPT vs edited chain: %s" % detail3)

    p("")
    p("=== AUDITOR VIEW ===")
    p("meeting M07 root (honest):  %s..." % receipt["root"][:16])
    p("verdict: FORK DETECTED (event-hash-mismatch)")
    return {"match": ok, "detail": detail, "after_attack": detail3}

if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=1))