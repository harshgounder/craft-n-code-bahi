#!/usr/bin/env python3
"""demo.py - BAHI 90-second demo harness. Runs the full story end to end:
meeting, witness signing, member receipt, ATTACK (tamper M07), fork detection.
Deterministic: same input -> same output, always."""
import json, sys
from chain import BahiChain, receipt_payload, verify_receipt
from witness import sign_entry

def run(verbose=True):
    p = lambda s: print(s) if verbose else None
    chain = BahiChain(group_id="G-RAJ-042")
    W1, W2 = ("Meera", "witness-pass-1"), ("Laxmi", "witness-pass-2")
    ts_base = "2026-08-02T10:00:00"

    p("=== MEETING M07: 14 members, contributions + repayments ===")
    chain.add_event(1, "contribution", "Sita", 10000, ts_base)          # Rs 100.00
    chain.add_event(2, "contribution", "Geeta", 10000, ts_base)
    chain.add_event(3, "contribution", "Reema", 10000, ts_base)
    chain.add_event(4, "repayment", "Kavita", 20000, ts_base)           # loan repayment
    chain.add_event(5, "loan", "Asha", 50000, ts_base)                  # new loan
    chain.add_event(6, "contribution", "Sita", 10000, ts_base)
    chain.add_event(7, "contribution", "Sita", 10000, ts_base)          # M07 target

    root = chain.close_meeting("M07", ts_base)
    # two witnesses sign the ROOT VALUE (metadata, outside the hashed chain)
    root["witnesses"] = [
        sign_entry({"root": root["root_hash"], "meeting": "M07"}, W1[1], W1[0]),
        sign_entry({"root": root["root_hash"], "meeting": "M07"}, W2[1], W2[0]),
    ]

    receipt = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain)
    ok, detail = verify_receipt(chain, receipt)
    assert ok and detail == "MATCH"
    p("MEMBER RECEIPT (Sita): %s" % detail)
    p("receipt root: %s" % receipt["root"][:16] + "...")

    chain.save("/tmp/bahi-honest.json")
    p("chain saved, %d events, chain root %s" % (len(chain.events), root["root_hash"][:16]))

    p("")
    p("=== ATTACK: secretary edits M07 event 7: Rs 100 -> Rs 10 ===")
    chain.events[6]["amount_paise"] = 1000   # silently change Sita's Rs 100 to Rs 10
    ok2, bad_seq, why = chain.verify()
    p("chain self-verify: ok=%s first_bad_seq=%s (%s)" % (ok2, bad_seq, why))

    ok3, detail3 = verify_receipt(chain, receipt)
    p("MEMBER RECEIPT vs edited chain: %s" % detail3)
    assert not ok3 and "FORK" in str(detail3)

    p("")
    p("=== AUDITOR VIEW ===")
    p("meeting M07 root (honest):  %s" % receipt["root"][:16])
    p("verdict: FORK DETECTED AT EVENT %s (%s)" % (bad_seq, why))
    return {"match": ok, "fork": not ok3, "bad_seq": bad_seq}

if __name__ == "__main__":
    result = run()
    print("RESULT:", json.dumps(result))
    sys.exit(0 if result["match"] and result["fork"] else 1)