#!/usr/bin/env python3
"""round3b_probe.py - business-logic + replay + transplant attacks."""
from chain import BahiChain, receipt_payload, verify_receipt, h
from witness import sign_entry
from loans import balances
from exporter import hint_flags

TS = "2026-08-02T10:00:00"

def show(name, ok, evidence):
    print("  %-4s %s  %s" % ("CONF" if ok else "NO  ", name, evidence))

# ===== B1. LOAN DOUBLE-SPEND: take loan, never repay, take another =====
c = BahiChain("G")
c.add_event(1, "loan", "Asha", 50000, TS)
c.add_event(2, "loan", "Asha", 50000, TS)  # never repaid the first
c.add_event(3, "contribution", "Sita", 10000, TS)
c.close_meeting("M01", TS)
b = balances(c)["Asha"]
flags = hint_flags(c)
hints = [f["hint"] for f in flags]
show("B1 double-spend: 2 loans, no repayment -> outstanding 100000 (no hint flags it)",
     b["outstanding_paise"] == 100000 and "arithmetic_mismatch" not in hints and "concentrated_lending" not in hints,
     "outstanding=%d hints=%s" % (b["outstanding_paise"], hints))

# ===== B2. CORPUS INSOLVENCY: loans exceed total contributions =====
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, TS)   # corpus 10000
c.add_event(2, "loan", "Asha", 100000, TS)          # loan 100000 > corpus
c.add_event(3, "loan", "Bela", 100000, TS)
c.close_meeting("M01", TS)
flags = hint_flags(c)
hints = [f["hint"] for f in flags]
show("B2 corpus insolvency: 210000 loaned vs 10000 corpus (no hint flags it)",
     "arithmetic_mismatch" not in hints and "concentrated_lending" not in hints,
     "hints=%s" % hints)

# ===== B3. CORRECTION LAUNDERING: fake correction zeroes a real loan =====
c = BahiChain("G")
c.add_event(1, "loan", "Asha", 50000, TS)
c.add_event(2, "correction", "Asha", 50000, TS)  # "corrects away" the entire loan
c.add_event(3, "contribution", "Sita", 10000, TS)
c.close_meeting("M01", TS)
b = balances(c)["Asha"]
show("B3 correction laundering: loan 50000 + correction 50000 -> outstanding 0 (loan erased)",
     b["outstanding_paise"] == 0 and b["corrected_paise"] == 50000,
     "outstanding=%d corrected=%d" % (b["outstanding_paise"], b["corrected_paise"]))

# ===== B4. CROSS-MEETING REPLAY: copy M01 events verbatim into M02 =====
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, TS)
c.add_event(2, "loan", "Asha", 50000, TS)
r1 = c.close_meeting("M01", TS)
# replay: identical events into M02 (different meeting, same amounts/members)
c.add_event(None, "contribution", "Sita", 10000, TS)
c.add_event(None, "loan", "Asha", 50000, TS)
r2 = c.close_meeting("M02", TS)
ok, bad, why = c.verify()
show("B4 cross-meeting replay: identical (member,amount) in M01 and M02 accepted by chain",
     ok and r1["root_hash"] != r2["root_hash"],
     "verify=%s M01!=M02 roots (replay not detected as such, only dup-id hint)" % ok)

# ===== B5. RECEIPT REPLAY: old receipt re-used after chain has advanced =====
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, TS)
root = c.close_meeting("M07", TS)
for w in ("Meera", "Laxmi"):
    root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M07"}, "pass-"+w, w))
r = receipt_payload("G", "M07", root, "Sita", chain=c)
ok1, d1 = verify_receipt(c, r)
# now a NEW meeting happens after (terminality: M07 was last, so adding M08 breaks it)
c.add_event(None, "contribution", "Geeta", 10000, TS)
c.close_meeting("M08", TS)
ok2, d2 = verify_receipt(c, r)
show("B5 receipt replay after chain advanced -> events-after-close",
     ok1 and not ok2 and "events-after-close" in d2,
     "before=%s after=%s" % (d1, d2))

# ===== B6. PHANTOM MEMBER: fabricated member with no real identity =====
c = BahiChain("G")
c.add_event(1, "contribution", "Ghost-Phantom-01", 100000, TS)  # fabricated contribution
c.add_event(2, "loan", "Asha", 50000, TS)
c.close_meeting("M01", TS)
ok, bad, why = c.verify()
show("B6 phantom member: fabricated contributor accepted (no KYC/identity check)",
     ok, "verify=%s (chain integrity holds; identity is out of scope)" % ok)

print("\nDone.")
