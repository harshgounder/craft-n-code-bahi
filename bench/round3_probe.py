#!/usr/bin/env python3
"""round3_probe.py - NEW findings against the FIXED code (post PR#9+PR#10)."""
from chain import BahiChain, receipt_payload, verify_receipt, h, _norm_witnesses
from witness import sign_entry, sign
from loans import balances
from exporter import hint_flags, export_csv, audit_report

TS = "2026-08-02T10:00:00"

def show(name, ok, evidence):
    print("  %-4s %s  %s" % ("CONF" if ok else "NO  ", name, evidence))

# ===== N1. QUORUM GAMING: one person signs twice =====
c = BahiChain("G")
for i in range(1, 4): c.add_event(i, "contribution", "Sita", 10000, TS)
root = c.close_meeting("M07", TS)
# Meera signs TWICE (two different "signatures", same witness)
root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera"))
root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M07"}, "pass-Meera-2", "Meera"))
r = receipt_payload("G", "M07", root, "Sita")
ok, det = verify_receipt(c, r)
names = sorted(set(w["witness"] for w in root["witnesses"]))
show("N1 quorum gaming: 2 sigs from SAME witness (Meera) satisfies quorum",
     ok and det == "MATCH" and len(names) == 1,
     "verify=%s det=%s unique_witnesses=%s" % (ok, det, names))

# ===== N2. STORED XSS: member name with HTML flows into hint evidence =====
c = BahiChain("G")
xss = '<img src=x onerror=alert(1)>'
c.add_event(1, "contribution", xss, 10000, TS)
c.add_event(2, "contribution", xss, 10000, TS)
c.add_event(3, "contribution", xss, 10000, TS)  # 3 identical -> duplicate_identity hint
c.add_event(4, "contribution", "Other", 5000, TS)
c.close_meeting("M01", TS)
flags = hint_flags(c)
dup = [f for f in flags if f["hint"] == "duplicate_identity"]
show("N2 stored XSS: member name HTML reflected in hint evidence (unescaped in UI)",
     dup and "<" in dup[0]["evidence"],
     "evidence=%r" % (dup[0]["evidence"] if dup else None))

# ===== N3. CSV formula guard: leading-space/tab before '=' bypasses =====
from exporter import export_csv
c = BahiChain("G")
c.add_event(1, "contribution", " =cmd|'/C calc", 10000, TS)  # leading space
c.close_meeting("M01", TS)
csvout = export_csv(c)
row = csvout.splitlines()[1]
show("N3 CSV formula guard misses leading-space ' =' payload",
     " =cmd" in row and not row.split(",")[2].startswith("'"),
     "member cell=%r" % (row.split(",")[2] if len(row.split(",")) > 2 else row))

# ===== N4. add_witness allows duplicate witness (no uniqueness) =====
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, TS)
root = c.close_meeting("M07", TS)
c.add_witness("M07", {"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera")
c.add_witness("M07", {"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera")
show("N4 add_witness permits duplicate witness names",
     len(root["witnesses"]) == 2 and root["witnesses"][0]["witness"] == root["witnesses"][1]["witness"],
     "witnesses=%s" % [w["witness"] for w in root["witnesses"]])

# ===== N5. close_meeting accepts pre-signed witness over WRONG payload =====
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, TS)
# pre-sign over a DIFFERENT meeting/root, then close with it
wrong = sign_entry({"root": "0"*64, "meeting": "M99"}, "pass-Meera", "Meera")
root = c.close_meeting("M07", TS, witnesses=[wrong])
ok, det = verify_receipt(c, receipt_payload("G", "M07", root, "Sita"), witness_keys={"Meera": "pass-Meera"})
show("N5 close_meeting accepts witness signed over wrong payload (caught at verify)",
     not ok and "witness-signature-invalid" in det,
     "close accepted, verify=%s (%s)" % (ok, det))

# ===== N6. _norm_witnesses silently drops malformed (could mask tampering) =====
norm = _norm_witnesses([{"witness": "Meera", "sig": sign({"root": "x", "meeting": "M"}, "p", "Meera")},
                        "GARBAGE_NOT_A_RECORD",
                        {"witness": "Laxmi", "sig": sign({"root": "x", "meeting": "M"}, "p", "Laxmi")}])
show("N6 malformed witness silently dropped (2 valid remain)",
     len(norm) == 2, "normalized=%d entries" % len(norm))

# ===== N7. group_id whitespace-only accepted? (corrupt checks .strip()) =====
try:
    c = BahiChain("   ")
    c.add_event(1, "contribution", "A", 100, TS)
    show("N7 whitespace-only group accepted by add_event", True, "group=%r accepted" % c.group_id)
except ValueError as e:
    show("N7 whitespace-only group rejected", False, str(e))

# ===== N8. receipt without member_events falls back to weak member-exists =====
c = BahiChain("G")
c.add_event(1, "contribution", "Sita", 10000, TS)
c.add_event(2, "contribution", "Geeta", 10000, TS)
root = c.close_meeting("M07", TS)
for w in ("Meera", "Laxmi"):
    root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M07"}, "pass-"+w, w))
# legacy receipt: no member_events, claims member=Geeta
legacy = {"group": "G", "meeting": "M07", "root": root["root_hash"], "root_seq": root["root_seq"],
          "member": "Geeta", "root_ts": TS, "witnesses": [dict(w) for w in root["witnesses"]],
          "member_events": None}
ok, det = verify_receipt(c, legacy)
show("N8 legacy receipt (no member_events) only checks member-exists",
     ok and det == "MATCH", "verify=%s (%s) — Geeta's receipt proves nothing about her lines" % (ok, det))

print("\nDone.")
