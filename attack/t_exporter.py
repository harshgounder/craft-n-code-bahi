#!/usr/bin/env python3
"""t_exporter.py - hint rules + CSV export attack matrix: blind spots,
substring bug, formula injection, meeting attribution edges."""
import sys, os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain
from witness import sign_entry
from exporter import hint_flags, audit_report, export_csv, _meetings_with_events

T = "2026-08-02T10:00:00"

def add(c, seq, etype, member, amt):
    c.add_event(seq, etype, member, amt, T)

def close(c, mid, ws=("Meera", "Laxmi")):
    r = c.close_meeting(mid, T)
    for w in ws:
        r["witnesses"].append(sign_entry({"root": r["root_hash"], "meeting": mid}, "pass-"+w if not "," in str(w) else w, w.split(",")[0] if "," in str(w) else w))
    return r

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    # ---------- hint rule basics ----------
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    add(c, 2, "loan", "A", 2000)
    close(c, "M1")
    fl = {f["hint"] for f in hint_flags(c)}
    t("SAFE.hint.concentrated A took 100% of loans", "concentrated_lending" in fl, str(fl))
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    add(c, 2, "loan", "B", 1000)
    close(c, "M1")
    fl = {f["hint"] for f in hint_flags(c)}
    t("SAFE.hint.no-concentrate equal split no flag", "concentrated_lending" not in fl, str(fl))
    c = BahiChain("G")
    for i in range(5):
        add(c, i + 1, "contribution", "Sita", 10000)
    close(c, "M1")
    fl = {f["hint"] for f in hint_flags(c)}
    t("SAFE.hint.dup 5 identical contributions flagged", "duplicate_identity" in fl, str(fl))
    c = BahiChain("G")
    for i in range(4):
        add(c, i + 1, "correction", "Sita", 100)
    close(c, "M1")
    fl = {f["hint"] for f in hint_flags(c)}
    t("SAFE.hint.reversal 4 corrections flagged", "reversal_burst" in fl)
    c = BahiChain("G")
    add(c, 1, "repayment", "A", 999)
    close(c, "M1")
    fl = {f["hint"] for f in hint_flags(c)}
    t("SAFE.hint.arithmetic repay>loan flagged", "arithmetic_mismatch" in fl)

    # ---------- hint blind spots / bugs ----------
    # duplicate_identity substring suppression: member "Ash" suppressed by "Asha" flag
    c = BahiChain("G")
    add(c, 1, "contribution", "Asha", 500)
    add(c, 2, "contribution", "Asha", 500)
    add(c, 3, "contribution", "Asha", 500)
    add(c, 4, "contribution", "Ash", 700)
    add(c, 5, "contribution", "Ash", 700)
    add(c, 6, "contribution", "Ash", 700)
    close(c, "M1")
    fl = [f["evidence"] for f in hint_flags(c) if f["hint"] == "duplicate_identity"]
    t("SAFE.hint.substr 'Ash' flag NOT suppressed by 'Asha' (fix landed)",
      any("Ash Rs 7" in e for e in fl),
      "both names flag independently: %s" % fl)
    # 3 identical contributions DO flag (threshold) but 2 identical loans do NOT (paired threshold logic only fires >=3)
    c = BahiChain("G")
    add(c, 1, "loan", "X", 1000)
    add(c, 2, "loan", "X", 1000)
    close(c, "M1")
    fl = {f["hint"] for f in hint_flags(c)}
    t("VULN.hint.duploan 2 identical loans not flagged", "duplicate_identity" not in fl,
      "identical loan pair (a classic double-disbursement pattern) never triggers (threshold is 3)")
    # orphan events outside any meeting root -> invisible to ALL hints
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1")
    try:
        add(c, 99, "loan", "A", 500000)   # PR10: non-sequential seq rejected
        t("SAFE.hint.orphan post-close event REJECTED (PR10)", False, "accepted")
    except ValueError:
        t("SAFE.hint.orphan post-close event REJECTED (PR10)", True)
    # events BEFORE first root (seq 0 window) attributed to first meeting (lo=0) - fine
    # concentrated_lending needs >=2 loans PER MEETING: single-loan meetings invisible
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1")
    add(c, 3, "loan", "A", 90000)
    close(c, "M2")
    fl = [f["hint"] for f in hint_flags(c)]
    t("VULN.hint.singleloan 99%-concentration via one loan per meeting never flagged",
      "concentrated_lending" not in fl,
      "rule requires len(loans) >= 2 INSIDE a meeting; 'A' takes 100% of every meeting's lending across 2 meetings -> zero flags")
    # arithmetic_mismatch is PER MEETING only: cross-meeting repay>loan missed
    c = BahiChain("G")
    add(c, 1, "repayment", "A", 1000)          # M1: repay 1000, no loan -> flagged in M1
    close(c, "M1")
    add(c, 3, "loan", "A", 5000)
    close(c, "M2")
    fl = [f["hint"] for f in hint_flags(c) if f["hint"] == "arithmetic_mismatch"]
    t("VULN.hint.crossmeeting repayment-before-loan pattern flagged", len(fl) == 1,
      "M1 repays Rs 1000 it has not yet borrowed (M2 lends later): per-meeting view flags M1 only, whole-group logic absent")
    # missing_witness per meeting
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1", ws=("Meera",))
    fl = [f["hint"] for f in hint_flags(c)]
    t("SAFE.hint.missing-witness 1 witness flagged", "missing_witness" in fl, str(fl))

    # ---------- corrupt chain ----------
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    c.roots = {"__corrupt__": {"corrupt": "load: boom"}}
    fl = hint_flags(c)
    t("SAFE.hint.corrupt chain -> corrupt_chain hint", len(fl) == 1 and fl[0]["hint"] == "corrupt_chain", str(fl))

    # ---------- meeting attribution edges ----------
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1")
    add(c, 3, "loan", "B", 2000)
    close(c, "M2")
    m = _meetings_with_events(c)
    pairs = m[0]  # (meetings, invalid_events) tuple post-PR10
    t("exporter.meet.001 two meetings two windows", len(pairs) == 2 and len(pairs[0][1]) == 1 and len(pairs[1][1]) == 1, str(m))
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    r2 = close(c, "M1")
    del c.roots["M1"]
    m = _meetings_with_events(c)
    t("VULN.exporter.meet.002 deleted root metadata silently drops meeting AND its events from exports",
      len(m[0]) == 0,
      "removing a roots[] entry erases the meeting from the audit report entirely; hints + meetings list go quiet")
    # duplicate root_seq (two meetings same seq) -> all events rehomed to the FIRST meeting
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1")
    c.roots["M2"] = {"root_hash": "x" * 64, "root_seq": c.roots["M1"]["root_seq"], "ts": T, "witnesses": [{"witness": "a", "sig": "0" * 64}, {"witness": "b", "sig": "1" * 64}]}
    m = _meetings_with_events(c)
    t("VULN.exporter.meet.003 duplicate root_seq rehomes events: M2 window empty, M1 double-claims",
      len(m[0]) == 2 and len(m[0][1][1]) == 0 and len(m[0][0][1]) == 1,
      "root_seqs sorted [(2,M1),(2,M2)]: M2 gets lo=3>hi=2 -> empty window; ALL M1 events attributed once to M1 but M2's identity vanishes")

    # ---------- CSV export: formula injection + escaping ----------
    c = BahiChain("G")
    add(c, 1, "loan", "=HYPERLINK(\"http://evil\",\"click\")", 1000)
    close(c, "M1")
    csv_out = export_csv(c)
    t("VULN.csv.formula member name with '=' formula lands unescaped in CSV",
      '=HYPERLINK' in csv_out,
      "member is attacker-influenced; opening export in Excel executes formula cells (CSV injection)")
    for prefix in ("+", "-", "@", "=", "|", "\t", "\r"):
        c = BahiChain("G")
        add(c, 1, "loan", prefix + "1+1", 1000)
        close(c, "M1")
        out = export_csv(c)
        t("VULN.csv.prefix %r member lands raw in CSV" % prefix, (prefix + "1+1") in out,
          "no formula-prefix protection ('%s'-leading cell)" % prefix)
    # member with comma (CSV quoting works)
    c = BahiChain("G")
    add(c, 1, "loan", "Singh, Raj", 1000)
    close(c, "M1")
    out = export_csv(c)
    t("SAFE.csv.comma comma member is quoted", '"Singh, Raj"' in out, "csv module quoting handles commas (v1.2 fix)")
    # newline injection
    c = BahiChain("G")
    add(c, 1, "loan", "Sita\nEVIL,row", 1000)
    close(c, "M1")
    out = export_csv(c)
    t("SAFE.csv.newline embedded newline quoted", '"Sita\nEVIL,row"' in out, "csv module quotes embedded newlines")
    # ts column with formula (ts is free-form too)
    c = BahiChain("G")
    c.add_event(1, "loan", "Sita", 1000, "=2+2")
    close(c, "M1")
    out = export_csv(c)
    t("VULN.csv.ts formula in timestamp lands unescaped", "=2+2" in out,
      "ts string is emitted raw into the CSV; same formula risk via the time field")

    # ---------- audit_report edges ----------
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1")
    rep = audit_report(c)
    t("SAFE.report.001 schema fields present", all(k in rep for k in ("group", "chain_ok", "first_bad_seq", "why", "meetings", "hints")), str(list(rep)))
    t("SAFE.report.002 chain_ok true", rep["chain_ok"] is True)
    t("SAFE.report.003 why ok", rep["why"] == "ok")
    t("SAFE.report.004 first_bad_seq None when ok", rep["first_bad_seq"] is None)
    c = BahiChain("G")
    add(c, 1, "loan", "A", 1000)
    close(c, "M1")
    c.events[0]["amount_paise"] = 1
    rep = audit_report(c)
    t("SAFE.report.005 tampered chain reported", rep["chain_ok"] is False and "mismatch" in rep["why"], str(rep["why"]))
    # corrupt chain report: audit_report does NOT crash (fix landed)
    c = BahiChain("G")
    c.roots = {"__corrupt__": {"corrupt": "load: boom"}}
    try:
        rep = audit_report(c)
        t("SAFE.report.006 audit_report survives corrupt chain", rep["chain_ok"] is False,
          "corrupt flag surfaced, no crash: %s" % str(rep)[:60])
    except Exception as e:
        t("SAFE.report.006 audit_report survives corrupt chain", False, "%s: %s" % (type(e).__name__, e))

    return R