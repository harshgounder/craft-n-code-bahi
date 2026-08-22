#!/usr/bin/env python3
"""runner.py - tiny stdlib test harness for the BAHI attack suite.

Each module exposes run() -> list of (tid, ok, detail) tuples.
Conventions:
  - ok=True  -> the test's EXPECTATION was met.
  - tid prefixed "VULN." -> the test EXPECTS a vulnerability to be
    reproducible. VULN.ok=True means the flaw is confirmed (finding).
  - tid prefixed "SAFE." -> the test EXPECTS the defense to hold.
    SAFE.ok=False means a real security bug (exploit succeeded).
  - Everything else is protocol/robustness behavior.
Pure stdlib. Exit 0 = all expectations met.
"""
import json, sys, time

RESULT = []


def t(tid, ok, detail=""):
    RESULT.append((tid, bool(ok), detail))
    return bool(ok)


def summarize(name, results=None):
    rows = results if results is not None else RESULT
    vuln_p = sum(1 for tid, ok, _ in rows if tid.startswith("VULN.") and ok)
    vuln_f = sum(1 for tid, ok, _ in rows if tid.startswith("VULN.") and not ok)
    safe_p = sum(1 for tid, ok, _ in rows if tid.startswith("SAFE.") and ok)
    safe_f = sum(1 for tid, ok, _ in rows if tid.startswith("SAFE.") and not ok)
    print("  %s: %d tests | vuln-confirmed %d | vuln-missed %d | safe-held %d | safe-broken %d"
          % (name, len(rows), vuln_p, vuln_f, safe_p, safe_f))
    return {"module": name, "total": len(rows), "vuln_confirmed": vuln_p,
            "vuln_missed": vuln_f, "safe_held": safe_p, "safe_broken": safe_f}