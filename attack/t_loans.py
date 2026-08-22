#!/usr/bin/env python3
"""t_loans.py - balances() attack matrix: negative outstanding, free money,
type confusion, huge amounts, corner cases."""
import sys, os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain
from loans import balances, format_rupees

T = "2026-08-02T10:00:00"

def chain_with(events):
    c = BahiChain("G")
    for i, (etype, member, amt) in enumerate(events, 1):
        c.add_event(i, etype, member, amt, T)
    return c

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    # baseline
    c = chain_with([("loan", "A", 10000), ("repayment", "A", 4000)])
    b = balances(c)
    t("loans.001 basic outstanding", b["A"]["outstanding_paise"] == 6000, str(b))
    t("loans.002 fields present", set(b["A"]) == {"member", "loaned_paise", "repaid_paise", "outstanding_paise"}, str(b["A"]))

    # -------- repayment without loan -> NEGATIVE outstanding (free money) --------
    c = chain_with([("repayment", "B", 5000)])
    b = balances(c)
    t("VULN.loans.repay-noloan negative outstanding for member with no loan",
      b["B"]["outstanding_paise"] == -5000,
      "repayment > loaned is accepted silently: member 'B' ends at Rs -50.00 outstanding (they can never have borrowed)")
    # over-repayment
    c = chain_with([("loan", "C", 1000), ("repayment", "C", 9000)])
    b = balances(c)
    t("VULN.loans.overrepay negative outstanding after over-repayment",
      b["C"]["outstanding_paise"] == -8000, str(b["C"]))
    # repayment by a member with zero events at all
    c = chain_with([("loan", "D", 1000)])
    b = balances(c)
    t("loans.003 members with no loan/repayment not listed", "Sita" not in b)

    # -------- contribution ignores: corpus never tracked --------
    c = chain_with([("contribution", "Sita", 100000), ("loan", "Asha", 200000)])
    b = balances(c)
    t("VULN.loans.corpus loans can exceed total contributions (no corpus check)",
      b["Asha"]["outstanding_paise"] == 200000,
      "ledger lends Rs 200,000 while corpus only ever received Rs 100,000: balances() never compares loans vs contributions")

    # -------- type confusion --------
    for junk in ("loan100", "Loan", "repayment ", "loan\n", "loan\x00", "MEETING-CLOSE", "contribution"):
        c = chain_with([(junk, "M", 5000)])
        b = balances(c)
        t("VULN.loans.type.%r ignored silently" % junk, junk not in b and "M" not in b,
          "event type %r is not loan/repayment so funds vanish from the loan view" % junk)
    # MEETING-CLOSE member __root__ 0 paise never enters balances
    c = chain_with([("loan", "Z", 5000), ("MEETING-CLOSE", "__root__", 0)])
    b = balances(c)
    t("loans.004 MEETING-CLOSE ignored", "Z" in b and "__root__" not in b)

    # -------- amounts --------
    c = chain_with([("loan", "Big", 10**18), ("repayment", "Big", 10**18)])
    b = balances(c)
    t("loans.005 huge amounts fine (arbitrary precision)", b["Big"]["outstanding_paise"] == 0)
    c = chain_with([("loan", "Zero", 0)])
    b = balances(c)
    t("loans.006 zero-value loan accepted", b["Zero"]["outstanding_paise"] == 0)
    # string amount that slipped through _norm_amount stores str -> int() crash in balances
    c = BahiChain("G")
    c.add_event(1, "loan", "S", "5000", T)      # VULN.amount.005 already proved this is possible
    try:
        b = balances(c)
        t("SAFE.loans.str-amount balances() handles string amount", isinstance(b["S"]["loaned_paise"], int), str(b))
    except Exception as e:
        t("SAFE.loans.str-amount balances() handles string amount", False, "%s: %r" % (type(e).__name__, e))
    c = BahiChain("G")
    c.add_event(1, "repaid", "S", 5000, T)      # typo type fallback family (repaid vs repayment)
    b = balances(c)
    t("VULN.loans.typo 'repaid' vs 'repayment' funds vanish", "S" not in b,
      "type 'repaid' is treated as an unrelated event: member S's Rs 5000 payment disappears from outstanding entirely")

    # -------- duplicate seq members --------
    c = BahiChain("G")
    c.add_event(1, "loan", "A", 1000, T)
    c.add_event(1, "loan", "A", 1000, T)
    b = balances(c)
    t("loans.007 duplicate-events summed", b["A"]["loaned_paise"] == 2000)

    # -------- format_rupees --------
    t("loans.008 format", format_rupees(12345) == "Rs 123.45", format_rupees(12345))
    t("loans.009 format negative", format_rupees(-50) == "Rs -0.50")
    t("loans.010 float precision", format_rupees(1) == "Rs 0.01")

    # -------- balances on corrupt chains -> CRASHES (no guards) --------
    c = chain_with([("loan", "A", 1000)])
    del c.events[0]["amount_paise"]
    try:
        b = balances(c)
        t("VULN.loans.corrupt chain balances() crashes", False, "no exception (expected KeyError)")
    except KeyError as e:
        t("VULN.loans.corrupt chain balances() crashes", True,
          "KeyError %r: balances() has NO guard against missing fields, contrary to chain.py's no-crash promise" % (e,))
    except Exception as e:
        t("VULN.loans.corrupt chain balances() crashes", True, "%s: %r" % (type(e).__name__, e))
    c = chain_with([("loan", "A", 1000)])
    c.events[0]["amount_paise"] = None
    try:
        b = balances(c)
        t("VULN.loans.null amount balances() crashes", False, "no exception (expected TypeError)")
    except TypeError as e:
        t("VULN.loans.null amount balances() crashes", True,
          "TypeError %r: None amount crashes the += replay" % (e,))
    except Exception as e:
        t("VULN.loans.null amount balances() crashes", True, "%s: %r" % (type(e).__name__, e))
    c = chain_with([("loan", "A", 1000)])
    c.events[0]["amount_paise"] = [1, 2]
    try:
        b = balances(c)
        t("VULN.loans.list amount balances() crashes", False, "no exception (expected TypeError)")
    except TypeError as e:
        t("VULN.loans.list amount balances() crashes", True,
          "TypeError %r: list amount crashes; a corrupt chain file takes down /api/state's loan tracker" % (e,))
    except Exception as e:
        t("VULN.loans.list amount balances() crashes", True, "%s: %r" % (type(e).__name__, e))
    c = chain_with([("loan", "A", 1000)])
    c.events[0]["member"] = None
    try:
        b = balances(c)
        t("VULN.loans.null member balances() absorbs (None keyed)", True, str(b))
    except Exception as e:
        t("VULN.loans.null member balances() absorbs (None keyed)", False, "%s: %r" % (type(e).__name__, e))

    return R