#!/usr/bin/env python3
"""t_v2.py - attack the PR4/PR5/PR6 FIXES (post-fix code, HEAD 85b0687).
Targets: member binding gaps, close-swap attack, legacy receipt downgrade,
Host/Origin residual vectors, new open-meeting flow.
"""
import http.client, json, os, sys, threading, time, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain, receipt_payload, verify_receipt, h
from witness import sign
from http.server import HTTPServer
import server as srv

T = "2026-08-02T10:00:00"

def full_recompute(c):
    prev = h("GENESIS", c.group_id)
    for ev in c.events:
        ev["prev"] = prev
        ev["hash"] = h(prev, ev["seq"], ev["type"], ev["member"], ev["amount_paise"], ev["ts"])
        prev = ev["hash"]

def make_bound(setup="default"):
    """chain with M06 (Kavita loan) + M07 (Sita/Geeta/Reema/Asha/Kavita), bound receipt for Sita."""
    c = BahiChain("G-RAJ-042")
    c.add_event(1, "loan", "Kavita", 20000, T)
    r6 = c.close_meeting("M06", T)
    for w in ("Meera", "Laxmi"):
        r6["witnesses"].append(sign({"root": r6["root_hash"], "meeting": "M06"}, "pass-" + w, w))
    c.add_event(3, "contribution", "Sita", 10000, T)
    c.add_event(4, "contribution", "Geeta", 10000, T)
    c.add_event(5, "contribution", "Reema", 10000, T)
    c.add_event(6, "repayment", "Kavita", 10000, T)
    c.add_event(7, "loan", "Asha", 50000, T)
    c.add_event(8, "contribution", "Sita", 10000, T)
    r7 = c.close_meeting("M07", T)
    for w in ("Meera", "Laxmi"):
        r7["witnesses"].append(sign({"root": r7["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    if setup == "open-m06":      # M06 closed normally, M07 OPEN (no close yet)
        return c, r6, None
    return c, r6, r7

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    # ============ 1. close-event SWAP attack (member binding does NOT catch) ============
    def swap_close(c, root_meta, ghost=None):
        """delete the meeting's close event, optionally insert ghost events,
        re-close at the SAME seq linked through the new tail."""
        rs = root_meta["root_seq"]
        c.events = [e for e in c.events if not (e.get("type") == "MEETING-CLOSE" and e.get("seq") == rs)]
        if ghost:
            for gseq, gmember, gamt in ghost:
                c.add_event(gseq, "contribution", gmember, gamt, T)
        prev = c.events[-1]["hash"]
        ev = {"seq": rs, "group": c.group_id, "type": "MEETING-CLOSE", "member": "__root__",
              "amount_paise": 0, "ts": T, "prev": prev}
        ev["hash"] = h(prev, ev["seq"], ev["type"], ev["member"], ev["amount_paise"], ev["ts"])
        c.events.append(ev)

    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)   # bound receipt, issued at close
    swap_close(c, r7)
    okv, _, whyv = c.verify()
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.close-swap close event deleted+replaced at same seq: bound receipt still MATCHes",
      okv and okr and det == "MATCH",
      "why=%s det=%s: member's own events untouched (hashes identical), root metadata stale-equal to receipt root, terminality passes (new close seq 9) -> silent close replacement" % (whyv, det))

    # ghost-insert forgery: delete close, inject arbitrary event, re-close same seq
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    swap_close(c, r7, ghost=[(r7["root_seq"], "Ghost", 1000000000)])
    okv, _, whyv = c.verify()
    okr, det = verify_receipt(c, rec)
    ghost_rows = [e for e in c.events if e.get("member") == "Ghost"]
    t("VULN.v2.ghost-insert FORGERY: Rs 10,000,000 Ghost contribution inserted into M07, bound receipt MATCHes",
      okv and okr and det == "MATCH" and ghost_rows and ghost_rows[0]["amount_paise"] == 1000000000,
      "verify=%s receipt=%s ghost=%s: member binding pins ONLY the receipt member's line items; any OTHER member's events below the close are unprotected -> entire fraud unobservable to Sita's receipt" % (okv, det, ghost_rows[0]["amount_paise"] if ghost_rows else None))

    # same attack but with full recompute after swap (still MATCH for swap-only)
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    swap_close(c, r7)
    full_recompute(c)
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.close-swap2 close swap + full recompute: bound receipt MATCHes", okr and det == "MATCH", det)

    # ============ 2. legacy receipt (no member_events) downgrade ============
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    del rec["member_events"]                     # strip binding -> legacy fallback
    c.events[6]["amount_paise"] = 1
    full_recompute(c)
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.downgrade member_events stripped: recompute MATCHes via legacy path",
      okr and det == "MATCH",
      "det=%s: verify_receipt uses receipt.get('member_events'); removing the key downgrades to member-exists check -> original recompute hole is back" % det)

    # legacy receipts in general still fully vulnerable
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita")      # no chain -> legacy
    c.events[6]["amount_paise"] = 1
    full_recompute(c)
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.legacy-recompute legacy receipts still MATCH under recompute", okr and det == "MATCH",
      "any receipt issued without chain context (pre-PR4 copies, printed QRs) verifies MATCH after edit+recompute")

    # bound receipt DOES catch recompute (their claim - verify it)
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    c.events[6]["amount_paise"] = 1
    full_recompute(c)
    okr, det = verify_receipt(c, rec)
    t("SAFE.v2.recompute bound receipt catches edit+recompute", not okr and "member-event" in det, det)

    # prefix deletion caught for bound receipts
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    del c.events[0]; del c.events[0]              # erase M06 entirely
    full_recompute(c)
    okr, det = verify_receipt(c, rec)
    t("SAFE.v2.prefix-del bound receipt catches whole-M06 deletion", not okr and "member-event" in det, det)

    # ============ 3. member binding gaps ============
    # attendance spoof: member whose events are ALL in M06 gets an M07 receipt
    c, r6, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Kavita", c)   # Kavita: M06 loan, M07 repayment
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.attendance receipt for M07 member who only acts in M06 also MATCHes",
      okr and det == "MATCH",
      "member_events spans seq<=root_seq across ALL meetings: no per-meeting participation proof; any historical member can be receipted for a meeting they never attended")
    # partial receipt: drop ONE of the member's own events from member_events -> MATCH
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    assert len(rec["member_events"]) >= 2
    rec["member_events"] = rec["member_events"][:1]              # she "forgot" Rs 100
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.partial member_events subset MATCHes (no completeness check)",
      okr and det == "MATCH",
      "receipt carrying only the FIRST of Sita's deposits still MATCHes: member cannot prove omitted line items; secretary can hand out 'partial' receipts")
    # inflated member_events IS caught
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    rec["member_events"] = rec["member_events"] + [{"seq": 8, "hash": "0" * 64}]
    okr, det = verify_receipt(c, rec)
    t("SAFE.v2.inflated extra member event caught", not okr and "member-event" in det, det)
    # member_events referencing another member's event caught
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    rec["member_events"] = [{"seq": 7, "hash": [e for e in c.events if e["seq"] == 7][0]["hash"]}]
    okr, det = verify_receipt(c, rec)
    t("SAFE.v2.cross-member event caught", not okr and "does-not-belong" in det, det)
    # dup-seq DoS: a same-seq event for another member breaks the HONEST receipt
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    # insert Ghost's dup-seq event BEFORE the close (appending after close trips terminality first)
    ghost_ev = {"seq": 8, "group": c.group_id, "type": "correction", "member": "Ghost",
                "amount_paise": 1, "ts": T, "prev": c.events[-2]["hash"]}
    ghost_ev["hash"] = h(ghost_ev["prev"], ghost_ev["seq"], ghost_ev["type"], ghost_ev["member"],
                         ghost_ev["amount_paise"], ghost_ev["ts"])
    c.events.insert(-1, ghost_ev)
    close = c.events[-1]
    close["prev"] = ghost_ev["hash"]
    close["hash"] = h(close["prev"], close["seq"], close["type"], close["member"], close["amount_paise"], close["ts"])
    okv, _, whyv = c.verify()
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.dupseq seq 8 duplicated by another member -> honest Sita receipt FORKs (availability)",
      okv and not okr and det == "member-event-does-not-belong",
      "verify=%s why=%s receipt=%s: seq_to_member dict last-wins: Ghost's seq 8 shadows Sita's; a member can sabotage another member's receipt with a same-seq correction, all while chain.verify() passes" % (okv, whyv, det))
    # member field in chain vs receipt: member name case/pidgin
    c, _, r7 = make_bound()
    rec = receipt_payload("G-RAJ-042", "M07", r7, "Sita", c)
    rec["member"] = "sita"                        # case differs
    okr, det = verify_receipt(c, rec)
    t("VULN.v2.case-sensitive name exact byte match (no normalization)", not okr and det != "MATCH",
      "det=%s: mobile keyboard case/spelling drift breaks honest receipts (interop), no NFC normalization" % det)

    # ============ 4. server flow / fixes ============
    srv.rebuild()
    httpd = HTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    def req(path, host=None, origin=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        hdrs = dict(headers or {})
        if host: hdrs["Host"] = host
        if origin: hdrs["Origin"] = origin
        conn.request("GET", path, headers=hdrs)
        res = conn.getresponse()
        body = res.read().decode("utf-8", "replace")
        conn.close()
        return res.status, body
    def st():
        return json.loads(req("/api/state")[1])

    # Host guard residual: IPv6 listed but unreachable
    st1, _ = req("/api/state", host="[::1]:8123")
    st2, _ = req("/api/state", host="::1")
    t("VULN.v2.host-ipv6 allowlist includes ::1 but parser rejects every IPv6 Host form",
      st1 == 403 and st2 == 403,
      "hostname = host.split(':')[0] -> '[' or '' : the guard's own allowlist entry ::1 can never pass; IPv6 localhost users get permanent 403")
    st3, _ = req("/api/state", host="localhost.")
    t("chain.v2.host-trailing-dot 'localhost.' rejected (legit DNS form blocked)", st3 == 403, str(st3))
    # Origin substring still passes when paired with valid Host (defense-in-depth gap)
    st4, _ = req("/api/state", host="127.0.0.1:8123", origin="http://evil.example/?u=http://127.0.0.1:8123")
    t("VULN.v2.origin-substring Origin containing '127.0.0.1' anywhere still passes", st4 == 200,
      "Origin check remains substring-based: no exact-origin compare, no Sec-Fetch-Site check")
    # GET CSRF: state-changing GET still executes after close when Origin absent
    srv.rebuild()
    req("/api/close")
    body = req("/api/attack", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"})[1]
    d = json.loads(body)
    s2 = st()
    t("VULN.v2.get-csrf cross-site GET /api/attack (no Origin, Sec-Fetch-Site: cross-site) still mutates chain",
      d.get("verdict") is False and s2["verdict"] is False,
      "after close, GET /api/attack rewrites event 8; browsers send NO Origin for img/form GET and the server never checks Sec-Fetch-Site: CSRF survives the Host fix")
    # open-meeting entry + attack no-op
    srv.rebuild()
    body = json.loads(req("/api/attack")[1])
    t("SAFE.v2.open-attack attack while meeting open is a no-op", body.get("verdict") is None and "meeting-open" in body.get("detail", ""), str(body))
    b1 = st()
    req("/api/entry?type=contribution&paise=100")
    b2 = st()
    t("SAFE.v2.open-entry entries accepted while open", len(b2["events"]) == len(b1["events"]) + 1 and b2["verdict"] is None, str(len(b2["events"])))
    # close then entry -> rejected
    req("/api/close")
    b3 = st()
    stc, bodyc = req("/api/entry?type=contribution&paise=100")
    t("SAFE.v2.closed-entry entries rejected after close (detail + ok False)",
      stc == 200 and json.loads(bodyc).get("ok") is False and "closed" in json.loads(bodyc).get("detail", ""), bodyc)
    # second close rejected
    stc, bodyc = req("/api/close")
    t("SAFE.v2.double-close second close rejected", json.loads(bodyc).get("ok") is False, bodyc)
    # reset orphans the closed M07 receipt when the rebuilt chain differs
    srv.rebuild()
    req("/api/entry?type=contribution&paise=777")
    req("/api/close")
    receipt_before = st()["receipt"]
    srv.STATE["verdict"], _ = verify_receipt(srv.STATE["chain"], receipt_before)
    ok_before = srv.STATE["verdict"] is True
    req("/api/reset")
    req("/api/close")                                  # rebuilt chain WITHOUT the Rs 777 entry
    s2 = st()
    okr_after, det_after = verify_receipt(srv.STATE["chain"], receipt_before)
    t("VULN.v2.reset-orphan reset drops the Rs 777 entry: pre-reset M07 receipt now fails silently",
      ok_before and not okr_after,
      "receipt was valid (MATCH) before reset; after reset+reclose the same receipt fails (%s): the demo UI commits data loss on Reset with no receipt migration/repair path" % det_after)
    # XSS sink audit on new UI: hint box still innerHTML with UNescaped evidence
    t("VULN.v2.xss-hints /api/export hint evidence rendered via innerHTML WITHOUT esc()",
      "innerHTML" in srv.INDEX_HTML and "esc(x.evidence)" not in srv.INDEX_HTML and "esc(x.hint)" not in srv.INDEX_HTML,
      "exportView() builds '<div class=hint>...x.hint @ x.meeting: x.evidence' raw; evidence embeds member names/amounts: attacker who controls any chain string (future file import) gets stored XSS in the auditor box")
    httpd.shutdown()
    return R