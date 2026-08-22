#!/usr/bin/env python3
"""server.py - BAHI demo web UI. Serves a single-page app: 4-icon entry,
repeat-back, meeting close, receipt display (QR-ish), attack button,
auditor panel with hint flags + export. Pure stdlib http.server.

v1.2 (bug-hunter pass 1 fixes):
- /api/entry actually appends a chain event (icons are live, not static)
- /api/close actually closes the meeting + signs with 2 witnesses + issues
  a fresh member receipt
- auditor panel renders /api/export hints + CSV download on screen
- demo chain includes a prior meeting (M06) so Kavita's repayment is
  supported by her loan: no negative outstanding on honest books.

Run: python3 server.py  (then open http://localhost:8123)
"""
import json, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from chain import BahiChain, receipt_payload, verify_receipt, MIN_WITNESSES
from witness import sign_entry
from loans import balances
from exporter import audit_report, export_csv

PORT = 8123
STATE = {"chain": None, "root": None, "receipt": None, "verdict": None, "last_detail": ""}

WITNESSES = ("Meera", "Laxmi")


def build_demo_chain():
    chain = BahiChain("G-RAJ-042")
    t = "2026-08-02T10:00:00"
    # M06 (prior meeting): Kavita borrowed Rs 20,000. Root seq = 2.
    chain.add_event(1, "loan", "Kavita", 20000, t)
    r6 = chain.close_meeting("M06", t)
    for w in WITNESSES:
        r6["witnesses"].append(sign_entry({"root": r6["root_hash"], "meeting": "M06"}, "pass-" + w, w))
    # M07 (live meeting): seqs 3..8. Event seq 8 = Sita deposit = attack target.
    chain.add_event(3, "contribution", "Sita", 10000, t)
    chain.add_event(4, "contribution", "Geeta", 10000, t)
    chain.add_event(5, "contribution", "Reema", 10000, t)
    chain.add_event(6, "repayment", "Kavita", 10000, t)   # partial repayment
    chain.add_event(7, "loan", "Asha", 50000, t)
    chain.add_event(8, "contribution", "Sita", 10000, t)  # attack target
    # M07 stays OPEN: the UI Close button closes it and issues the receipt.
    # Starting closed broke live entry under the terminality check.
    return chain, None


def rebuild():
    chain, _ = build_demo_chain()
    STATE["chain"] = chain
    STATE["root"] = None            # no receipt until the meeting closes
    STATE["receipt"] = None
    STATE["verdict"] = None
    STATE["last_detail"] = "MEETING OPEN: entries accepted until Close"


def apply_attack():
    """Secretary edits the M07 Sita deposit (event seq 8, index 7): Rs 100 -> Rs 10.
    Only meaningful after the meeting closed (receipt exists)."""
    chain = STATE["chain"]
    if STATE["receipt"] is None:
        STATE["verdict"] = None
        STATE["last_detail"] = "meeting-open: close the meeting first"
        return
    chain.events[7]["amount_paise"] = 1000
    STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])


rebuild()   # fresh boot must be fully initialized before serving (G2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        # RFC 7231: HEAD = GET headers but NO body. do_GET writes no body
        # when self.command is HEAD via _respond (PR5, sujalsshukla).
        self.do_GET()

    def _respond(self, body_bytes, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body_bytes)

    def do_GET(self):
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin", "")
        # localhost scope limit is NOT authentication (hardening report):
        # reject foreign Host and any Origin so a remote page cannot forge
        # state-changing requests against the demo UI (DNS rebinding, CSRF).
        # Host suffix tricks (127.0.0.1.evil.com) are blocked by parsing the
        # REGISTERED hostname (pentest PR6), not a naive prefix check.
        hostname = host.split(":")[0].strip().lower()
        if hostname not in ("127.0.0.1", "localhost", "::1"):
            self.send_error(403, "foreign host rejected")
            return
        if origin and "127.0.0.1" not in origin and "localhost" not in origin:
            self.send_error(403, "foreign origin rejected")
            return
        path = self.path.split("?", 1)[0]
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/api/state":
            root = STATE["root"]
            self.send_json({
                "verdict": STATE["verdict"], "detail": STATE["last_detail"],
                "receipt": STATE["receipt"], "events": STATE["chain"].events,
                "balances": balances(STATE["chain"]),
                "root_hash": root["root_hash"] if root else None,
                "witnesses": root["witnesses"] if root else []})
        elif path == "/api/entry":
            if STATE["receipt"] is not None:
                self.send_json({"ok": False, "detail": "meeting-closed: no more entries"})
                return
            etype = qs.get("type", ["contribution"])[0]
            if etype not in ("contribution", "loan", "repayment", "correction"):
                etype = "contribution"   # whitelist: blocks stored XSS via type (PR6)
            try:
                paise = int(qs.get("paise", ["10000"])[0])
            except ValueError:
                paise = 10000
            if paise < 0:
                paise = 0
            chain = STATE["chain"]
            member = "Sita"
            try:
                chain.add_event(None, etype, member, paise, "2026-08-02T10:00:00")
            except ValueError as e:
                self.send_json({"ok": False, "detail": str(e)})
                return
            chain_ok, bad_seq, why = chain.verify()
            STATE["verdict"] = None
            STATE["last_detail"] = "entry recorded (meeting open, %d events)" % len(chain.events)
            self.send_json({"ok": True, "detail": STATE["last_detail"], "event": chain.events[-1]})
        elif path == "/api/close":
            # close the OPEN M07 + 2 witnesses sign + fresh receipt for Sita
            chain = STATE["chain"]
            if STATE["receipt"] is not None:
                self.send_json({"ok": False, "detail": "meeting already closed"})
                return
            root = chain.close_meeting("M07", "2026-08-02T10:00:00")
            for w in WITNESSES:
                root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))
            STATE["root"] = root
            STATE["receipt"] = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain)
            STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])
            self.send_json({"ok": True, "meeting": "M07", "root_hash": root["root_hash"], "detail": STATE["last_detail"]})
        elif path == "/api/attack":
            if STATE["receipt"] is None:
                self.send_json({"ok": False, "detail": "no receipt yet: close the meeting first"})
                return
            apply_attack()
            self.send_json({"verdict": STATE["verdict"], "detail": STATE["last_detail"]})
        elif path == "/api/reset":
            rebuild()
            self.send_json({"ok": True, "verdict": STATE["verdict"]})
        elif path == "/api/export":
            rep = audit_report(STATE["chain"])
            self.send_json({"report": rep, "csv_rows": export_csv(STATE["chain"]), "hints": rep.get("hints", [])})
        else:
            self._respond(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")

    def send_json(self, obj):
        self._respond(json.dumps(obj).encode("utf-8"), "application/json")


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="BAHI: member-witnessed offline ledger for Indian self-help groups. SHA-256 chain, signed meeting roots, member receipts, fork detection.">
<title>BAHI - the witnessed ledger</title>
<style>
:root{
  --paper:#F1E7CE; --paper-2:#E7D9B8; --panel:#FFF9EA; --ink:#2B2118;
  --ink-soft:#5C4F3E; --ink-faint:#6E6050; --rule:#B5A37C; --rule-soft:#DDD2B4;
  --saffron:#E08A1E; --saffron-deep:#9A5608; --saffron-soft:#F6DFB8;
  --green:#1F6B3B; --green-soft:#DCE9DC; --red:#A32F2F; --red-soft:#F3DDD8;
  --disp:Georgia,'Times New Roman',serif;
  --sans:'Trebuchet MS','Noto Sans Devanagari',system-ui,sans-serif;
  --mono:'Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--paper);color:var(--ink);font-family:var(--sans);padding:0 0 24px;
  background-image:repeating-linear-gradient(0deg,transparent 0 27px,var(--rule-soft) 27px 28px),
  radial-gradient(ellipse 60% 35% at 85% -5%,var(--saffron-soft) 0%,transparent 70%),
  radial-gradient(ellipse 45% 30% at 8% 108%,var(--saffron-soft) 0%,transparent 65%);}
.wrap{max-width:1180px;margin:0 auto;padding:0 18px}
/* header */
.mast{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 0 10px;border-bottom:2px solid var(--ink)}
.brand{display:flex;align-items:baseline;gap:12px}
.brand h1{font-family:var(--disp);font-size:34px;letter-spacing:.5px}
.brand .tag{font-size:12.5px;color:var(--ink-soft);letter-spacing:.4px}
.brand .tag b{color:var(--saffron-deep);font-weight:700}
.mode{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;letter-spacing:1.5px;
  border:1.5px solid var(--ink);padding:6px 10px;background:var(--ink);color:var(--paper);text-transform:uppercase}
.mode .dot{width:9px;height:9px;border-radius:50%;background:var(--saffron);box-shadow:0 0 0 3px var(--saffron-soft);animation:pulse 2s infinite}
@keyframes pulse{50%{opacity:.45}}
/* bento grid */
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px;margin-top:14px;align-items:start}
.card{background:var(--panel);border:1.5px solid var(--rule);border-radius:10px;padding:14px;position:relative}
.card h2{font-family:var(--disp);font-size:18px;margin-bottom:2px}
.card .sub{font-size:13px;color:var(--ink-soft);margin-bottom:8px}
.eyebrow{font-family:var(--mono);font-size:10.5px;letter-spacing:2px;color:var(--saffron-deep);text-transform:uppercase;margin-bottom:1px}
.c7{grid-column:span 7}.c5{grid-column:span 5}.c8{grid-column:span 8}.c4{grid-column:span 4}.c12{grid-column:span 12}
/* icon tiles */
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.tile{border:2px solid var(--ink);border-radius:10px;background:var(--paper);padding:10px 6px 8px;
  display:flex;flex-direction:column;align-items:center;gap:5px;cursor:pointer;user-select:none;min-height:84px;
  transition:transform .12s,box-shadow .12s,background .12s}
.tile:hover{transform:translateY(-2px);box-shadow:0 4px 0 var(--ink)}
.tile:active{transform:translateY(1px);box-shadow:none}
.tile.sel{background:var(--saffron);border-color:var(--saffron-deep);box-shadow:0 4px 0 var(--saffron-deep)}
.tile .lbl{font-size:14px;font-weight:600;text-align:center}
.tile .amt{font-family:var(--mono);font-size:12px;color:var(--ink-soft)}
.tile.sel .amt{color:var(--ink)}
.tile svg{width:34px;height:34px;stroke:var(--ink);stroke-width:1.7;fill:none;stroke-linecap:round;stroke-linejoin:round}
/* console steps */
.steps{display:flex;gap:6px;margin:2px 0 8px;flex-wrap:wrap}
.step{font-family:var(--mono);font-size:10.5px;letter-spacing:1px;border:1px solid var(--rule);border-radius:99px;padding:4px 10px;color:var(--ink-soft);background:var(--paper)}
.step b{color:var(--saffron-deep)}
.tally{font-family:var(--mono);font-size:12px;color:var(--ink-soft);margin:-4px 0 8px}
.tally b{color:var(--ink)}
/* member chips */
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.chip{border:1.5px solid var(--ink);background:var(--paper);border-radius:999px;padding:7px 14px;font-size:14px;
  font-weight:600;cursor:pointer;font-family:var(--sans)}
.chip.sel{background:var(--ink);color:var(--paper);box-shadow:0 3px 0 var(--saffron-deep);transform:translateY(-1px)}
.chip small{color:var(--ink-soft);font-weight:400}
/* repeat back / actions */
.repeat{font-family:var(--disp);font-style:italic;font-size:17px;min-height:26px;color:var(--ink);
  border-left:3px solid var(--saffron);padding-left:12px;margin:4px 0 8px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{font-family:var(--sans);font-size:15px;font-weight:700;border:2px solid var(--ink);border-radius:8px;
  background:var(--ink);color:var(--paper);padding:12px 16px;min-width:148px;cursor:pointer;box-shadow:0 3px 0 var(--ink);
  transition:transform .1s,box-shadow .1s}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 0 var(--ink)}
.btn:active{transform:translateY(2px);box-shadow:none}
.btn.ghost{background:var(--paper);color:var(--ink)}
.btn.danger{background:var(--red);border-color:var(--red);color:#fff}
.btn.saffron{background:var(--saffron);border-color:var(--saffron-deep);color:var(--ink)}
/* a11y */
:focus-visible{outline:3px solid var(--saffron-deep);outline-offset:2px;border-radius:6px}
.tile:focus-visible,.chip:focus-visible{outline-offset:3px}
#verdict[aria-live="polite"]{min-height:56px}
@media print{
  body{background:#fff}
  .mast,.actions,.row2,.hints,.foot,.tally{display:none!important}
  .grid{grid-template-columns:1fr}
  .card{border-color:#000;break-inside:avoid}
  .card.c7,.card.c8,.card.c4,.card.c5{grid-column:span 1}
}
@media (prefers-reduced-motion: reduce){
  *{animation:none!important;transition:none!important;scroll-behavior:auto!important}
}
/* receipt */
.receipt{font-family:var(--mono);font-size:12.5px;line-height:1.7;background:var(--paper-2);
  border:1.5px dashed var(--ink-faint);border-radius:8px;padding:10px;word-break:break-all;min-height:110px}
.receipt .lbl{display:inline-block;width:78px;color:var(--ink-faint);text-transform:uppercase;letter-spacing:1px;font-size:9.5px}
.fp{display:grid;grid-template-columns:repeat(12,1fr);gap:3px;margin:8px 0;width:132px}
.fp i{aspect-ratio:1;border-radius:2px;background:var(--ink-faint)}
.fp i.on{background:var(--ink)}
/* verdict stamp */
.stamp{display:flex;align-items:center;gap:14px;padding:11px 14px;border-radius:8px;font-weight:800;font-size:19px;
  letter-spacing:1px;text-transform:uppercase;font-family:var(--disp);background:var(--paper-2);border:2px solid var(--rule);color:var(--ink-soft)}
.stamp.show{display:flex}
.stamp.await{justify-content:center;background:var(--saffron-soft);color:var(--saffron-deep);font-size:13px;letter-spacing:2px;font-family:var(--mono);border-color:var(--saffron-deep)}
.stamp.ok{background:var(--green-soft);color:var(--green);border:2px solid var(--green)}
.stamp.bad{background:var(--red-soft);color:var(--red);border:2px solid var(--red)}
.stamp .st{transform:rotate(-2deg);display:inline-block;border:3px double currentColor;border-radius:6px;
  padding:4px 12px;font-size:17px;animation:slap .3s ease-out}
@keyframes slap{0%{transform:rotate(14deg) scale(1.6);opacity:0}60%{transform:rotate(-4deg) scale(.96);opacity:1}100%{transform:rotate(-2deg) scale(1)}}
.stamp .why{font-size:13px;font-weight:600;letter-spacing:.3px;text-transform:none;font-family:var(--sans)}
/* receipt upgrade */
.rcpt-plain{font-size:14.5px;font-family:var(--disp);line-height:1.45;margin-bottom:8px}
.rcpt-plain b{color:var(--saffron-deep)}
.wits{display:flex;gap:8px;margin:10px 0}
.wit{display:flex;align-items:center;gap:7px;border:1.5px solid var(--ink);border-radius:999px;padding:4px 10px 4px 4px;background:var(--paper);font-size:12px;font-weight:700}
.wit i{width:22px;height:22px;border-radius:50%;background:var(--ink);color:var(--paper);font-style:normal;display:flex;align-items:center;justify-content:center;font-size:11px;font-family:var(--mono)}
.vstamp{position:absolute;top:14px;right:14px;font-family:var(--mono);font-size:10px;letter-spacing:2px;border:2px solid var(--green);color:var(--green);border-radius:4px;padding:3px 8px;transform:rotate(3deg);background:var(--green-soft)}
.hashgrp{font-family:var(--mono);font-size:11.5px;color:var(--ink-soft);word-break:keep-all;line-height:1.8}
/* ledger table */
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{font-family:var(--mono);font-size:10.5px;letter-spacing:1.2px;text-transform:uppercase;color:var(--ink-soft);
  border-bottom:2px solid var(--ink);padding:6px 8px;text-align:left}
td{border-bottom:1px solid var(--rule);padding:6px 8px;font-variant-numeric:tabular-nums}
td.mono{font-family:var(--mono);font-size:12px;color:var(--ink-soft)}
tr.meet td{background:var(--saffron-soft);font-weight:700}
tr.bad td{background:var(--red-soft);color:var(--red);font-weight:700}
/* loans */
.loans{display:flex;flex-direction:column;gap:10px}
.loan{background:var(--paper);border:1.5px solid var(--rule);border-radius:8px;padding:8px 10px}
.loan{display:grid;grid-template-columns:34px 1fr;gap:10px;align-items:center}
.loan .av{width:32px;height:32px;border-radius:50%;background:var(--saffron);color:var(--ink);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;font-family:var(--sans);border:2px solid var(--saffron-deep)}
.loan .nm{font-weight:700;font-size:15px;display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.loan .due{font-family:var(--disp);font-size:18px;color:var(--ink)}
.loan .tag{font-family:var(--mono);font-size:9.5px;letter-spacing:1px;border:1px solid #7C4505;color:var(--paper);border-radius:99px;padding:2px 8px;text-transform:uppercase;background:#7C4505}
.loan .bar{height:8px;background:var(--rule-soft);border-radius:99px;margin-top:7px;overflow:hidden}
.loan .bar i{display:block;height:100%;background:var(--saffron);border-radius:99px}
.loan .meta{font-family:var(--mono);font-size:11.5px;color:var(--ink-soft);margin-top:5px}
/* auditor hints */
.hints{list-style:none;display:flex;flex-direction:column;gap:6px}
.hints li{border-left:3px solid var(--red);background:var(--red-soft);border-radius:0 8px 8px 0;padding:8px 10px;font-size:14px;display:flex;gap:9px;align-items:flex-start}
.hints li.serious{border-left-color:var(--red)}
.hints li.soft{border-left-color:var(--saffron-deep);background:var(--saffron-soft)}
.hints li svg{width:16px;height:16px;flex:0 0 16px;margin-top:2px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.hints li>div{display:flex;flex-direction:column;gap:2px}
.hints li b{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--red)}
.hints li.soft b{color:var(--saffron-deep)}
.hints li .ev{color:var(--ink-soft);font-size:13px;display:block}
.hintsum{font-family:var(--mono);font-size:12px;color:var(--ink-soft);margin-bottom:6px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
.foot{margin-top:18px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);letter-spacing:1px;
  text-align:center;border-top:1px solid var(--rule);padding-top:10px}
@media(max-width:900px){.c7,.c5,.c8,.c4{grid-column:span 12}.tiles{grid-template-columns:repeat(2,1fr)}}
.twrap{overflow-x:auto;max-width:100%}
</style>
</head>
<body>
<div class="wrap">

<header class="mast">
  <div class="brand">
    <h1>BAHI</h1>
    <div class="tag">the witnessed ledger <b>·</b> member-held receipts, offline</div>
  </div>
  <div class="mode"><span class="dot"></span><span>Fixture + Live</span></div>
</header>

<main class="grid">

  <section class="card c7">
    <div class="eyebrow">Meeting Console</div>
    <h2>Record an entry</h2>
    <div class="sub">Group G-RAJ-042 · weekly meeting · everything is signed, nothing is editable</div>
    <div class="steps"><span class="step"><b>1</b> PICK ICON</span><span class="step"><b>2</b> GREEN TICK</span><span class="step"><b>3</b> CLOSE + RECEIPTS</span></div>
    <div class="tiles" id="tiles"></div>
    <div class="repeat" id="repeat">Tap an icon, then confirm with the green tick.</div>
    <div class="tally" id="tally">entries recorded for Sita · single shared meeting device (fixture)</div>
    <div class="actions">
      <button class="btn saffron" id="confirmBtn">Green tick: confirm entry</button>
      <button class="btn" id="closeBtn">Close meeting + 2 witnesses sign</button>
    </div>
  </section>

  <section class="card c5">
    <div class="eyebrow">Member Receipt</div>
    <h2>Sita's receipt</h2>
    <div class="sub">printed QR equivalent · verify anytime, offline, forever</div>
    <div class="vstamp" id="vstamp">UNVERIFIED</div>
    <div class="rcpt-plain" id="rcptplain">loading…</div>
    <div class="receipt" id="receiptbox">loading…</div>
    <div class="wits" id="wits"></div>
    <div class="fp" id="fp"></div>
    <div class="row2">
      <button class="btn ghost" id="reverifyBtn">Re-verify</button>
      <button class="btn ghost" id="resetBtn">Reset to honest ledger</button>
      <button class="btn danger" id="attackBtn">Simulate tamper: Rs 100 → Rs 10</button>
    </div>
    <div style="margin-top:8px;font-size:11.5px;color:var(--ink-soft);line-height:1.45">
      The button edits Sita's contribution (event 8) from Rs 100 → Rs 10 in memory. Receipts were signed over the original root, so the books can no longer verify. Demo fixture, not fraud prevention.
    </div>
  </section>

  <section class="card c12">
    <div class="stamp" id="verdict" aria-live="polite" role="status"></div>
    <div id="lastDetail" style="margin-top:8px;font-family:var(--mono);font-size:12px;color:var(--red)"></div>
  </section>

  <section class="card c8">
    <div class="eyebrow">The Ledger</div>
    <h2>Append-only chain</h2>
    <div class="sub">SHA-256 · edit anything past and every later hash breaks</div>
    <div class="twrap"><table><thead><tr><th>Seq</th><th>Type</th><th>Member</th><th>Amount</th><th>Timestamp</th><th>Hash</th></tr></thead>
    <tbody id="chainbody"><tr><td colspan="6">loading…</td></tr></tbody></table></div>
  </section>

  <section class="card c4">
    <div class="eyebrow">Loan Tracker</div>
    <h2>Who owes what</h2>
    <div class="sub">deterministic from the chain</div>
    <div class="loans" id="loans">loading…</div>
  </section>

  <section class="card c12">
    <div class="eyebrow">Auditor View</div>
    <h2>Federation report</h2>
    <div class="sub">block / district audit, no visit needed</div>
    <div class="hintsum" id="hintsum">…</div>
    <ul class="hints" id="hints"></ul>
    <div class="row2">
      <button class="btn ghost" id="exportJsonBtn">Export audit JSON</button>
      <button class="btn ghost" id="exportCsvBtn">Export CSV</button>
    </div>
  </section>

</main>

<footer class="foot">OFFLINE · PURE STDLIB · DETERMINISTIC · THE MEMBER IS THE WITNESS · PS-17</footer>
</div>

<script>
const TYPES = [
  {t:"contribution", lbl:"Contribution", amt:"Rs 100", paise:10000, icon:'<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6.5" rx="7" ry="3"/><path d="M5 6.5v11c0 1.66 3.13 3 7 3s7-1.34 7-3v-11"/><path d="M5 12c0 1.66 3.13 3 7 3s7-1.34 7-3"/></svg>'},
  {t:"loan", lbl:"Loan issued", amt:"Rs 500", paise:50000, icon:'<svg viewBox="0 0 24 24"><path d="M4 17c3-6 9-8 15-7"/><path d="M15 6l4 4-4 4"/><circle cx="7" cy="7" r="2.6"/></svg>'},
  {t:"repayment", lbl:"Repayment", amt:"Rs 200", paise:20000, icon:'<svg viewBox="0 0 24 24"><path d="M20 17c-3-6-9-8-15-7"/><path d="M9 6L5 10l4 4"/><circle cx="17" cy="7" r="2.6"/></svg>'},
  {t:"correction", lbl:"Correction", amt:"reversal", paise:0, icon:'<svg viewBox="0 0 24 24"><path d="M4 20h4L20 8l-4-4L4 16v4z"/><path d="M14 6l4 4"/></svg>'}
];
let selType = TYPES[0];
const $=id=>document.getElementById(id);

function phrase(){
  const t=selType, m="Sita", amt=t.paise?("Rs "+(t.paise/100).toFixed(0)):"the reversal";
  const p={contribution:"deposits",loan:"borrows",repayment:"repays",correction:"flags a correction for"}[t.t];
  return "Voice repeat: “"+(t.t==="correction"?m+" "+p+" "+amt:m+" "+p+" "+amt)+"”";
}
function renderTiles(){
  $("tiles").innerHTML=TYPES.map((t,i)=>'<div class="tile'+(i===TYPES.indexOf(selType)?' sel':'')+'" data-i="'+i+'">'+
    t.icon+'<div class="lbl">'+t.lbl+'</div><div class="amt">'+t.amt+'</div></div>').join("");
  document.querySelectorAll(".tile").forEach(el=>el.onclick=()=>{selType=TYPES[+el.dataset.i];renderTiles();$("repeat").textContent=phrase();});
  $("repeat").textContent=phrase();
}
let firstRun=true;
let __seen={};
async function refresh(){
  if(firstRun){$("repeat").textContent="Tap an icon, choose the member, then confirm with the green tick.";firstRun=false;}
  const s=await (await fetch("/api/state")).json();
  // verdict stamp
  const v=$("verdict");
  if(s.verdict){v.className="stamp show ok";v.innerHTML='<span class="st">MATCH</span><span class="why">receipt and books agree · root '+s.root_hash.slice(0,12)+'…</span>';}
  else if(s.verdict===false){v.className="stamp show bad";v.innerHTML='<span class="st">FORK AT EVENT '+s.detail.replace("FORK-AT-EVENT-","").split(" ")[0]+'</span><span class="why">'+s.detail+' · the receipt FAILS</span>';}
  else{v.className="stamp await";v.textContent="PENDING · MEETING OPEN · "+s.events.filter(e=>e.type!=="MEETING-CLOSE").length+" ENTRIES · CLOSE TO SIGN + ISSUE RECEIPTS";}
  // receipt
  const r=s.receipt;
  $("attackBtn").disabled=!r; $("attackBtn").title=r?"":"Close the meeting first";
  if(r){
    const root=String(r.root);
    $("receiptbox").innerHTML=
      "<div><span class='lbl'>Receipt</span>v1</div>"+
      "<div><span class='lbl'>Group</span>"+r.group+"</div>"+
      "<div><span class='lbl'>Meeting</span>"+r.meeting+"</div>"+
      "<div><span class='lbl'>Member</span>"+r.member+"</div>"+
      "<div><span class='lbl'>Root</span>"+root.slice(0,8)+"-"+root.slice(8,16)+"-"+root.slice(16,24)+"-"+root.slice(24,32)+"…</div>"+
      "<div><span class='lbl'>Witness</span>"+r.witnesses.map(w=>String(w.witness||w.w||w).slice(0,10)).join(" + ")+"</div>";
    const sigs=r.witnesses.map(w=>w.sig||w.w||w);
    const wits=r.witnesses.map(w=>String(w.witness||w.w||w).replace("pass-","").slice(0,12));
    const lineItems=r.member_events&&r.member_events.length?(" It proves her <b>"+r.member_events.length+"</b> line item(s): seq "+r.member_events.map(m=>m.seq).join(", ")+"."):"";
    $("rcptplain").innerHTML="<b>"+r.member+"</b> holds a receipt for meeting <b>"+r.meeting+"</b> in group <b>"+r.group+"</b>. Two witnesses signed the close: <b>"+wits.join(" and ")+"</b>."+lineItems+" If anyone edits the books later, this receipt will name the exact event.";
    $("wits").innerHTML=wits.map((n,i)=>"<span class='wit' title='witness signature'><i>W"+(i+1)+"</i>"+n.slice(0,6)+"…</span>").join("");
    $("vstamp").textContent=s.verdict?"VERIFIED":"FORKED";
    $("vstamp").style.borderColor=s.verdict?"var(--green)":"var(--red)";
    $("vstamp").style.color=s.verdict?"var(--green)":"var(--red)";
    $("vstamp").style.background=s.verdict?"var(--green-soft)":"var(--red-soft)";
  } else {
    $("receiptbox").textContent="no receipt yet";
    $("rcptplain").textContent="Close a meeting to issue the member receipt.";
    $("wits").innerHTML="";
  }
  // fingerprint grid from root hash bits
  const bits=(r?String(r.root):"0000").split("").map(c=>parseInt(c,16)%2);
  $("fp").innerHTML=bits.slice(0,60).map(b=>"<i"+(b?" class='on'":"")+"></i>").join("");
  // chain
  if(s.verdict===true&&s.events){s.events.forEach(e=>{if(e.type!=="MEETING-CLOSE")__seen[e.seq]=e.amount_paise;});}
  if(s.verdict===false){
    const diffs=Object.keys(__seen).filter(seq=>s.events.some(e=>e.seq==seq&&e.amount_paise!==__seen[seq]))
      .map(seq=>{const e=s.events.find(x=>x.seq==seq);return "event "+seq+": Rs "+(__seen[seq]/100).toFixed(0)+" differs from chain Rs "+(e.amount_paise/100).toFixed(0);});
    if(diffs.length){
      $("lastDetail").textContent="Receipt remembers: "+diffs.join("; ");
      const st=$("verdict").querySelector(".why");
      if(st)st.textContent+=" · receipt remembers "+diffs.join("; ");
    }
  }
  const liveCount=s.events.filter(e=>e.type!=="MEETING-CLOSE").length;
  const closedMeetings=s.events.filter(e=>e.type==="MEETING-CLOSE").length;
  $("tally").innerHTML="<b>"+liveCount+"</b> events · state: <b>"+(s.verdict===undefined||s.verdict===null?"PENDING":(s.verdict?"MATCH":"FORK"))+"</b> · meetings closed: "+closedMeetings+(r&&r.meeting?" · receipt for "+r.meeting:"");
  $("chainbody").innerHTML=s.events.map((e,i)=>{
    const isClose=e.type==="MEETING-CLOSE", isBad=e.type!=="MEETING-CLOSE"&&s.verdict===false&&i===(s.detail.match(/EVENT-([0-9]+)/)||[])[1]-1;
    return "<tr id='row-"+e.seq+"' class='"+(isClose?"meet":isBad?"bad":"")+"'><td>"+e.seq+"</td><td>"+(isClose?"MEETING CLOSE":e.type)+"</td><td>"+e.member+"</td><td>"+(isClose?"-":(isBad?"<b>Rs "+(e.amount_paise/100).toFixed(0)+"</b> <span style='font-family:var(--mono);font-size:9.5px;text-transform:uppercase;border:1px solid currentColor;border-radius:3px;padding:0 4px'>altered</span>":"Rs "+(e.amount_paise/100).toFixed(0)))+"</td><td class='mono' title='"+e.ts+"'>"+e.ts+"</td><td class='mono' title='full hash: "+e.hash+"'>"+String(e.hash).slice(0,14)+"…</td></tr>";
  }).join("");

  // loans
  const bs=Object.values(s.balances||{});
  $("loans").innerHTML=bs.length?bs.map(b=>{
    const pct=Math.min(100,Math.round(100*(b.repaid_paise/(b.loaned_paise||1))));
    const av=b.member.slice(0,2).toUpperCase();
    return "<div class='loan'><div class='av'>"+av+"</div><div><div class='nm'><span>"+b.member+"</span><span>"+(b.outstanding_paise>0?"<span class='due'>Rs "+(b.outstanding_paise/100).toFixed(0)+" due</span>":(b.overpaid_paise||0)>0?"<span class='tag'>overpaid Rs "+(b.overpaid_paise/100).toFixed(0)+"</span>":"<span class='tag'>clear</span>")+"</span></div><div class='bar'><i style='width:"+pct+"%'></i></div><div class='meta'>loaned Rs "+(b.loaned_paise/100).toFixed(0)+" · repaid Rs "+(b.repaid_paise/100).toFixed(0)+" · "+pct+"% repaid</div></div></div>";
  }).join(""):"<div class='sub'>no loans yet</div>";
  // hints
  const ex=await (await fetch("/api/export")).json();
  const hz=(ex.hints&&ex.hints.length)?ex.hints:[];
  const serious=hz.filter(h=>["duplicate_identity","missing_witness","corrupt_chain"].includes(h.hint)).length;
  $("hints").innerHTML=hz.length?hz.map(h=>{
    const sev=["duplicate_identity","missing_witness","corrupt_chain"].includes(h.hint)?"serious":"soft";
    const ic=sev==="serious"?"<svg viewBox='0 0 24 24'><path d='M12 3L2 20h20L12 3z'/><path d='M12 9v5'/><path d='M12 17.5v.5'/></svg>":"<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='9'/><path d='M12 8v5'/><path d='M12 16.5v.5'/></svg>";
    return "<li class='"+sev+"'>"+ic+"<div><b>"+h.hint+"</b> · "+h.meeting+"<span class='ev'>"+h.evidence+"</span></div></li>";
  }).join(""):"<li style='border-color:var(--green);background:var(--green-soft)'><b style='color:var(--green)'>no flags</b><span class='ev'>all rules evaluated deterministically</span></li>";
  $("hintsum").innerHTML=hz.length?"<span style='border:1px solid var(--red);color:var(--red);border-radius:99px;padding:2px 8px;margin-right:6px'>"+serious+" serious</span><span style='border:1px solid var(--saffron-deep);color:var(--saffron-deep);border-radius:99px;padding:2px 8px'>"+(hz.length-serious)+" advisory</span> · deterministic rules, no ML":"<span style='border:1px solid var(--green);color:var(--green);border-radius:99px;padding:2px 8px'>0 flags · clean</span>";
}
$("confirmBtn").onclick=async()=>{
  $("confirmBtn").disabled=true; $("confirmBtn").textContent="Posting…";
  const r=await fetch("/api/entry?type="+encodeURIComponent(selType.t)+"&paise="+selType.paise);
  const j=await r.json();
  $("confirmBtn").disabled=false; $("confirmBtn").textContent="Green tick: confirm entry";
  if(j.ok){$("repeat").textContent="✓ recorded: Sita "+selType.t+" Rs "+(selType.paise/100).toFixed(0)+" · seq "+j.event.seq+" · "+j.detail;refresh();}
  else alert(j.detail||j.error||"entry failed");
};
$("closeBtn").onclick=async()=>{const r=await(await fetch("/api/close")).json();if(r.ok){$("repeat").textContent="✓ meeting "+r.meeting+" closed · witnesses Meera+Laxmi signed · "+r.detail;refresh();}};
$("reverifyBtn").onclick=refresh;
$("resetBtn").onclick=async()=>{await fetch("/api/reset");__seen={};await refresh();};
$("attackBtn").onclick=async()=>{await fetch("/api/attack");$("repeat").textContent="⚠ tamper applied: event 8 (Sita Rs 100) was edited to Rs 10 in memory. Receipts still hold the original root.";refresh();};
$("exportJsonBtn").onclick=async()=>{const d=await(await fetch("/api/export")).json();download("bahi-audit.json",JSON.stringify(d.report,null,1));};
$("exportCsvBtn").onclick=async()=>{const d=await(await fetch("/api/export")).json();const rows=Array.isArray(d.csv_rows)?d.csv_rows:d.csv_rows.split("\n");download("bahi-chain.csv",rows.join("\n"));};
function download(name,text){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type:"text/plain"}));a.download=name;a.click();}
renderTiles();refresh();setInterval(refresh,4000);
</script>
</body>
</html>"""


if __name__ == "__main__":
    rebuild()
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    print("BAHI demo UI: http://localhost:%d" % PORT)
    srv.serve_forever()