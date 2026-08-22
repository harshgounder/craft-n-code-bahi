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
from witness import sign
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
        r6["witnesses"].append(sign({"root": r6["root_hash"], "meeting": "M06"}, "pass-" + w, w))
    # M07 (live meeting): seqs 3..8. Event seq 8 = Sita deposit = attack target.
    chain.add_event(3, "contribution", "Sita", 10000, t)
    chain.add_event(4, "contribution", "Geeta", 10000, t)
    chain.add_event(5, "contribution", "Reema", 10000, t)
    chain.add_event(6, "repayment", "Kavita", 10000, t)   # partial repayment
    chain.add_event(7, "loan", "Asha", 50000, t)
    chain.add_event(8, "contribution", "Sita", 10000, t)  # attack target
    r7 = chain.close_meeting("M07", t)
    for w in WITNESSES:
        r7["witnesses"].append(sign({"root": r7["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    return chain, r7


def rebuild():
    chain, root = build_demo_chain()
    STATE["chain"] = chain
    STATE["root"] = root
    STATE["receipt"] = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])


def apply_attack():
    """Secretary edits the M07 Sita deposit (event seq 8, index 7): Rs 100 -> Rs 10."""
    chain = STATE["chain"]
    chain.events[7]["amount_paise"] = 1000
    STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])


rebuild()   # fresh boot must be fully initialized before serving (G2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/api/state":
            self.send_json({
                "verdict": STATE["verdict"], "detail": STATE["last_detail"],
                "receipt": STATE["receipt"], "events": STATE["chain"].events,
                "balances": balances(STATE["chain"]),
                "root_hash": STATE["root"]["root_hash"],
                "witnesses": STATE["root"]["witnesses"]})
        elif path == "/api/entry":
            etype = qs.get("type", ["contribution"])[0]
            try:
                paise = int(qs.get("paise", ["10000"])[0])
            except ValueError:
                paise = 10000
            if paise < 0:
                paise = 0
            chain = STATE["chain"]
            member = "Sita"
            try:
                chain.add_event(len([e for e in chain.events if e["type"] != "MEETING-CLOSE"]) + 1,
                                etype, member, paise, "2026-08-02T10:00:00")
            except ValueError as e:
                self.send_json({"ok": False, "detail": str(e)})
                return
            STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])
            self.send_json({"ok": True, "detail": STATE["last_detail"]})
        elif path == "/api/close":
            # close + 2 witnesses sign + fresh receipt for Sita
            chain = STATE["chain"]
            nxt = "M08"
            root = chain.close_meeting(nxt, "2026-08-02T10:00:00")
            for w in WITNESSES:
                root["witnesses"].append(sign({"root": root["root_hash"], "meeting": nxt}, "pass-" + w, w))
            STATE["root"] = root
            STATE["receipt"] = receipt_payload("G-RAJ-042", nxt, root, "Sita")
            STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])
            self.send_json({"ok": True, "meeting": nxt, "detail": STATE["last_detail"]})
        elif path == "/api/attack":
            apply_attack()
            self.send_json({"verdict": STATE["verdict"], "detail": STATE["last_detail"]})
        elif path == "/api/reset":
            rebuild()
            self.send_json({"ok": True, "verdict": STATE["verdict"]})
        elif path == "/api/export":
            rep = audit_report(STATE["chain"])
            self.send_json({"report": rep, "csv_rows": export_csv(STATE["chain"]), "hints": rep.get("hints", [])})
        else:
            html = INDEX_HTML
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

    def send_json(self, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


INDEX_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BAHI - the witnessed ledger</title>
<style>
 body{font-family:'Segoe UI',system-ui,sans-serif;background:#f5f2ea;color:#241f18;margin:0;padding:0 24px}
 h1{font-size:28px;margin:18px 0 4px}.sub{color:#6b6153;margin-bottom:18px}
 .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
 .icon{font-size:40px;background:#fff;border:2px solid #d8d2c4;border-radius:16px;padding:12px 16px;cursor:pointer;user-select:none}
 .icon:hover{border-color:#b45309}
 .entry{margin:14px 0;font-size:20px;min-height:26px}
 .tick{color:#15803d;font-weight:700}
 .btn{background:#1e3a2f;color:#fff;border:none;border-radius:10px;padding:12px 18px;font-size:17px;cursor:pointer;margin:6px 6px 0 0}
 .btn.attack{background:#7c1d1d}.btn.gray{background:#6b6153}
 .card{background:#fff;border:1px solid #d8d2c4;border-radius:14px;padding:16px;margin:14px 0;max-width:820px}
 .verdict{margin:14px 0;padding:16px;border-radius:12px;font-size:26px;font-weight:700}
 .ok{background:#dcefe0;color:#14532d}.bad{background:#fbe3e3;color:#7f1d1d}
 .mono{font-family:ui-monospace,monospace;font-size:12px;color:#555;word-break:break-all}
 table{border-collapse:collapse;width:100%;margin-top:8px}
 td,th{border:1px solid #e3dccb;padding:6px 9px;text-align:left;font-size:14px}
 th{background:#eee7d8}
 .hint{font-size:13px;color:#7c1d1d;margin:2px 0}
 .hint.note{color:#6b6153}
</style></head><body>
<h1>BAHI - the witnessed ledger</h1>
<div class="sub">G-RAJ-042 &middot; Weekly meeting M07 &middot; offline &middot; pure hash math</div>

<div class="card">
 <div class="row">
  <div class="icon" onclick="entry('contribution',10000)" title="Deposit Rs 100">&#128176; Rs 100</div>
  <div class="icon" onclick="entry('loan',50000)" title="Borrow Rs 500">&#128181; Rs 500</div>
  <div class="icon" onclick="entry('repayment',10000)" title="Repay Rs 100">&#128200; Rs 100</div>
 </div>
 <div class="entry" id="entryline">&nbsp;</div>
 <button class="btn" onclick="closeMeeting()">Close meeting, 2 witnesses sign, issue receipt</button>
 <button class="btn gray" onclick="refresh()">Re-verify</button>
</div>

<div class="card">
 <div><b>Member receipt (Sita)</b> <span class="mono">QR-ready</span></div>
 <div class="mono" id="receiptbox">...</div>
 <button class="btn attack" onclick="attack()">ATTACK: edit meeting M07, Rs 100 &rarr; Rs 10</button>
</div>

<div class="verdict" id="verdict">checking&hellip;</div>

<div class="card">
 <div><b>Loan tracker</b> (deterministic from chain)</div>
 <table id="loanstable"></table>
</div>

<div class="card">
 <div><b>Chain</b> (append-only, SHA-256)</div>
 <table id="chainstable"></table>
 <div class="hint note">Any edit, deletion, reorder or witness change breaks the chain. Try the ATTACK button.</div>
</div>

<div class="card">
 <div><b>Auditor view</b> <button class="btn gray" id="exportbtn" onclick="exportView()">Refresh hints</button></div>
 <div id="hintsbox" class="hint note">click Refresh hints</div>
 <pre class="mono" id="csvbox" style="max-height:160px;overflow:auto"></pre>
</div>

<script>
function entry(type,paise){
 fetch('/api/entry?type='+type+'&paise='+paise).then(r=>r.json()).then(s=>{
  var names={contribution:'deposits',loan:'borrows',repayment:'repays'};
  var line='Sita '+names[type]+' Rs '+(paise/100)+' <span class="tick">&#9989; recorded in chain</span>';
  document.getElementById('entryline').innerHTML=line;
  refresh();
 });
}
function closeMeeting(){
 fetch('/api/close').then(r=>r.json()).then(s=>{
  var bx=document.getElementById('receiptbox');
  bx.textContent='receipt v1 | group G-RAJ-042 | meeting '+s.meeting+' | member Sita | witnesses 2 | signed root';
  refresh();
 });
}
function attack(){fetch('/api/attack').then(r=>r.json()).then(show);}
function refresh(){fetch('/api/state').then(r=>r.json()).then(show);}
function exportView(){
 fetch('/api/export').then(r=>r.json()).then(d=>{
  var hb=document.getElementById('hintsbox'),h='';
  d.hints.forEach(x=>{h+='<div class="hint">&#9888;&#65039; '+x.hint+' @ '+x.meeting+': '+x.evidence+'</div>';});
  hb.innerHTML=h||'<div class="hint note">no flags</div>';
  document.getElementById('csvbox').textContent=d.csv_rows;
 });
}
function show(s){
 var v=document.getElementById('verdict');
 if(s.verdict){v.className='verdict ok';v.textContent='VERDICT: MATCH - receipt and books agree';}
 else{v.className='verdict bad';v.textContent='VERDICT: '+s.detail+' - receipt FAILS';}
 var tbl=document.getElementById('loanstable'),h='<tr><th>Member</th><th>Loaned</th><th>Repaid</th><th>Outstanding</th></tr>';
 Object.values(s.balances).forEach(b=>{h+='<tr><td>'+b.member+'</td><td>Rs '+(b.loaned_paise/100)+'</td><td>Rs '+(b.repaid_paise/100)+'</td><td><b>Rs '+(b.outstanding_paise/100)+'</b></td></tr>';});
 tbl.innerHTML=h;
 var c=document.getElementById('chainstable'),ch='<tr><th>Seq</th><th>Type</th><th>Member</th><th>Amt</th><th>Hash</th></tr>';
 s.events.forEach(e=>{ch+='<tr><td>'+e.seq+'</td><td>'+e.type+'</td><td>'+e.member+'</td><td>Rs '+(e.amount_paise/100)+'</td><td class="mono">'+(''+e.hash).slice(0,16)+'&hellip;</td></tr>';});
 c.innerHTML=ch;
}
refresh();
</script>
</body></html>"""

if __name__ == "__main__":
    rebuild()
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    print("BAHI demo UI: http://localhost:%d" % PORT)
    srv.serve_forever()