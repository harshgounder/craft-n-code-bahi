#!/usr/bin/env python3
"""server.py - BAHI demo web UI. Serves a single-page app: 4-icon entry,
repeat-back, meeting close, receipt display (QR-ish), attack button,
auditor view with hint flags. Pure stdlib http.server. Deterministic core.

Demo flow (matches tests):
  add contributions -> close meeting -> 2 witnesses sign ->
  member receipt printed -> ATTACK button edits event 7 ->
  receipt verification shows FORK.

Run: python3 server.py  (then open http://localhost:8123)
"""
import json, os, threading, webbrowser, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from chain import BahiChain, receipt_payload, verify_receipt
from witness import sign
from loans import balances, format_rupees

PORT = 8123
STATE = {"chain": None, "receipt": None, "verdict": None, "last_detail": ""}

def build_demo_chain():
    chain = BahiChain("G-RAJ-042")
    events = [
        (1, "contribution", "Sita", 10000), (2, "contribution", "Geeta", 10000),
        (3, "contribution", "Reema", 10000), (4, "repayment", "Kavita", 20000),
        (5, "loan", "Asha", 50000), (6, "contribution", "Sita", 10000),
        (7, "contribution", "Sita", 10000),
    ]
    for seq, etype, member, paise in events:
        chain.add_event(seq, etype, member, paise, "2026-08-02T10:00:00")
    root = chain.close_meeting("M07", "2026-08-02T10:00:00")
    for w in ("Meera", "Laxmi"):
        root["witnesses"].append(sign({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    return chain, root

def rebuild():
    chain, root = build_demo_chain()
    STATE["chain"] = chain
    STATE["root"] = root
    STATE["receipt"] = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/state"):
            self.send_json({
                "verdict": STATE["verdict"],
                "detail": STATE["last_detail"],
                "receipt": STATE["receipt"],
                "events": STATE["chain"].events,
                "balances": balances(STATE["chain"]),
                "root_hash": STATE["root"]["root_hash"],
            })
        elif self.path.startswith("/api/attack"):
            chain = STATE["chain"]
            chain.events[6]["amount_paise"] = 1000   # Rs 100 -> Rs 10 on event 7
            STATE["verdict"], STATE["last_detail"] = verify_receipt(chain, STATE["receipt"])
            self.send_json({"verdict": STATE["verdict"], "detail": STATE["last_detail"]})
        elif self.path.startswith("/api/reset"):
            rebuild()
            self.send_json({"ok": True, "verdict": STATE["verdict"]})
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
 .icon{font-size:44px;background:#fff;border:2px solid #d8d2c4;border-radius:16px;padding:14px 18px;cursor:pointer;user-select:none}
 .icon:hover{border-color:#b45309}.icon.sel{background:#b45309;color:#fff;border-color:#b45309}
 .entry{margin:14px 0;font-size:20px}
 .btn{background:#1e3a2f;color:#fff;border:none;border-radius:10px;padding:12px 18px;font-size:17px;cursor:pointer;margin:6px 6px 0 0}
 .btn.attack{background:#7c1d1d}.btn.gray{background:#6b6153}
 .card{background:#fff;border:1px solid #d8d2c4;border-radius:14px;padding:16px;margin:14px 0;max-width:760px}
 .verdict{margin:14px 0;padding:16px;border-radius:12px;font-size:26px;font-weight:700}
 .ok{background:#dcefe0;color:#14532d}.bad{background:#fbe3e3;color:#7f1d1d}
 .mono{font-family:ui-monospace,monospace;font-size:12px;color:#555;word-break:break-all}
 table{border-collapse:collapse;width:100%;margin-top:8px}
 td,th{border:1px solid #e3dccb;padding:6px 9px;text-align:left;font-size:14px}
 th{background:#eee7d8}
 .hint{font-size:12px;color:#7c1d1d;margin:2px 0}
</style></head><body>
<h1>BAHI &mdash; the witnessed ledger</h1>
<div class="sub">G-RAJ-042 &middot; Weekly meeting M07 &middot; offline &middot; pure hash math</div>

<div class="card">
 <div class="row">
  <div class="icon" onclick="entry('contribution',10000)">&#128176; Contribution</div>
  <div class="icon" onclick="entry('loan',50000)">&#128176; Loan</div>
  <div class="icon" onclick="entry('repayment',20000)">&#128176; Repayment</div>
  <div class="icon" onclick="entry('correction',0)">&#9998;&#65039; Correction</div>
 </div>
 <div class="entry" id="entryline">&nbsp;</div>
 <button class="btn" onclick="closeMeeting()">Close meeting + two witnesses sign</button>
 <button class="btn gray" onclick="refresh()">Re-verify</button>
</div>

<div class="card">
 <div><b>Member receipt (Sita)</b> &mdash; printed QR equivalent</div>
 <div class="mono" id="receiptbox">...</div>
 <button class="btn attack" onclick="attack()">ATTACK: edit meeting M07, Rs 100 &rarr; Rs 10</button>
</div>

<div class="verdict" id="verdict">checking&hellip;</div>

<div class="card">
 <div><b>Loan tracker</b> (deterministic from chain)</div>
 <table id="loanstable"></table>
</div>

<div class="card">
 <div><b>Chain</b> (append-only, SHA-256, %d events)</div>
 <table id="chainstable"></table>
 <div class="hint">Hint flags: any amount edit, deletion, reorder or witness change breaks the chain.</div>
</div>

<script>
function entry(type,paise){fetch('/api/state').then(r=>r.json()).then(s=>{
 var line="";
 if(type==='contribution')line="Sita deposits Rs "+(paise/100)+" &mdash; voice repeats: &ldquo;Sita, contribution, one hundred rupees&rdquo; &mdash; green tick";
 if(type==='loan')line="Asha borrows Rs "+(paise/100)+" at group interest &mdash; voice repeats &mdash; green tick";
 if(type==='repayment')line="Kavita repays Rs "+(paise/100)+" &mdash; voice repeats &mdash; green tick";
 if(type==='correction')line="Correction flagged &mdash; reversal + replacement only, no edits";
 document.getElementById('entryline').innerHTML=line;});
}
function closeMeeting(){
 fetch('/api/state').then(r=>r.json()).then(s=>{
  document.getElementById('receiptbox').textContent=
   'receipt v1 | group G-RAJ-042 | meeting M07 | member Sita | root '+s.root_hash;
  refresh();});
}
function attack(){fetch('/api/attack').then(r=>r.json()).then(show);}
function refresh(){fetch('/api/state').then(r=>r.json()).then(show);}
function show(s){
 var v=document.getElementById('verdict');
 if(s.verdict){v.className='verdict ok';v.textContent='VERDICT: MATCH &mdash; receipt and books agree';}
 else{v.className='verdict bad';v.textContent='VERDICT: '+s.detail+' &mdash; receipt FAILS';}
 var tbl=document.getElementById('loanstable'),h='<tr><th>Member</th><th>Loaned</th><th>Repaid</th><th>Outstanding</th></tr>';
 Object.values(s.balances).forEach(b=>{h+='<tr><td>'+b.member+'</td><td>Rs '+(b.loaned_paise/100)+'</td><td>Rs '+(b.repaid_paise/100)+'</td><td><b>Rs '+(b.outstanding_paise/100)+'</b></td></tr>';});
 tbl.innerHTML=h;
 var c=document.getElementById('chainstable'),ch='<tr><th>Seq</th><th>Type</th><th>Member</th><th>Amt</th><th>Hash</th></tr>';
 s.events.forEach(e=>{ch+='<tr><td>'+e.seq+'</td><td>'+e.type+'</td><td>'+e.member+'</td><td>Rs '+(e.amount_paise/100)+'</td><td class="mono">'+ (''+e.hash).slice(0,16)+'&hellip;</td></tr>';});
 c.innerHTML=ch;
}
refresh();
</script>
</body></html>"""

if __name__ == "__main__":
    rebuild()
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"BAHI demo UI: http://localhost:{PORT}")
    webbrowser.open(f"http://localhost:{PORT}")
    srv.serve_forever()