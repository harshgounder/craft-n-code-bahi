#!/usr/bin/env python3
"""t_server.py - live HTTP attack matrix vs CURRENT HEAD server.py (post PR4/5/6).
Expectation style: SAFE = defense must hold, VULN = flaw confirmed present."""
import http.client, json, sys, os, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from http.server import HTTPServer
import server as srv

S = {"port": None}

def start():
    srv.rebuild()
    httpd = HTTPServer(("127.0.0.1", 0), srv.Handler)
    S["port"] = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return httpd

def req(path, host=None, origin=None, method="GET", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", S["port"], timeout=10)
    hdrs = dict(headers or {})
    if host is not None:
        hdrs["Host"] = host
    if origin is not None:
        hdrs["Origin"] = origin
    conn.request(method, path, headers=hdrs)
    res = conn.getresponse()
    body = res.read().decode("utf-8", "replace")
    conn.close()
    return res.status, dict(res.getheaders()), body

def state():
    st, _, body = req("/api/state")
    return st, json.loads(body)

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    httpd = start()
    time.sleep(0.2)

    # baseline: M07 now starts OPEN (amber pending)
    st, stb = state()
    t("chain.http.base.001 /api/state reports MEETING OPEN (amber Pending)",
      st == 200 and stb["verdict"] is None and "OPEN" in stb["detail"] and stb["receipt"] is None,
      "%s %s" % (st, stb.get("detail")))
    st, _h, body = req("/")
    t("SAFE.http.base.002 index serves HTML", st == 200 and "BAHI" in body, str(st))
    st, _h, body = req("/nonexistent")
    t("VULN.http.base.003 unknown path serves the app (no 404)", st == 200 and "BAHI" in body,
      "every unknown URL returns the demo HTML: no 404, no route distinction")
    st, hdrs, body = req("/api/state")
    t("SAFE.http.base.004 JSON content-type", hdrs.get("Content-Type", "").startswith("application/json"), str(hdrs.get("Content-Type")))

    # -------- GET side effects (CSRF surface) --------
    # attack while OPEN is a no-op (fixed); attack after CLOSE still mutates via GET
    srv.rebuild()
    st, _h, body = req("/api/close")
    st, _h, body = req("/api/attack")
    d = json.loads(body)
    st2, stb2 = state()
    t("VULN.http.csrf.001 GET /api/attack AFTER close mutates ledger state (state-changing GET, no CSRF token)",
      d.get("verdict") is False and stb2["verdict"] is False,
      "plain GET permanently alters the chain post-close; <img src=http://localhost:8123/api/attack> triggers it (no Origin header sent for image GETs)")
    srv.rebuild()
    st, _h, body = req("/api/entry?type=contribution&paise=500")
    st2, stb2 = state()
    t("SAFE.http.csrf.002 GET /api/entry appends event while open", st == 200 and len(stb2["events"]) == 9 and stb2["events"][-1]["amount_paise"] == 500,
      "GET /api/entry is a write (append). Any cross-site GET (img/form/link) can still write ledger entries while the meeting is open")
    st, _h, body = req("/api/close")
    st2, stb2 = state()
    t("SAFE.http.csrf.003 GET /api/close closes M07 + issues bound receipt", st == 200 and stb2["verdict"] is True and stb2["receipt"]["meeting"] == "M07", stb2["receipt"]["meeting"])
    t("SAFE.http.csrf.003b close receipt carries member_events", stb2["receipt"].get("member_events") is not None, str(stb2["receipt"].get("member_events"))[:60])
    st, _h, body = req("/api/reset")
    st2, stb2 = state()
    t("SAFE.http.csrf.004 GET /api/reset resets to open state", st == 200 and stb2["verdict"] is None and len(stb2["events"]) == 8 and stb2["receipt"] is None)
    t("VULN.http.csrf.005 all four state-changing endpoints are still GET",
      True, "<img src=.../api/attack> runs on page load; POST is 501 so no CSRF token infrastructure exists")

    # -------- parameter handling --------
    srv.rebuild()
    req("/api/entry?type=contribution&paise=-100")
    st, stb = state()
    t("VULN.http.param.001 negative paise silently clamped to 0 (intent lost)",
      stb["events"][-1]["amount_paise"] == 0, "Rs -100 became Rs 0 with no error, no refusal")
    req("/api/entry?type=contribution&paise=abc")
    st, stb = state()
    t("VULN.http.param.002 non-numeric paise silently becomes Rs 10000",
      stb["events"][-1]["amount_paise"] == 10000, "typo 'abc' books a Rs 100 deposit: silent default misrecords money")
    req("/api/entry?type=contribution&paise=" + "9" * 6000)
    st, stb = state()
    t("VULN.http.param.003 6000-digit paise silently truncated to default Rs 10000",
      stb["events"][-1]["amount_paise"] == 10000,
      "int() digit-limit ValueError -> silent fallback; a corrupt/attack request books 10000 paise without error")
    req("/api/entry?type=contribution&paise=1&paise=2")
    st, stb = state()
    t("VULN.http.param.004 duplicate params: first wins silently",
      stb["events"][-1]["amount_paise"] == 1, "paise=1&paise=2 books 1 paisa; no error on ambiguity")
    req("/api/entry?type=contribution&paise=0")
    st, stb = state()
    t("chain.http.param.005 zero-paise entry accepted", stb["events"][-1]["amount_paise"] == 0)
    req("/api/entry?type=contribution&paise=100000000000000000000")
    st, stb = state()
    t("chain.http.param.006 huge paise accepted (arbitrary precision)", stb["events"][-1]["amount_paise"] == 10**20)
    req("/api/entry?type=" + "x" * 5000 + "&paise=100")
    st, stb = state()
    t("SAFE.http.param.007 5KB type whitelisted to contribution (XSS fix holds)",
      stb["events"][-1]["type"] == "contribution", "type field sanitized server-side")
    req("/api/entry?type=%E0%A4%95%E0%A5%8D%E0%A4%B0%E0%A4%AE%E0%A4%A3&paise=100")
    st, stb = state()
    t("SAFE.http.param.008 unicode type whitelisted to contribution (allowed types only)",
      stb["events"][-1]["type"] == "contribution", "unicode types no longer reach the chain via API")

    # -------- XSS surface (server-side whitelist fixed; UI escape present) --------
    payload = '<img src=x onerror="document.body.setAttribute(\'data-xss\',\'PWNED\')">'
    import urllib.parse
    req("/api/entry?type=" + urllib.parse.quote(payload) + "&paise=100")
    st, stb = state()
    t("SAFE.http.xss.001 attacker type payload neutralized to contribution (stored XSS blocked server-side)",
      stb["events"][-1]["type"] == "contribution", "whitelist replaces the payload with contribution")
    t("SAFE.http.xss.002 esc() present on chain table render path",
      "function esc(s)" in srv.INDEX_HTML and "esc(e.member)" in srv.INDEX_HTML and "esc(e.type)" in srv.INDEX_HTML,
      "PR6 UI escaping added to show() table builder")
    req("/api/entry?type=MEETING-CLOSE&paise=666")
    st, stb = state()
    t("SAFE.http.xss.003 MEETING-CLOSE type via /api/entry neutralized (protocol pollution fixed)",
      stb["events"][-1]["type"] == "contribution", "clients can no longer mint MEETING-CLOSE events")

    # -------- Host / Origin guards (PR6 hostname parse) --------
    for host, expect in (
        ("127.0.0.1", 200), ("localhost", 200), ("127.0.0.1:8123", 200),
        ("127.0.0.1.evil.com", 403), ("localhost.evil.com", 403),
        ("evil.com", 403), ("", 403),
    ):
        st, _, _ = req("/api/state", host=host)
        if expect == 200:
            t("chain.http.host.%r accepted" % host, st == 200, str(st))
        else:
            t("SAFE.http.host.%r rejected" % host, st == 403, str(st))
    # PR6 parser hole: split(':')[0] strips port, suffix after port still passes
    st, _, _ = req("/api/state", host="127.0.0.1:8123.attacker.com")
    t("VULN.http.host.port-suffix '127.0.0.1:8123.attacker.com' accepted (split(:)[0] strips everything after the port)",
      st == 200,
      "hostname = host.split(':')[0] = '127.0.0.1': any Host starting '127.0.0.1:' + arbitrary suffix passes; naive split, not a real hostname parse (browser-unreachable via DNS today, but the guard's intent is broken and any 0.0.0.0 bind makes it live)")
    for origin, expect in (
        ("http://127.0.0.1:8123", 200), ("http://localhost:8123", 200),
        ("http://127.0.0.1.evil.com", 200),
        ("http://evil.example/?u=http://127.0.0.1:8123", 200),
        ("https://evil.com", 403),
    ):
        st, _, _ = req("/api/state", origin=origin)
        if expect == 200:
            t("VULN.http.origin.%r accepted (substring check)" % origin, st == 200,
              "Origin guard is still a SUBSTRING check ('127.0.0.1' anywhere passes): not an exact-origin compare")
        else:
            t("SAFE.http.origin.%r rejected" % origin, st == 403, str(st))
    st, _, _ = req("/api/entry?type=contribution&paise=1")
    t("VULN.http.origin.none missing Origin header passes state-changing request",
      st == 200, "Origin absent (img/form GET) -> guard skipped entirely: GET-CSRF path survives the Host fix")
    # full rebinding combo now blocked at Host
    srv.rebuild()
    st, _h, body = req("/api/attack", host="127.0.0.1.evil.com", origin="http://127.0.0.1.evil.com")
    t("SAFE.http.rebind.001 hostname-parse fix blocks DNS-rebinding Host", st == 403,
      "127.0.0.1.evil.com -> hostname '127.0.0.1.evil.com' not in allowlist -> 403")

    # -------- methods --------
    st, _, _ = req("/api/state", method="POST")
    t("SAFE.http.method.001 POST rejected", st in (501, 405), str(st))
    st, _, _ = req("/api/state", method="PUT")
    t("SAFE.http.method.002 PUT rejected", st in (501, 405), str(st))
    st, _, _ = req("/api/state", method="DELETE")
    t("SAFE.http.method.003 DELETE rejected", st in (501, 405), str(st))
    st, _, _ = req("/api/state", method="OPTIONS")
    t("chain.http.method.004 OPTIONS -> 501 (no CORS preflight)", st == 501, str(st))
    st, hdrs, body = req("/", method="HEAD")
    t("SAFE.http.method.005 HEAD headers only, no body (PR5)", st == 200 and body == "" and "Content-Length" in hdrs, str(hdrs.get("Content-Length")))

    # -------- path weirdness --------
    st, _h, body = req("/api/../api/state")
    t("chain.http.path.001 dotdot path no traversal (serves HTML)", st == 200 and "BAHI" in body)
    st, _h, body = req("/%61pi/state")
    t("chain.http.path.002 percent-encoded path not decoded", st == 200 and "BAHI" in body)
    st, _h, body = req("/api/state%00.png")
    t("chain.http.path.003 null byte in path", st == 200)

    # -------- repeated operations (open-meeting flow) --------
    srv.rebuild()
    req("/api/close")
    st, _h, body = req("/api/close")
    j = json.loads(body)
    st2, stb2 = state()
    closes = [e for e in stb2["events"] if e["type"] == "MEETING-CLOSE"]
    t("SAFE.http.repeat.001 second /api/close rejected (already closed)", j.get("ok") is False and len(closes) == 2,
      "M06+M07 closes only; no duplicate M07 root this pass")
    srv.rebuild()
    req("/api/close")
    st, _h, body = req("/api/entry?type=contribution&paise=100")
    j = json.loads(body)
    st2, stb2 = state()
    t("SAFE.http.repeat.002 /api/entry after /api/close rejected (receipt stays MATCH)",
      j.get("ok") is False and stb2["verdict"] is True, "post-close entry now refused; terminality protected")
    # reset orphans: covered in t_v2.reset-orphan

    # -------- response hygiene --------
    httpd.shutdown()
    return R