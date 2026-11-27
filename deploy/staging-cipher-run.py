#!/usr/bin/env python3
"""
staging-cipher-run.py - run one full Cipher attack run on THIS server and print the results.

For the staging server: it talks to Apache on this machine directly (so the Cloudflare Access login in front of
staging isn't involved), starts a run exactly as the Lair page does, follows it to the end, and prints the timing,
the attacks that didn't hold, the detection rules that fired and the AI calls used.

    sudo -u tucker_app /opt/tucker-venv/bin/python /opt/tucker/deploy/staging-cipher-run.py

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time

HOST = os.environ.get("CIPHER_HOST", "staging.tuckerpaymentprocessing.com")
CTX = ssl.create_default_context()


class LocalHTTPS(http.client.HTTPSConnection):
    """Connect to this machine's Apache, but present and verify the real hostname (TLS SNI and Host)."""
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", 443), self.timeout)
        self.sock = CTX.wrap_socket(raw, server_hostname=HOST)


cookie = {}


def call(method, path, body=None):
    c = LocalHTTPS(HOST, 443, timeout=30)
    headers = {"Content-Type": "application/json", "Host": HOST}
    if cookie:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookie.items())
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    r = c.getresponse()
    for h in r.headers.get_all("Set-Cookie") or []:
        m = re.match(r"([^=]+)=([^;]*)", h)
        if m:
            cookie[m.group(1)] = m.group(2)
    data = r.read()
    c.close()
    return json.loads(data or b"{}")


def main():
    start = call("POST", "/api/cipher/start", {})
    if start.get("error"):
        sys.exit(f"Could not start: {start}")
    t0, act2 = time.time(), None
    while True:
        st = call("GET", "/api/cipher/status")
        attacks = st.get("attacks") or []
        if act2 is None and any(a.get("act") == 2 for a in attacks):
            act2 = time.time() - t0
        if st.get("status") in ("done", "error"):
            break
        time.sleep(3)
    summary = st.get("summary") or {}
    print(f"status:        {st.get('status')}")
    print(f"attacks:       {len(attacks)}  held: {summary.get('held')}  seconds: {summary.get('seconds')}")
    print(f"act 2 began:   ~{act2:.0f}s" if act2 else "act 2 began:   never")
    print(f"not held:      {[a['id'] for a in attacks if a.get('held') is not True and not a.get('check')]}")
    print(f"checks:        {[(a['id'], a.get('evidence', '')[:50]) for a in attacks if a.get('check')]}")
    print(f"rules fired:   {[(d['rule'], d['count']) for d in st.get('detections', []) if d.get('fired')]}")
    print(f"blocked:       {st.get('blocked_source')}  retry: {(st.get('retry') or {}).get('status')}")
    print(f"AI calls:      {summary.get('ai_calls')}  requests: {summary.get('requests')}")


if __name__ == "__main__":
    main()
