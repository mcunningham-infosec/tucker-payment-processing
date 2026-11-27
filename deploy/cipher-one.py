#!/usr/bin/env python3
"""
cipher-one.py - run chosen Cipher attacks once against this server and print each result in full.
A troubleshooting tool for staging: shows the evidence behind an attack that didn't hold.

    sudo bash -c 'set -a; . /etc/tucker/tucker.env; cd /opt/tucker; /opt/tucker-venv/bin/python deploy/cipher-one.py a10-range'

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import sys
import time

sys.path.insert(0, "/opt/tucker")
from app import cipher  # noqa: E402
from app.cipher.attacks import ATTACKS, Probe  # noqa: E402
from app.cipher.runner import HOST, TARGET  # noqa: E402

wanted = set(sys.argv[1:])
run_id, token = cipher.new_run_token()
probe = Probe(TARGET, HOST, token, cipher.HEADER)
ctx = {"started": time.time(), "repo": "/opt/tucker", "run_id": run_id}
for a in ATTACKS:
    if a.id in wanted:
        try:
            out = a.run(probe, ctx)
            print(f"{a.id}: held={out.held} check={out.check} evidence={out.evidence}")
        except Exception as e:
            print(f"{a.id}: ERROR {type(e).__name__}: {e}")
