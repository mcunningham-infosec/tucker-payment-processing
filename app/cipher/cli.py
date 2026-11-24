"""
cli.py - run Cipher once from the server's command line and print the results (for the site owner).

    sudo bash -c 'set -a; . /etc/tucker/tucker.env; set +a; cd /opt/tucker; \
                  runuser -u tucker_app -m -- /opt/tucker-venv/bin/python -m app.cipher.cli'
"""
import time

from . import runner


def main():
    rid = runner.start(pace=0)
    if not rid:
        print("Another Cipher run is in progress.")
        return
    while runner.state(rid)["status"] == "running":
        time.sleep(0.5)
    st = runner.state(rid)
    for a in st["attacks"]:
        mark = "HELD" if a["held"] is True else ("FAIL" if a["held"] is False else "ERR ")
        print(f"{mark} {a['owasp']:<6} {a['id']:<18} {a['evidence'][:70]}")
    print(st["status"], st["summary"])


if __name__ == "__main__":
    main()
