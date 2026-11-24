"""
cli.py - run Cipher once from the server's command line and print the results (for the site owner).

    sudo bash -c 'set -a; . /etc/tucker/tucker.env; set +a; cd /opt/tucker; \\
                  runuser -u tucker_app -m -- /opt/tucker-venv/bin/python -m app.cipher.cli [--soc]'

--soc also runs the AI SOC Squirrel's two check-ins with the real model (costs a fraction of a cent).

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import sys
import time

from . import runner, soc


def main():
    """Run all of Cipher's attacks with no pauses, print HELD/FAIL per attack, the detection rules and, with
    --soc, the AI SOC Squirrel's report. Useful after any server change: every line should say HELD."""
    use_soc = "--soc" in sys.argv
    llm = None
    if use_soc:
        from ..llm import GeminiLLM
        llm = GeminiLLM()

    def alert(rid, st):
        """The alert-stage check-in (only with --soc)."""
        if llm:
            st["soc"].append({"when": "alert", **soc.check_in(llm, list(st["attacks"]), final=False)})

    def done(rid, st):
        """The final check-in (only with --soc)."""
        if llm:
            st["soc"].append({"when": "final", **soc.check_in(llm, list(st["attacks"]), final=True)})

    rid = runner.start(on_alert=alert, on_done=done, pace=0)
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
    for d in st["detections"]:
        print(f"RULE {d['rule']}: {d['count']}/{d['limit']} -> {d['outcome']}")
    if st.get("retry"):
        print("Cipher retry after block:", st["retry"]["evidence"])
    for c in st["soc"]:
        print(f"\nSQUIRREL ({c['when']}, ai={c.get('ai')}, calls={c.get('ai_calls')}): {c['headline']}")
        for line in c["lines"]:
            print("   -", line)
        print("   verdict:", c["verdict"], "| injection spotted:", c["injection_spotted"])
        for p in c.get("proposals", []):
            print(f"   proposed {p['action']} -> {p['policy']} ({p['reason']})")


if __name__ == "__main__":
    main()
