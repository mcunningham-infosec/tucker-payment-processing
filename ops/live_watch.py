#!/usr/bin/env python3
"""Outside-in integrity watch for tuckerpaymentprocessing.com (alert only, never changes anything).
Fetches every file in the repo's site/ folder from the live site, exactly as a visitor gets it through
Cloudflare, and checks each one's git blob SHA-1 against the versions of that file in the last 40 commits
on GitHub. A file matching any recent version is fine (so a push that isn't deployed yet never alarms).
It runs hourly as a scheduled job outside the server, so an attacker on the server can't switch it off.
Usage:  git clone https://github.com/mcunningham-infosec/tucker-payment-processing.git repo
        python3 ops/live_watch.py repo        (exit 0 = all match, 1 = files not loading, 2 = MISMATCH)
Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import hashlib, re, subprocess, sys, urllib.request, urllib.error, concurrent.futures as cf

SITE = "https://tuckerpaymentprocessing.com/"
# Cloudflare's bot protection inserts this one script just before </body> on HTML pages. It is removed ONLY
# if it matches this template exactly, with nothing but its per-request ray id and token differing.
CF_TEMPLATE = '<script>(function(){function c(){var b=a.contentDocument||(a.contentWindow&&a.contentWindow.document);if(b){var d=b.createElement(\'script\');d.innerHTML="window.__CF$cv$params={r:\'RAY\',t:\'TOK\'};var l=window.parent.location,o;try{o=new URL(l.origin).origin}catch(e){try{o=new URL(new URL(l.href).origin).origin}catch(e){o=\'\'}}var u=\'/cdn-cgi/challenge-platform/scripts/jsd/main.js?ray=RAY\',a=document.createElement(\'script\');a.src=o?new URL(u,o).href:u;document.getElementsByTagName(\'head\')[0].appendChild(a);";b.getElementsByTagName(\'head\')[0].appendChild(d)}}if(document.body){var a=document.createElement(\'iframe\');a.height=1;a.width=1;a.style.position=\'absolute\';a.style.top=0;a.style.left=0;a.style.border=\'none\';a.style.visibility=\'hidden\';document.body.appendChild(a);if(\'loading\'!==document.readyState)c();else if(window.addEventListener)document.addEventListener(\'DOMContentLoaded\',c);else{var e=document.onreadystatechange||function(){};document.onreadystatechange=function(b){e(b);\'loading\'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();</script>'
CF_BOT = re.compile(r'<script>\(function\(\)\{function c\(\)[^<]*</script>$')
# Cloudflare Web Analytics beacon: fully pinned pattern (this site's token; the integrity hash pins the code).
CF_BEACON = re.compile(r'<script (?:type="module"|defer) src="https://static\.cloudflareinsights\.com/beacon\.min\.js/v[0-9a-f]{20,80}"'
                       r' integrity="sha512-[A-Za-z0-9+/]{86}==" data-cf-beacon=\'\{"version":"[0-9.]{1,12}",'
                       r'"token":"f768b80b6ca2455abc4c8005a3a860a6","r":1,"spa":2\}\' crossorigin="anonymous"></script>$')


def _bot_ok(snippet: str) -> bool:
    s = re.sub(r"r:'[0-9a-f]{16}'", "r:'RAY'", snippet)
    s = re.sub(r"t:'[A-Za-z0-9+/=]{1,64}'", "t:'TOK'", s)
    s = re.sub(r"ray=[0-9a-f]{16}", "ray=RAY", s)
    return s == CF_TEMPLATE


def strip_cloudflare(body: bytes):
    """Remove Cloudflare's own additions just before </body>. Returns (body, genuine): genuine is False if
    something in that spot only looks like Cloudflare's code."""
    i = body.rfind(b"</body>")
    if i < 0:
        return body, True
    head, tail = body[:i].decode("utf-8", "replace"), body[i:]
    for _ in range(3):
        m = CF_BEACON.search(head)
        if m:
            head = head[:m.start()]
            continue
        m = CF_BOT.search(head)
        if m:
            if not _bot_ok(m.group(0)):
                return body, False
            head = head[:m.start()]
            continue
        break
    if re.search(r"cloudflareinsights|__CF\$cv\$params|challenge-platform", head[-3000:]):
        return body, False          # Cloudflare-looking code that didn't match exactly: treat as tampering
    return head.encode() + tail, True


repo = sys.argv[1]
git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True).stdout

commits = git("rev-list", "--max-count=40", "HEAD").split()
known = {}                                        # path -> set of blob shas seen in recent commits
for c in commits:
    for line in git("ls-tree", "-r", c, "site/").splitlines():
        meta, path = line.split("\t", 1)
        known.setdefault(path, set()).add(meta.split()[2])
current = [l.split("\t", 1)[1] for l in git("ls-tree", "-r", "HEAD", "site/").splitlines()]
oldest = set(l.split("\t", 1)[1] for l in git("ls-tree", "-r", commits[-1], "site/").splitlines())

def blob_sha(b: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(b) + b).hexdigest()   # noqa: S324 - git's own object id

def check(path):
    url = SITE + path[len("site/"):]
    req = urllib.request.Request(url, headers={"User-Agent": "TPP-integrity-watch/1.0"})   # noqa: S310 - fixed https URL
    try:
        with urllib.request.urlopen(req, timeout=20) as r:     # noqa: S310 - fixed https URL
            body = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404 and path not in oldest:
            return path, "new", "added recently on GitHub; not deployed yet"
        return path, "http", e.code
    except Exception as e:
        return path, "error", type(e).__name__
    if path == "site/robots.txt":
        # Cloudflare's managed robots.txt puts a block of "#" comment lines (its content-signal notice) above ours.
        # Comments change nothing for crawlers, so only that leading comment block is removed before comparing.
        lines = body.split(b"\n")
        while lines and (lines[0].startswith(b"#") or not lines[0].strip()):
            lines.pop(0)
        body = b"\n".join(lines)
    if path.endswith(".html"):
        body, genuine = strip_cloudflare(body)
        if not genuine:
            return path, "MISMATCH", "unexpected script before </body>"
    return path, ("ok" if blob_sha(body) in known[path] else "MISMATCH"), blob_sha(body)

with cf.ThreadPoolExecutor(8) as ex:
    results = list(ex.map(check, current))
bad = [r for r in results if r[1] == "MISMATCH"]
unreach = [r for r in results if r[1] in ("http", "error")]
print(f"checked {len(results)} files against {len(commits)} recent commits (HEAD {commits[0][:7]})")
print(f"ok={sum(r[1]=='ok' for r in results)} mismatch={len(bad)} unreachable={len(unreach)}")
for r in bad + unreach:
    print("  ", *r)
sys.exit(2 if bad else (1 if unreach else 0))
