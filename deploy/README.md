# deploy/ - how the server is set up and updated

Everything that configures the live server is in this folder, so the whole setup can be read and repeated.
Secrets are never here: they live only on the server in `/etc/tucker/tucker.env` (root-only, mode 600).

## Updating the live site (every change)

    sudo git -C /opt/tucker pull -q && sudo bash /opt/tucker/deploy/update.sh

`update.sh` installs pinned Python packages, copies the website, installs the Apache and log settings, reloads
Apache only if its config test passes, refreshes the nightly timers and restarts the app. Safe to run any time.

## What each file is

| File | What it does | Installed |
|---|---|---|
| `update.sh` | One-step update from GitHub (above) | run on every deploy |
| `apache-hardening.conf` | Security headers (CSP, HSTS, framing, referrer, permissions), blocks hidden and backup files, cache rules | by `update.sh` |
| `apache-cloudflare.conf` | Trusts the visitor's real IP only from Cloudflare's ranges; adds Cloudflare's location to the access log | by `update.sh` |
| `tucker-api.conf` | Apache sends `/api/` to the app on 127.0.0.1:8000, with a small request-size limit | once, at setup |
| `tucker.service` | Runs the app as an unprivileged user, listening on 127.0.0.1 only, with systemd sandboxing | once, at setup |
| `tucker-reset.service` / `.timer` | Nightly reset of the demo store at midnight Eastern (`db/nightly_reset.sql`) | by `update.sh` |
| `tucker-report.service` / `.timer` | The owner's daily security and activity email at 11:50 PM Eastern (`app/report.py`) | by `update.sh` |
| `logrotate-apache2` | Web server logs kept at most two days | by `update.sh` |
| `ops-agent-config.yaml` | Google Cloud Ops Agent: ships ONLY the app's owner-alert lines to Cloud Logging | once, at setup |
| `alert-policy.json` | Cloud Monitoring policy that emails the owner when an alert line arrives | once, at setup |
| `postgres-store-login.md` | How the app's two database logins work with no passwords (peer authentication) | once, at setup |
| `gcp-firewall.md` | The Google Cloud firewall: web traffic only from Cloudflare, admin only through Identity-Aware Proxy | once, at setup |
| `auto-maintenance.sh` | Automatic security updates, reboot-if-needed at 4:30 AM, services on boot, log and disk caps | once, at setup |
| `status.sh` | One-screen health check of every service, updates, disk, certificate and the site | any time |
| `build_policy_pages.py` | Builds the AI Policies pages from `policies/*.md` (a test keeps them in sync) | after editing a policy |
| `build_scan_reports.py` | Builds the security scan PDFs from `docs/scans/<date>/results.json` | after a new scan |
