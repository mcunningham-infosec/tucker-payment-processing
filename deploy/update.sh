#!/usr/bin/env bash
# update.sh - install the latest code from GitHub on the server, in one step. Safe to run any time.
#   sudo git -C /opt/tucker pull -q && sudo bash /opt/tucker/deploy/update.sh
# Every step is idempotent. Apache is reloaded only if its configuration test passes.
# Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
set -euo pipefail
cd /opt/tucker

/opt/tucker-venv/bin/pip install -q -r requirements.txt            # pinned Python dependencies
cp -r site/. /var/www/html/                                         # the static site
# Files retired from the site: copying never deletes, so remove them from the web root explicitly.
rm -f /var/www/html/chat.html /var/www/html/assets/welcome.js /var/www/html/assets/police-hat.svg \
      /var/www/html/assets/lair-sign.svg /var/www/html/assets/squirrel-soc.svg /var/www/html/assets/blackie_avatar_256.png

cp deploy/apache-hardening.conf  /etc/apache2/conf-available/tucker-hardening.conf
cp deploy/apache-cloudflare.conf /etc/apache2/conf-available/tucker-cloudflare.conf
a2enmod -q remoteip headers >/dev/null
a2enconf -q tucker-hardening tucker-cloudflare >/dev/null
apache2ctl configtest && systemctl reload apache2

cp deploy/logrotate-apache2 /etc/logrotate.d/apache2                # web logs kept at most two days

# SSH hardening (modern MACs and key exchange only). sshd's own config test must pass before it is reloaded,
# so a bad file can never lock anyone out; on a failed test the new file is removed again.
cp deploy/sshd-hardening.conf /etc/ssh/sshd_config.d/50-tucker-hardening.conf
if sshd -t; then systemctl reload ssh; else rm -f /etc/ssh/sshd_config.d/50-tucker-hardening.conf; echo "sshd config test FAILED: hardening not applied"; fi
cp deploy/tucker-reset.service deploy/tucker-reset.timer deploy/tucker-report.service deploy/tucker-report.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tucker-reset.timer tucker-report.timer >/dev/null
if [ -e /etc/tucker/STAGING ]; then                                 # staging server: no owner report emails
  systemctl disable --now tucker-report.timer >/dev/null 2>&1 || true
fi

# Restart the app only when its code changed. Cipher's attack runs live in the app's memory, so a restart
# in the middle of one cuts it off: if a run is in progress, wait for it to finish first (a run is capped
# at 5 minutes; we wait up to 7).
APP_REV=$(git rev-parse HEAD:app HEAD:policies HEAD:requirements.txt | sha1sum | cut -c1-40)
STAMP=/var/lib/tucker-deploy/app.rev
mkdir -p "$(dirname "$STAMP")"
if [ "$APP_REV" != "$(cat "$STAMP" 2>/dev/null || true)" ]; then
  for _ in $(seq 1 84); do
    curl -fsS --max-time 3 http://127.0.0.1:8000/api/health 2>/dev/null | grep -q '"cipher_busy":true' || break
    echo "Waiting for a Cipher attack run to finish before restarting the app..."
    sleep 5
  done
  systemctl restart tucker
  echo "$APP_REV" > "$STAMP"
  sleep 3
else
  echo "App code unchanged: no restart"
fi
systemctl is-active apache2 tucker
# (no "| head" here: with pipefail, head closing the pipe early made the script report a false failure)
systemctl list-timers tucker-report.timer tucker-reset.timer --no-pager --no-legend
echo "Deploy OK"
