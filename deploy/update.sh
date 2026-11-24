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
cp deploy/tucker-reset.service deploy/tucker-reset.timer deploy/tucker-report.service deploy/tucker-report.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tucker-reset.timer tucker-report.timer >/dev/null

systemctl restart tucker
sleep 3
systemctl is-active apache2 tucker
# (no "| head" here: with pipefail, head closing the pipe early made the script report a false failure)
systemctl list-timers tucker-report.timer tucker-reset.timer --no-pager --no-legend
echo "Deploy OK"
