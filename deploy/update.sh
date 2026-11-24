#!/usr/bin/env bash
# update.sh - install the latest code from GitHub on the server, in one step. Safe to run any time.
#   sudo git -C /opt/tucker pull -q && sudo bash /opt/tucker/deploy/update.sh
# Every step is idempotent. Apache is reloaded only if its configuration test passes.
set -euo pipefail
cd /opt/tucker

/opt/tucker-venv/bin/pip install -q -r requirements.txt            # pinned Python dependencies
cp -r site/. /var/www/html/                                         # the static site

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
systemctl list-timers tucker-report.timer tucker-reset.timer --no-pager | head -3
