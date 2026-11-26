#!/usr/bin/env bash
# staging-setup.sh - build the staging server from this repository, on a fresh Ubuntu 24.04 VM.
# Run once, as root, on the new VM (through IAP SSH, like production):
#   sudo bash staging-setup.sh
# It installs the same stack as production from the same deploy/ files, so it also proves the setup can be
# rebuilt from scratch. It does NOT create secrets or accept any terms: the owner pastes the Gemini key into
# /etc/tucker/tucker.env and runs the one certbot line printed at the end.
# Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
set -euo pipefail
HOST=staging.tuckerpaymentprocessing.com
REPO=https://github.com/mcunningham-infosec/tucker-payment-processing

echo "== Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q apache2 postgresql python3-venv git certbot python3-certbot-apache fail2ban ufw unattended-upgrades >/dev/null

echo "== App user and code (staging branch)"
id tucker_app >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin tucker_app
[ -d /opt/tucker/.git ] || git clone -q -b staging "$REPO" /opt/tucker
git config --global --add safe.directory /opt/tucker
[ -d /opt/tucker-venv ] || python3 -m venv /opt/tucker-venv
/opt/tucker-venv/bin/pip install -q -r /opt/tucker/requirements.txt

echo "== Database (same schema, roles and fictional seed data as production)"
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='tucker'" | grep -q 1; then
  sudo -u postgres psql -q -c "CREATE DATABASE tucker"
  for f in schema roles seed; do sudo -u postgres psql -q -v ON_ERROR_STOP=1 -d tucker -f /opt/tucker/db/$f.sql; done
fi
PGD=/etc/postgresql/16/main
grep -q "^tuckermap" $PGD/pg_ident.conf || echo "tuckermap   tucker_app   tucker_store" >> $PGD/pg_ident.conf
grep -q "tucker_store   peer map=tuckermap" $PGD/pg_hba.conf || \
  sed -i '0,/^local\s\+all\s\+all\s\+peer/s//local   tucker   tucker_store   peer map=tuckermap\n&/' $PGD/pg_hba.conf
systemctl reload postgresql

echo "== Settings (staging values; the Gemini key is left blank for the owner to paste in)"
mkdir -p /etc/tucker
touch /etc/tucker/STAGING
if [ ! -f /etc/tucker/tucker.env ]; then
  umask 077
  cat > /etc/tucker/tucker.env <<CONF
# STAGING settings. Secrets live only here (root-only). Paste the STAGING Gemini key below.
GEMINI_API_KEY=
HASH_SALT=$(openssl rand -hex 32)
CIPHER_ENABLED=1
CIPHER_HOST=$HOST
CIPHER_ONE_PER_DAY=0
MONTHLY_CAP_USD=10.00
DAILY_CAP_USD=2.00
CONF
  chmod 600 /etc/tucker/tucker.env
fi

echo "== Apache: staging site, banner, noindex"
a2enmod -q ssl proxy proxy_http headers remoteip rewrite substitute reqtimeout >/dev/null
a2dismod -q -f status autoindex >/dev/null 2>&1 || true
a2dissite -q 000-default >/dev/null 2>&1 || true
cp /opt/tucker/deploy/tucker-api.conf /etc/apache2/conf-available/tucker-api.inc
cp /opt/tucker/deploy/staging-robots.txt /etc/apache2/tucker-staging-robots.txt
cp /opt/tucker/deploy/apache-staging.conf /etc/apache2/sites-available/tucker-staging.conf
a2ensite -q tucker-staging >/dev/null
rm -f /var/www/html/index.html

echo "== App service, timers and the normal deploy steps"
cp /opt/tucker/deploy/tucker.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable tucker >/dev/null
bash /opt/tucker/deploy/update.sh
bash /opt/tucker/deploy/auto-maintenance.sh >/dev/null

echo "== Host firewall (web and SSH only; Google Cloud's firewall already limits who can reach them)"
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw --force enable >/dev/null

echo
echo "Staging server built. Two steps are the owner's:"
echo "  1. Paste the staging Gemini key:   sudo nano /etc/tucker/tucker.env   then   sudo systemctl restart tucker"
echo "  2. HTTPS certificate (you accept Let's Encrypt's terms):"
echo "     sudo certbot --apache -d $HOST --redirect -m <your email> --agree-tos"
