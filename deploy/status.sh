#!/usr/bin/env bash
# status.sh - one-screen health check:  sudo bash /opt/tucker/deploy/status.sh
# Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
for s in apache2 postgresql tucker fail2ban ufw unattended-upgrades certbot.timer; do
  printf '%-22s boot=%-8s now=%s\n' "$s" "$(systemctl is-enabled $s 2>/dev/null)" "$(systemctl is-active $s 2>/dev/null)"
done
echo "Uptime:        $(uptime -p)"
echo "Reboot needed: $( [ -f /var/run/reboot-required ] && echo yes '(will happen at 4:30 am)' || echo no)"
echo "Last updates:  $(grep -h 'upgraded' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -1 | cut -c1-90)"
echo "Disk:          $(df -h / | awk 'NR==2{print $3" used of "$2" ("$5")"}')"
echo "Certificate:   $(certbot certificates 2>/dev/null | grep -m1 Expiry | sed 's/^ *//')"
echo "Site:          $(curl -s -o /dev/null -w '%{http_code}' https://tuckerpaymentprocessing.com/)  API: $(curl -s https://tuckerpaymentprocessing.com/api/health)"
