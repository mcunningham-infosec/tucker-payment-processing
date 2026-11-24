#!/usr/bin/env bash
# auto-maintenance.sh - make the server look after itself. Safe to run more than once.
#   sudo bash /opt/tucker/deploy/auto-maintenance.sh
#
# What it sets up:
#  1. Every service starts on boot (Apache, PostgreSQL, Tucker's app, firewall, fail2ban).
#  2. Ubuntu installs ALL security and regular updates automatically every day, including Apache,
#     PostgreSQL, OpenSSL and the kernel (they all come from Ubuntu's own repositories).
#  3. If an update needs a reboot (e.g. a new kernel), the server reboots itself at 4:30 am Eastern,
#     and every service comes back on its own.
#  4. Old packages and kernels are cleaned up so the 30 GB disk never fills.
#  5. Logs are capped so they can't fill the disk either.
#  6. The HTTPS certificate keeps renewing itself (certbot's timer).
# Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
set -euo pipefail

echo "== 1. Start everything on boot"
systemctl enable apache2 postgresql tucker fail2ban ufw unattended-upgrades certbot.timer >/dev/null 2>&1 || true

echo "== 2-4. Automatic updates, automatic reboot when needed, cleanup"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
cat > /etc/apt/apt.conf.d/52tucker-unattended <<'CONF'
// Tucker server: install security AND regular updates, clean up, reboot at night only if required.
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
        "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
CONF
timedatectl set-timezone America/New_York

echo "== 5. Cap system logs at 200 MB"
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=200M\n' > /etc/systemd/journald.conf.d/tucker.conf
systemctl restart systemd-journald

echo "== Check"
unattended-upgrade --dry-run >/dev/null 2>&1 && echo "unattended-upgrades: config OK"
for s in apache2 postgresql tucker fail2ban ufw unattended-upgrades certbot.timer; do
  printf '  %-22s boot=%-8s now=%s\n' "$s" "$(systemctl is-enabled $s 2>/dev/null)" "$(systemctl is-active $s 2>/dev/null)"
done
echo "Timezone: $(timedatectl show -p Timezone --value)"
