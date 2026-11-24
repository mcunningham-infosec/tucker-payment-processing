# Origin lockdown: only Cloudflare can reach the web server

Cloudflare's protection (DDoS absorption, firewall rules, bot defense) only works if attackers can't skip it by
going straight to the server's own IP address (34.26.213.50). So the Google Cloud firewall allows web traffic
(ports 80 and 443) ONLY from Cloudflare's published IPv4 ranges (https://www.cloudflare.com/ips/). Admin access
(SSH on port 22) stays limited to Google's Identity-Aware Proxy range, 35.235.240.0/20, as before.

    CF=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22
    gcloud compute firewall-rules create allow-web-cloudflare-only --network=default --direction=INGRESS \
        --action=ALLOW --rules=tcp:80,tcp:443 --source-ranges="$CF" --target-tags=http-server,https-server \
        --description="Web traffic only via Cloudflare (origin lockdown)"
    # then remove the old open-to-the-world web rules:
    gcloud compute firewall-rules delete default-allow-http default-allow-https

Cipher's attacks are unaffected: they run on the server against its own loopback address.
If Cloudflare ever publishes new ranges, update this rule and deploy/apache-cloudflare.conf together.
