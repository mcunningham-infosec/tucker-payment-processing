# Google Cloud firewall: only Cloudflare can reach the web server

Cloudflare's protection (DDoS absorption, web application firewall, bot defense) only works if attackers can't
skip it by going straight to the server's own IP address. So the Google Cloud firewall lets web traffic
(ports 80 and 443) in **only from Cloudflare's published IPv4 ranges** (https://www.cloudflare.com/ips/).
Anyone who tries the server's IP directly gets no answer at all.

| Rule | Allows | From |
|---|---|---|
| `allow-web` | TCP 80, 443 (web) | Cloudflare's IPv4 ranges only |
| `allow-ssh-iap-only` | TCP 22 (admin) | Google's Identity-Aware Proxy, `35.235.240.0/20`, only (no public SSH) |

How `allow-web` was locked down (run in Cloud Shell). The ranges are fetched fresh from Cloudflare rather
than typed by hand:

    CF=$(curl -s https://www.cloudflare.com/ips-v4 | paste -sd,)
    gcloud compute firewall-rules update allow-web --source-ranges="$CF"

Check it:

    gcloud compute firewall-rules describe allow-web --format="value(sourceRanges)"
    curl -s -o /dev/null -w '%{http_code}\n' https://tuckerpaymentprocessing.com/      # 200 through Cloudflare
    curl -s -m 5 -o /dev/null -w '%{http_code}\n' -k https://<server IP>/             # 000: no answer direct

Notes:
- Cipher's attacks are unaffected: they run on the server against its own address.
- Apache trusts the visitor's real IP (the `CF-Connecting-IP` header) only from these same Cloudflare ranges
  (`deploy/apache-cloudflare.conf`). If Cloudflare ever publishes new ranges, update both together.
- Certificate renewals (Let's Encrypt) still work behind Cloudflare.
