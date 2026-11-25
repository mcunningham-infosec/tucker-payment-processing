# DNS (Cloudflare) for tuckerpaymentprocessing.com

Registrar and DNS: Cloudflare (Free plan). Every record below is live; check with `dig` against any public resolver.

| Record | Type | Value | Why |
|---|---|---|---|
| `@`, `www` | A (proxied) | the server | Visitors reach the server only through Cloudflare |
| `@` | CAA | `0 issue "letsencrypt.org"` | Only Let's Encrypt (plus Cloudflare's own CAs) may issue certificates |
| (zone) | DNSSEC | enabled, DS at the registrar | Answers are signed, so DNS can't be forged |
| `@` | TXT (SPF) | `v=spf1 -all` | No server anywhere may send email as this domain |
| `_dmarc` | TXT (DMARC) | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` | Receivers must reject any email claiming to be from it (subdomains too) |
| `*._domainkey` | TXT (DKIM) | `v=DKIM1; p=` | Every DKIM signing key is revoked |
| `@` | MX | `0 .` (null MX, RFC 7505) | The domain accepts no email |

## Why the domain is locked out of email

The site never sends email as @tuckerpaymentprocessing.com: the owner's alerts and nightly report go out through
Resend's shared sender (`onboarding@resend.dev`). So the domain follows the standard "this domain sends no mail"
setup (M3AAWG / CISA guidance for non-sending domains): nobody can spoof it in a phishing email, and receivers are
told to reject anything that tries. Verified Nov 24, 2026: the records resolve on Cloudflare and Google public
DNS, and a test report still arrived normally.

If the site ever needs to send as its own domain, replace the SPF and DKIM records with the ones Resend gives when
the domain is verified there, and remove the null MX only if the domain should receive mail.

## Cloudflare settings that matter

- SSL/TLS: minimum TLS 1.2; "Always Use HTTPS" on, so plain-HTTP requests are redirected at Cloudflare's edge
  before they reach the server (the HSTS preload checker requires that no HSTS header is sent over HTTP).
- HSTS: sent by the server (max-age two years, includeSubDomains, preload; see apache-hardening.conf). The domain was
  submitted to the browser preload list at hstspreload.org on Nov 24, 2026 (status: pending). Once listed, removal
  takes months, so every subdomain must stay HTTPS-only.
- Caching: Browser Cache TTL = "Respect Existing Headers" (the server's Cache-Control rules decide).
- Security: Bot Fight Mode on; Cloudflare managed ruleset on; Turnstile human check on Cipher's Lair.
