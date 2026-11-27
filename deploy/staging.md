# Staging: where every change is tried before it reaches the live site

**staging.tuckerpaymentprocessing.com** is a complete, separate copy of Tucker Payment Processing. Changes are
built, tested, attacked and scanned there first. Only code moves to production, from the `main` branch, after
staging passes.

## Two environments, sized to the risk

| | Production | Staging |
|---|---|---|
| Code | `main` branch | `staging` branch (features are built on their own branches) |
| Server | `tucker-web` VM | `tucker-staging` VM, built from this repository by `deploy/staging-setup.sh` |
| Database | its own PostgreSQL | its own PostgreSQL: same schema, roles and fictional seed data |
| Secrets | `/etc/tucker/tucker.env` | its own env file: separate Gemini key, separate salt, lower spend caps |
| Who can reach it | everyone, through Cloudflare | only the owner: Cloudflare Access with Google login, in front of Cloudflare's usual protection |
| Firewall | web only from Cloudflare; admin only through IAP | identical |
| Search engines | indexed | kept out (`X-Robots-Tag: noindex` and `robots.txt`) |
| Owner report and alerts | on | off |

There is no separate development tier: a one-person project doesn't need one. Development happens on a branch,
GitHub Actions runs the full test suite on every push (`.github/workflows/tests.yml`) against a throwaway
database, and staging is the one shared test environment.

## Data rules

- Staging holds only the same fictional demo data as production. There are no real card numbers anywhere in
  this project, in either environment.
- Nothing is copied from staging to production except code. Test orders and test runs stay on staging.
- Staging never uses production's secrets. Its Gemini key and budget are separate, so a test can't spend
  production's AI budget.

## The login in front (Cloudflare Access)

Cloudflare Zero Trust (free plan) protects `staging.tuckerpaymentprocessing.com` with an Access application:

- Login method: Google (an OAuth client in Google Cloud, entered in Zero Trust by the owner). The emailed
  one-time code stays on as a backup way in.
- Policy: allow only the owner's Google account. Session length: one month.
- Nothing reaches the staging server without passing Access, and the Google Cloud firewall only admits
  Cloudflare, so the login can't be skipped by going to the server's address directly.
- Tests and Cipher runs on staging run on the server itself (through IAP SSH), so they never need the login.

## Building it (once)

1. Create the `tucker-staging` VM in the same project, region and network as production (Ubuntu 24.04).
2. Add a proxied DNS record `staging` pointing at its address in Cloudflare.
3. On the VM: `sudo bash staging-setup.sh` (from this folder). It installs everything from the repository.
4. The owner pastes the staging Gemini key into `/etc/tucker/tucker.env` and runs the certbot line the
   script prints (accepting Let's Encrypt's terms is the owner's call).
5. Turn on Cloudflare Access for the hostname (above).

## Updating it (every change)

From Cloud Shell, the same one step as production, pointed at the staging server:

    gcloud compute ssh tucker-staging --zone us-east1-b --tunnel-through-iap --command "sudo git -C /opt/tucker pull -q && sudo bash /opt/tucker/deploy/update.sh"

`update.sh` sees `/etc/tucker/STAGING` and keeps the owner report off.

## Release checklist (staging to production)

1. GitHub Actions: all tests pass on the branch.
2. Staging: a full Cipher run with every attack held; timing and AI cost per run written down.
3. Merge to `main`, deploy production the normal way, then run Cipher once on production.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
