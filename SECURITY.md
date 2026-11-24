# Security policy

Tucker Payment Processing is a **fictional** company built as an AI governance and security demonstration
(https://tuckerpaymentprocessing.com). There is no real customer, card or payment data anywhere in it.
That said, the security is real, and reports are genuinely welcome.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability**
(https://github.com/mcunningham-infosec/tucker-payment-processing/security/advisories/new).
Please don't open a public issue for a security problem.

Helpful details: what you found, where (page, API path or file), how to reproduce it, and what an attacker
could do with it. You'll get an acknowledgement, and fixes are credited in the commit history if you'd like.

## Scope

In scope: the website and its API, the AI guardrails around Tucker and the AI SOC Squirrel (including prompt
injection that gets around them), and the code and server configuration in this repository.

Out of scope: denial of service and volume testing, social engineering, and third-party services
(Cloudflare, Google Cloud, Google Gemini) themselves.

## Testing

Please don't point automated scanners or attack tools at the live site. Cipher's Lair already runs 50 real
attacks against it, safely, from inside its own server, and anyone can run that. For deeper testing, run the
project locally from this repository; the tests in `tests/` show how the guardrails are checked.

The site publishes this policy at https://tuckerpaymentprocessing.com/.well-known/security.txt (RFC 9116).
