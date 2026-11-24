<p align="center"><a href="https://tuckerpaymentprocessing.com"><img src="docs/banner.png" alt="Tucker Payment Processing: An AI Governance, Technology and Security Demonstration" width="100%"></a></p>

**Live site:** https://tuckerpaymentprocessing.com

Tucker Payment Processing is a **fictional** payment company. Its customer-support agent is Tucker (a real cocker spaniel), an AI assistant built to show how a customer-facing AI should be governed and secured: what it is allowed to do, what it is never allowed to do, and how every guardrail is visible in real time.

> Status: early build. The live site currently shows a starter page while the demo is built.

## What the finished demo will show
- A guided tour that starts as soon as you land, narrated by Tucker in speech bubbles.
- A chat with Tucker beside a live **"Behind the Scenes"** panel that shows the code path and every guardrail as it fires.
- A read-only site: the only free-form input is the chat. No uploads, no sign-ups, no forms that write data.
- Guardrails: read-only tools, authorization decided in Python (never by the model), last-4-digits-only card output, prompt-injection checks, topic fence, rate limits, and a hard monthly AI spend cap with a graceful "Tucker's taking a nap" fallback.
- Policy answers grounded in the site's own policy documents (retrieval-augmented generation), with the source named.

## Stack
Google Cloud (Always Free e2-micro, Ubuntu 24.04) · Apache · Python (FastAPI) · PostgreSQL · Gemini (paid tier, so chats are not used for training) · Let's Encrypt TLS · Cloudflare DNS.

## Security and privacy by design
- Admin access is identity-based: no SSH open to the internet; access only through Google's Identity-Aware Proxy with 2-step verification.
- Least privilege everywhere: the server has no cloud permissions; the app's database user is read-only.
- No cookie banner because nothing needs consent: one strictly necessary session cookie, no analytics cookies, no third-party scripts or fonts.
- Secrets live only on the server, never in this repository.

## Repository layout
- `site/` - public web pages (currently the coming-soon page)
- `app/` - the Python (FastAPI) application behind Tucker's chat:
  - `chat.py` - one chat turn through every guardrail, in order
  - `guardrails.py` - input checks, prompt-injection detection, output masking
  - `tools.py` - Tucker's only abilities: read-only lookups, authorized in Python
  - `session.py` - who is verified (the AI never chooses whose data to read)
  - `spend.py` - the app-level AI spending cap
  - `policies.py` - small retrieval (RAG) over the policy documents
  - `llm.py` - swappable model adapter (Google Gemini, plus a fake model for tests)
  - `db.py` - all database access, parameterized queries only
- `db/` - schema, least-privilege database role, fictional seed data
- `policies/` - the company's (fictional) policies that Tucker answers from
- `tests/` - automated tests proving the guardrails work (run with `pytest`)

Built by **Michael Cunningham**, information security leader (25+ years, payments and PCI), with AI-assisted development.
LinkedIn: https://www.linkedin.com/in/mcunningham-infosec/

All names, customers, cards and data on the site are fictional.
