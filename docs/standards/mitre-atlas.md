# MITRE ATLAS
The attacker techniques that apply to the site's AI, and the defense against each · Self-assessment · November 24, 2026

## About this document
This is a self-assessment written by Michael Cunningham, who designed and built the site. MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the AI counterpart of MITRE ATT&CK: a catalog of the techniques real attackers use against AI systems, organized by tactic, which security operations and threat-hunting teams use to plan detections and red-team tests. Where the OWASP lists describe risks, ATLAS describes what the attacker actually does.
This write-up uses ATLAS release v2026.10 (October 28, 2026: 16 tactics, 129 techniques and 92 sub-techniques), taken from MITRE's official data. That release moved two techniques this site relies on into new sub-techniques, and the IDs below use the new numbers. It covers the eleven techniques that fit a public chatbot and an AI security analyst. Techniques that need access the site never offers, such as stealing model weights or poisoning training data, don't apply: the model is Google's hosted Gemini and nothing is trained here. The attack simulator tags each of its AI attacks with the technique it uses, in the live log and in the incident report.

## Techniques
### AML.T0051.000 LLM Prompt Injection: Direct
**Status: Met**
The attacker types instructions meant to override the AI's own. Known injection phrasing is blocked before it reaches the model, and the real control is that a successful injection gains nothing: the AI chatbot's tools are read-only and Python decides whose data can be read.
Evidence: `app/guardrails.py`, `app/tools.py`, `tests/test_guardrails.py`; tested live by the attack simulator: Order the AI chatbot to ignore its rules.

### AML.T0051.001 LLM Prompt Injection: Indirect
**Status: Met**
The attacker hides instructions in data the AI will read later. Here that means attack payloads landing in the logs the AI SOC reviews. Every log line is shortened, defanged and wrapped as untrusted data, and the AI SOC can only propose actions that Python checks. The attack simulator plants such instructions on every run to prove it.
Evidence: `app/cipher/soc.py`, `tests/test_cipher_soc.py`; tested live by the attack simulator: Plant instructions in the logs for the AI SOC.

### AML.T0054 LLM Jailbreak
**Status: Met**
Jailbreaks try to talk the model out of its rules ("developer mode", role-play). Common forms are blocked at input, but the design doesn't rely on that: rules that matter (authorization, masking, limits) are enforced in Python, outside the model, so a jailbroken chatbot is still unable to do anything harmful.
Evidence: `app/guardrails.py`, `app/chat.py`.

### AML.T0085.003 Data from AI Services: System Instructions
**Status: Met**
The attacker tries to make the AI reveal its hidden instructions. The AI chatbot's instructions are published in the open-source repository on purpose, and they hold no secrets, keys, customer data or security rules, so extracting them is worthless.
Evidence: `app/chat.py`; tested live by the attack simulator: Trick the AI chatbot into revealing its hidden instructions.

### AML.T0085.002 Data from AI Services: Conversation Context and Memory
**Status: Met**
The attacker tries to make the AI reveal data it shouldn't. The AI never has full card numbers to leak, it sees only the verified customer's own minimized records, and every reply is filtered for card numbers, Social Security numbers and API keys before it is shown.
Evidence: `db/schema.sql`, `app/tools.py`, `app/guardrails.py`, `tests/test_guardrails.py`; tested live by the attack simulator: Ask for every customer's full card number and Make the AI chatbot print a card number.

### AML.T0053 AI Agent Tool Invocation
**Status: Met**
The attacker tries to make the agent call its tools for them. The AI chatbot's tools are all read-only lookups, allow-listed per page, limited to four rounds per reply, and none accepts a customer number from the AI. There is no tool that refunds, pays, edits or deletes anything.
Evidence: `app/tools.py`, `tests/test_guardrails.py`, `tests/test_page_chats.py`; tested live by the attack simulator: Get the AI chatbot to issue a refund.

### AML.T0086 Exfiltration via AI Agent Tool Invocation
**Status: Met**
The attacker uses an agent's write-capable tools (sending email, posting to a URL) to carry stolen data out. Neither agent has any tool that writes, sends or calls out, so there is no channel to exfiltrate through.
Evidence: `app/tools.py`, `app/cipher/soc.py`.

### AML.T0080 AI Agent Context Poisoning
**Status: Met**
The attacker plants content in an agent's memory or context to steer it later. The AI chatbot's conversation lives only in server memory for one visitor's session, which ends after 30 minutes of inactivity, and only the last eight messages are sent to the model, so nothing one visitor plants reaches another. The policy library is under version control, and the AI SOC sees only the current attack run.
Evidence: `app/session.py`, `app/chat.py`, `app/policies.py`.

### AML.T0034.001 Cost Harvesting: Resource-Intensive Queries
**Status: Met**
The attacker runs up the victim's AI bill with long or expensive requests. Messages are capped at 500 characters and requests at 16 KB, each network has a fair share of the day's AI budget, hard caps of $5 a day and $50 a month stop all AI use, with Google's own $60 spend cap behind them, and the attack simulator's real attacks run one at a time, under a daily cap set on the server, with a fair line for everyone else.
Evidence: `app/config.py`, `app/spend.py`, `app/limits.py`, `tests/test_limits.py`; tested live by the attack simulator: Send a novel to run up the AI bill.

### AML.T0029 Denial of AI Service
**Status: Met**
The attacker floods the AI to make it unavailable to everyone else. Per-minute, per-session and per-day limits by visitor and by network (an IPv6 visitor counts as their whole /64), Cloudflare's protection in front of the server, and the fair-share rule keep one source from crowding others out.
Evidence: `app/limits.py`, `deploy/gcp-firewall.md`, `tests/test_limits.py`; also exercised by the attack simulator's request-flood test, which is filed as a web attack rather than an ATLAS technique.

### AML.T0048 External Harms
**Status: Met**
The attacker uses the AI to cause harm outside the system: financial loss, reputational damage or harm to users. The AI chatbot cannot move money or change accounts, stays on Tucker Payment Processing topics only, discloses that it is an AI, and never asks for card numbers, passwords or Social Security numbers.
Evidence: `app/chat.py`, `app/tools.py`, `policies/ai-assistant-policy.md`.

## Detection, not just prevention
ATLAS is also a detection map. On the site, code rules count what the real defenses blocked from each source: after 15 blocked attacks the AI SOC is woken to investigate, and after 50 the source is refused for the rest of the run. The AI SOC's incident report lists the techniques it saw, so a reader can tie every event back to this catalog.
Evidence: `app/cipher/detect.py`, `app/cipher/attacks.py`, `site/assets/report.js`.
