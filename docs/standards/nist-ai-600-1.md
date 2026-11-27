# NIST AI 600-1: Generative AI Profile
The twelve risks NIST names for generative AI, and how each is handled here · Self-assessment · November 25, 2026

## About this document
This is a self-assessment written by Michael Cunningham of Root Cause Associates, who designed and built the site. It is not an audit. NIST AI 600-1, the Generative Artificial Intelligence Profile (July 2024), is a companion to the NIST AI Risk Management Framework. It names twelve risks that are unique to generative AI, or made worse by it, and suggests actions for each. It is voluntary, and it is still NIST's current profile for generative AI; NIST has said the AI RMF itself is being revised under the White House AI Action Plan.
Both of the site's AI systems are generative: the AI chatbot, the customer-support agent, and the AI SOC, which writes incident reports, both run on Google Gemini. The framework-level view is in the NIST AI RMF write-up; this one goes risk by risk.
Evidence: `docs/standards/nist-ai-rmf.md`.

## The twelve risks
### 1. CBRN information or capabilities
**Status: Met**
The risk is an AI making it easier to find or design chemical, biological, radiological or nuclear weapons. The AI chatbot will only discuss Tucker Payment Processing: accounts, cards, orders and company policies. Anything else is politely declined and steered back, and Gemini's own safety training sits underneath that rule. Neither AI can search the web or reach any outside information.
Evidence: `app/chat.py`, `app/tools.py`.

### 2. Confabulation
**Status: Partly met**
Confabulation is confidently stated falsehood, often called hallucination. The AI chatbot is told to use its tools for every fact and never to invent account data, numbers or policy rules; answers about policies must name the policy used; and the model runs at a low temperature. The AI SOC goes further: code checks its report against the logged events, correcting any number it states, setting whether an injection was attempted from the actual logs, and removing any claim of a block that has not happened yet. The gap: the AI chatbot's free-text replies are not automatically scored for accuracy, so a wrong paraphrase of a policy could still reach a visitor.
Evidence: `app/chat.py`, `app/llm.py`, `app/cipher/soc.py`, `tests/test_cipher_soc.py`.

### 3. Dangerous, violent or hateful content
**Status: Partly met**
The topic limit keeps the AI chatbot away from violent, hateful or illegal subjects, and the attack simulator tests, on every run, whether it can be ordered to ignore its rules. NIST also lists advice on self-harm under this risk. The AI chatbot declines such messages as off topic, but it has no specific response that points a person in crisis to help, such as the 988 Suicide and Crisis Lifeline. A public chatbot should have one, and Colorado's new chatbot law will require one; it is the clearest gap this review found.
Evidence: `app/chat.py`, `app/cipher/attacks.py`, `docs/standards/colorado-ai-laws.md`.

### 4. Data privacy
**Status: Met**
The AI chatbot can only read a customer's records after the identity check, and only that customer's. Its tools are read-only. Anything that looks like a full card number is masked before it is shown. Visitors' IP addresses are never sent to the AI, web logs are deleted after two days, and on Gemini's paid tier the conversations are not used to train the model.
Evidence: `app/tools.py`, `app/guardrails.py`, `app/limits.py`, `policies/data-retention.md`.

### 5. Environmental impacts
**Status: Met**
Generative AI uses a lot of computing power, mostly in training. The site trains nothing. It uses the smallest Gemini model that does the job (Flash-Lite), keeps the model's "thinking" to a minimum, caps every reply's length, and has hard daily and monthly spending caps, which also cap the computing used. Pages are cached by Cloudflare, so most visits never reach the server.
Evidence: `app/llm.py`, `app/config.py`, `app/spend.py`.

### 6. Harmful bias or homogenization
**Status: Partly met**
The biggest bias risk in finance is an AI deciding something about a person unfairly. Here, neither AI decides anything about anyone: the AI chatbot explains and looks things up, and every verified customer gets the same tools and the same rules. The gap: the AI chatbot has only been tested in English, so how well it serves people writing in other languages has not been measured.
Evidence: `app/chat.py`, `docs/standards/iso-42005.md`.

### 7. Human-AI configuration
**Status: Met**
This risk is about people trusting AI too much, or in the wrong way. The AI chatbot says it is an AI in its greeting and whenever asked, and it cannot change anything: no refunds, no moving money, no unfreezing cards. It sends people to the secure portal or the disputes team instead. The AI SOC only proposes actions from a fixed menu; the real blocking is done by code rules, and anything that got through is flagged for a human.
Evidence: `app/chat.py`, `app/cipher/soc.py`, `app/cipher/detect.py`.

### 8. Information integrity
**Status: Met**
The risk is AI producing content that blurs fact and fiction at scale. The AI chatbot only talks about one clearly labeled fictional company, using its own records. Every reply the model writes is marked as AI-generated in the data the page receives, and the incident report PDF names the AI as its author in the file itself.
Evidence: `app/chat.py`, `site/assets/report-pdf.js`, `docs/standards/eu-ai-act.md`.

### 9. Information security
**Status: Met**
Generative AI brings new attacks, prompt injection above all, and the site is built around them: injection checks before anything reaches the model, read-only tools, identity enforced in code rather than by the model, output masking, rate limits and spend caps. The attack simulator runs 100 real attacks against the live site on demand, and each OWASP AI risk is answered in its own write-up.
Evidence: `app/guardrails.py`, `app/cipher/attacks.py`, `docs/standards/owasp-llm-top-10.md`, `tests/test_guardrails.py`.

### 10. Intellectual property
**Status: Met**
The risk is an AI reproducing copyrighted or confidential material. The topic limit keeps the AI chatbot to the company's own products, records and policies, which the site owns. It does not write essays, code, lyrics or anything else outside that scope, and it generates no images.
Evidence: `app/chat.py`.

### 11. Obscene, degrading or abusive content
**Status: Met**
Both AIs produce text only, so there is no image or video generation to misuse. The AI chatbot's topic limit and Gemini's own safety training sit in front of any attempt to make it produce abusive content, and attempts to break its rules are part of the attack simulator's attack set.
Evidence: `app/chat.py`, `app/cipher/attacks.py`.

### 12. Value chain and component integration
**Status: Partly met**
Every outside component is known and bounded: Google (model and hosting), Cloudflare (DNS, TLS and protection) and Resend (alert email), each receiving only what it needs. The model sits behind a small adapter, so it can be swapped, and the model is named in one place. Python libraries are pinned to exact versions (one held to a major version) and checked by Dependabot. The gap: the site relies on Google's published documentation for how Gemini was built and tested; it cannot inspect the model itself.
Evidence: `app/llm.py`, `app/config.py`, `requirements.txt`.

## The bottom line
Eight of the twelve risks are handled by design, mostly because neither AI can decide or change anything about a person. The four gaps are stated plainly: no automatic accuracy scoring of the AI chatbot's replies, no crisis-referral response for self-harm messages, no testing in languages other than English, and no way to inspect the vendor's model itself. The crisis referral is the one a real company should fix first.
