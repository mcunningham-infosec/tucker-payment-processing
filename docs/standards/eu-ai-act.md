# EU AI Act (Regulation (EU) 2024/1689)
Where the AI chatbot sits in the EU's risk tiers, and the duties that apply · Self-assessment · November 24, 2026

## About this document
This is a self-assessment written by Michael Cunningham, who designed and built the site. It is not legal advice. Tucker Payment Processing is a fictional US company with no EU customers, so the AI Act would not apply to it in practice. This document asks a more useful question: if a real payment company deployed this same chatbot to customers in the EU, what would the Act require, and does the design already meet it?
The Act sorts AI by risk. Some practices are banned outright. "High-risk" systems face the heaviest duties. Systems that talk to people, or generate content, have transparency duties. The rest have few or none. The dates reflect the Digital Omnibus on AI (Regulation (EU) 2026/1744), in force since July 27, 2026, which pushed back some deadlines.

## Classification
### Prohibited practices (Article 5)
**Status: Not applicable**
Neither AI does anything on the banned list, such as manipulative techniques that cause harm, social scoring or exploiting people's vulnerabilities. The AI chatbot is a support assistant; it cannot persuade anyone to spend money, and it has no tool that could.

### High-risk systems (Article 6, Annex III)
**Status: Not applicable**
Payment companies need to watch this one. Annex III lists AI used to assess a person's creditworthiness or set their credit score as high-risk (fraud detection is excluded). The AI chatbot makes no decision about anyone: no credit, eligibility, pricing or fraud decisions. It only reads a verified customer's own records and explains policies. If a real company later let a chatbot like this one decide disputes or offer credit, it would become high-risk. Under the Digital Omnibus, the Annex III duties now apply from December 2, 2027.

### Transparency: telling people they are talking to an AI (Article 50(1))
**Status: Met**
This is the duty that applies, from August 2, 2026: people must be told they are dealing with an AI unless it is obvious. The AI chatbot's greeting in every chat says it is an AI assistant, its label on the home page reads "AI Support Agent", and its instructions require it to say it is an AI if asked. The AI SOC is labeled "AI Security Analyst", and its incident report names it as the author.
Evidence: `site/index.html`, `site/treats.html`, `site/checkout.html`, `app/chat.py`.

### Transparency: marking AI-generated content (Article 50(2))
**Status: Partly met**
Providers of AI that generates text must also mark it as AI-generated in a machine-readable way, where technically feasible, from August 2, 2026 (December 2, 2026 for systems already on the market before then). Every reply the AI chatbot's model writes carries an "ai_generated: true" mark in the data the website receives; most of the app's own fixed messages, such as the notice shown when the AI is unavailable, are marked false, though two fallback replies (when a lookup cannot be finished, or the model returns nothing) are still marked as AI-generated and should be corrected. The AI SOC's incident report PDF names the AI as its author in the file's metadata. The European Commission published its final Code of Practice on marking and labelling AI-generated content on June 10, 2026; a real company would align its marking with that code, which this site has not yet done.
Evidence: `app/chat.py`, `tests/test_guardrails.py`, `site/assets/report-pdf.js`.

## Other duties
### AI literacy (Article 4)
**Status: Met**
Companies that provide or deploy AI should make sure the people working with it understand it. The Digital Omnibus softened the original wording, but the expectation remains. The site's builder and only operator wrote its AI policies, designed its guardrails and documents how each AI works and fails.
Evidence: `policies/ai-assistant-policy.md`, `site/about.html`.

### General-purpose AI model duties (Articles 53 to 55)
**Status: Not applicable**
These fall on the company that makes the underlying model (Google, for Gemini), not on a company that builds a chatbot on top of it. A real deployer would keep Google's published documentation for the model on file.

### Data protection alongside the Act
**Status: Met**
The AI Act sits on top of the GDPR, which would apply to a real EU deployment. The design already practices data minimization: no IP addresses are sent to the AI, chat text is not stored with IP addresses, web logs are kept for at most two days, the only cookie is strictly necessary (so no cookie banner is needed), and the model provider does not train on the chats.
Evidence: `policies/data-retention.md`, `deploy/logrotate-apache2`, `app/limits.py`.

## The bottom line
As built, the AI chatbot is a limited-risk AI system. Its main duty, telling people they are talking to an AI, is met in every chat. The content-marking duty is partly met: replies are marked, but not yet aligned with the Commission's Code of Practice. The design choice that keeps it out of the high-risk tier is the same one that makes it secure: the AI decides nothing about anyone.
