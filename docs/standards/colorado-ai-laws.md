# Colorado AI laws: SB 26-189 and HB 26-1263
Colorado's automated decision law, which replaced the Colorado AI Act, and its new chatbot law · Self-assessment · November 25, 2026

## About this document
This is a self-assessment written by Michael Cunningham, who designed and built the site. It is not legal advice. Tucker Payment Processing is fictional and has no Colorado customers; as with the EU AI Act write-up, the useful question is what these laws would require of a real payment company running this same chatbot for people in Colorado, and whether the design already meets it.
Colorado passed the first broad US state AI law in 2024, the Colorado AI Act (SB 24-205). It never took effect. On May 14, 2026, Colorado repealed and replaced it with SB 26-189, a narrower law about automated decision-making technology used in consequential decisions, including access to financial and lending services. Its duties begin on January 1, 2027, and the attorney general is writing the rules. The old law's broad duty of care against algorithmic discrimination, and its safe harbor for following the NIST AI RMF or ISO/IEC 42001, are gone.
A second law matters more for a chatbot: HB 26-1263, signed on May 29, 2026, sets rules for operators of public conversational AI services, with its design duties applying from January 1, 2027. Its exact exclusions depend on the final text and the attorney general's rules, so this assessment treats Tucker as covered.
Evidence: `docs/standards/eu-ai-act.md`.

## SB 26-189: automated decisions
### Tucker and consequential decisions
**Status: Not applicable**
The law applies when automated technology materially influences a consequential decision about a person, such as approving credit, setting a price or opening an account. Tucker influences no decision: he reads a verified customer's own records, explains policies and points to the secure portal or the disputes team. He cannot approve, deny, refund or change anything, so there is no adverse decision to explain.
Evidence: `app/chat.py`, `app/tools.py`.

### The AI SOC analyst and blocking
**Status: Not applicable**
Blocking a source of attacks could, in a real payment company, keep a customer from reaching a financial service, so it is worth checking. The block here is made by fixed code rules after repeated attacks, not by the AI, and it lasts 24 hours. The AI SOC analyst only writes the report and proposes actions from a fixed menu; it decides nothing about a person.
Evidence: `app/cipher/detect.py`, `app/cipher/soc.py`.

### Records
**Status: Not applicable**
If either AI ever did influence a consequential decision, the law would require records for at least three years. The site keeps records briefly on purpose, for privacy: web logs for two days, demo data reset nightly. A real deployment that came into scope would need a separate, longer-lived record of each decision. The AI's instructions and tools are already in version control, so how it behaved at any point is on record.
Evidence: `policies/data-retention.md`, `app/chat.py`.

## HB 26-1263: chatbots
### Telling people they are talking to an AI
**Status: Met**
Operators must disclose that a user is interacting with AI. Tucker's greeting in every chat says he is an AI assistant, his label on the page reads "AI Support Agent", he says so whenever asked, and every reply the model writes is marked as AI-generated in the data the page receives.
Evidence: `site/index.html`, `app/chat.py`.

### A protocol for suicidal ideation and self-harm
**Status: Partly met**
Operators must have a protocol for messages about suicidal ideation or self-harm that refers the person to a crisis service. Tucker declines anything outside Tucker Payment Processing and steers back, so he will not give harmful advice, but he has no specific response that points the person to help, such as the 988 Suicide and Crisis Lifeline. This is a real gap. The fix is a check that runs before the AI, like the prompt-injection check, and answers with a fixed crisis-referral message.
Evidence: `app/chat.py`, `app/guardrails.py`.

### Not implying professional services
**Status: Met**
Operators may not imply that the chatbot's output is equivalent to advice from a licensed professional. Tucker discusses only the company's own accounts, orders and policies, declines opinions and other topics, and sends account changes and disputes to the right team.
Evidence: `app/chat.py`, `policies/ai-assistant-policy.md`.

### Protections for minors
**Status: Partly met**
For users under 18, the law adds repeated AI disclosure, no points or rewards to drive engagement, measures against sexually explicit content and statements that simulate emotional dependence, and privacy controls. Tucker has no rewards, his topic limit keeps conversations to payments, and he says he is an AI. His playful dog persona is light, but the site does not know a visitor's age, so it cannot switch that persona off or repeat the disclosure specifically for minors.
Evidence: `app/chat.py`.

### Annual reporting to the attorney general
**Status: Partly met**
Operators must report on their crisis protocol each year. Guardrail events are already counted and summarized every night, so crisis referrals could be counted the same way once the protocol exists.
Evidence: `app/report.py`.

## The bottom line
Under SB 26-189, the site is out of scope for the same reason it stays out of the EU AI Act's high-risk tier: the AI decides nothing about anyone. If a real company let an AI approve credit or decide disputes, it would owe consumers notice, a plain-language explanation within 30 days of an adverse decision, a way to correct their data and a human review. Under HB 26-1263, AI disclosure is met, and the one gap that matters is a crisis-referral protocol, which a real company should add before January 1, 2027.
