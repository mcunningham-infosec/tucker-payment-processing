# Model Risk Management: SR 26-2 (formerly SR 11-7)
The US banking agencies' model risk guidance, applied to the site's AI the way a bank would · Self-assessment · November 25, 2026

## About this document
This is a self-assessment written by Michael Cunningham, who designed and built the site. It is not an audit or a regulatory opinion. For fifteen years, US banks governed their models under SR 11-7 (the Federal Reserve's 2011 guidance, issued by the OCC as Bulletin 2011-12). On April 17, 2026, the Federal Reserve, the OCC and the FDIC rescinded it and issued revised interagency guidance: Federal Reserve SR 26-2, OCC Bulletin 2026-13 and FDIC FIL-16-2026. Many policies still say "SR 11-7".
The revised guidance is principles-based and risk-based. It covers model development and use, validation and monitoring, governance and controls, and vendor and third-party models, scaled to a bank's size and how much it relies on each model. It matters most for banks with more than $30 billion in assets.
One detail shapes everything below: the agencies say generative AI and agentic AI are "novel and rapidly evolving" and so are not within the scope of the guidance. They have said separate AI guidance will follow. Until then, banks are expected to manage these tools with their broader risk management, and the NIST AI Risk Management Framework is the usual reference. So this write-up does what a careful bank's model risk team would do today: it applies the guidance's principles to Tucker and the AI SOC analyst voluntarily, as a sound practice, not as a legal requirement.
Evidence: `docs/standards/nist-ai-rmf.md`.

## Scope and inventory
### Is the site's AI a "model" under the guidance?
**Status: Not applicable**
Strictly, no: both AIs are generative and agentic, which the agencies excluded, and the guidance's definition of a model centers on quantitative methods that produce estimates. A bank would still put them in its inventory and apply the same discipline, which is what the rest of this document does.

### Model inventory and ownership
**Status: Met**
Every AI system is listed with its purpose, owner, underlying model and what it can and cannot do: Tucker (customer support, read-only) and the AI SOC analyst (writes incident reports, proposes actions from a fixed menu). The owner is named, and the model in use is set in one place in the configuration.
Evidence: `site/about.html`, `app/config.py`, `docs/standards/iso-42005.md`.

### Risk rating and materiality
**Status: Met**
The guidance scales oversight to a model's risk and materiality. Both AIs rate low: neither makes a decision about any person, neither can move money or change an account, and the business does not depend on their answers being right. The rating would rise sharply if a model were ever used to decide credit, disputes or fraud, and the impact assessment says so.
Evidence: `docs/standards/iso-42005.md`, `docs/standards/iso-23894.md`.

## Development and validation
### Development and testing before use
**Status: Met**
Each AI's design, intended use and limits are documented, and 88 automated tests check the controls before any change is deployed, using a scripted stand-in for the model so the results are exact and repeatable.
Evidence: `tests/`, `app/llm.py`, `tests/test_guardrails.py`.

### Conceptual soundness
**Status: Partly met**
The design choices are documented and reasoned: facts come from tools rather than the model's memory, identity is checked in code, and the AI SOC analyst's claims are checked against the real data. What cannot be assessed is the inside of the model itself, because Gemini is a vendor model; the site relies on Google's published documentation for that.
Evidence: `app/chat.py`, `app/cipher/soc.py`.

### Ongoing monitoring and outcomes analysis
**Status: Partly met**
Every guardrail event is logged and summarized in a nightly report to the owner, spending is tracked against hard caps, and Cipher's Lair re-tests the defenses on demand with 50 live attacks, counting what held. The gap: Tucker's answers are not sampled and scored for accuracy, and there is no automatic check for drift when Google updates the model behind the same name.
Evidence: `app/report.py`, `app/spend.py`, `app/cipher/detect.py`.

### Independent validation
**Status: Partly met**
The revised guidance judges validation by its rigor and effectiveness rather than by who it reports to. Some of it is independent here: five public scanners graded the site, the code is open for anyone to review, and anyone can attack the live site. But no independent reviewer has validated the AI's behavior; the person who built it also tested it.
Evidence: `docs/scans/`, `SECURITY.md`.

## Governance and vendors
### Governance, policies and controls
**Status: Partly met**
Written AI policies came before the build, one owner is accountable, and every control is documented next to the code that enforces it. What one person cannot show is the structure a bank's examiners would look for: board reporting, a separate model risk function and internal audit.
Evidence: `policies/ai-assistant-policy.md`, `README.md`.

### Change control for models
**Status: Met**
A change to the model, its instructions or its tools is a code change: recorded in GitHub with its full history, scanned, tested and deployed by one scripted command.
Evidence: `app/chat.py`, `app/config.py`, `deploy/update.sh`.

### Third-party and vendor models
**Status: Partly met**
The revised guidance says model risk principles still apply when a bank cannot see inside a vendor's model, and that is the situation here. The response is to control what surrounds it: the model gets no IP addresses or card data, can only use read-only tools, sits behind a small adapter so it can be replaced, and has hard spend caps. What a bank would add is a formal vendor review of Google's own model testing.
Evidence: `app/llm.py`, `app/tools.py`, `app/spend.py`.

## The bottom line
The most useful lesson for a bank is the scope gap: the new guidance deliberately leaves generative AI out, so for now the discipline has to be applied voluntarily, with the NIST AI RMF as the reference. The site does that. Its strongest point is the one examiners care about most, materiality: the AI decides nothing, so a wrong answer has a small blast radius. Its gaps are independent validation and monitoring of answer quality over time.
