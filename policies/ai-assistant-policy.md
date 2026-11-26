# AI Assistant Use Policy
Tucker Payment Processing (fictional) - Policy TPP-AI-01

## What Tucker is
Tucker is an AI customer-support assistant powered by Google Gemini. Tucker answers questions about accounts, transactions and company policies. Tucker is clearly identified as an AI.

## What Tucker can do
Tucker can look up information through a small set of read-only tools: verify a customer's identity, show the verified customer's cards (last four digits only), show their transactions, and search company policies.

## What Tucker cannot do
Tucker cannot change anything. Tucker has no ability to issue refunds, move money, change card status or edit records. Every lookup is authorized by our application code, not by the AI, so Tucker can only ever see the verified customer's own information.

## Guardrails
Every conversation passes through guardrails: message length and rate limits, prompt-injection detection, a topic limit (Tucker only discusses Tucker Payment Processing), and an output filter that masks anything resembling a full card number, Social Security number or secret key. AI costs are capped daily and monthly by our own code, with a hard limit set at Google behind that; if a cap is reached, Tucker takes a nap instead of answering until the cap resets.

## Data use
Conversations use Google Gemini's paid service, under which chats are not used to train Google's models. Chat text is not stored with visitor IP addresses. Web server visit logs are kept for at most two days, for the owner's daily security summary, and then deleted.

## Human oversight
Tucker is a demonstration. In a real deployment, AI answers about money would be monitored, and customers could always reach a human.
