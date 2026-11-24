-- Tucker Payment Processing - database schema.
-- Two schemas on purpose:
--   demo : the fictional company's data (customers, cards, transactions). The web app can only READ it.
--   ops  : the app's own operational records (AI spend, guardrail events, visit counts). The web app can
--          INSERT here, but these tables never contain customer data and are never shown to the AI.
-- No full card numbers exist anywhere: cards are stored as brand + last 4 digits + a random token.

DROP SCHEMA IF EXISTS demo CASCADE;
DROP SCHEMA IF EXISTS ops CASCADE;
CREATE SCHEMA demo;
CREATE SCHEMA ops;

-- Fictional customers. customer_ref + zip are the demo "identity check" values shown on the site.
CREATE TABLE demo.customers (
    id            SERIAL PRIMARY KEY,
    customer_ref  TEXT UNIQUE NOT NULL,      -- e.g. TPP-1001
    full_name     TEXT NOT NULL,
    zip           TEXT NOT NULL,             -- used only for the demo identity check
    email         TEXT NOT NULL,             -- always @example.com
    member_since  DATE NOT NULL,
    plan          TEXT NOT NULL              -- e.g. 'Treat Club Gold'
);

-- Payment cards on file: never a full number, only what a support agent may see.
CREATE TABLE demo.cards (
    id           SERIAL PRIMARY KEY,
    customer_id  INT NOT NULL REFERENCES demo.customers(id),
    brand        TEXT NOT NULL,
    last4        CHAR(4) NOT NULL,
    exp_month    INT NOT NULL,
    exp_year     INT NOT NULL,
    status       TEXT NOT NULL,              -- active / frozen / expired
    vault_token  TEXT NOT NULL               -- random token standing in for a vaulted card
);

-- Transactions, numbered 1-50 so visitors can ask about "transaction 12".
CREATE TABLE demo.transactions (
    id           INT PRIMARY KEY,
    customer_id  INT NOT NULL REFERENCES demo.customers(id),
    card_id      INT NOT NULL REFERENCES demo.cards(id),
    created_at   TIMESTAMP NOT NULL,
    merchant     TEXT NOT NULL,
    amount_usd   NUMERIC(10,2) NOT NULL,
    status       TEXT NOT NULL,              -- approved / declined / refunded / disputed / pending
    decline_reason TEXT                      -- only for declined transactions
);

-- Monthly AI spend, one row per model call (used for the app-level spend cap).
CREATE TABLE ops.ai_usage (
    id            BIGSERIAL PRIMARY KEY,
    called_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    model         TEXT NOT NULL,
    input_tokens  INT NOT NULL,
    output_tokens INT NOT NULL,
    cost_usd      NUMERIC(12,6) NOT NULL
);

-- Guardrail and chat events (no chat text, no IP): feeds the daily report.
CREATE TABLE ops.chat_events (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    session_id  TEXT NOT NULL,               -- random per-browser-session id
    event_type  TEXT NOT NULL,               -- e.g. message, injection_blocked, masked_output, nap
    detail      TEXT
);
