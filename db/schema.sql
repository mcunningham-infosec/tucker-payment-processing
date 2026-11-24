-- Tucker Payment Processing - database schema.
-- Two schemas on purpose:
--   demo : the fictional company's data (customers, cards, products, orders, transactions).
--          The chat can only READ it. The store can only ADD orders, through one function (see roles.sql).
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
    plan          TEXT NOT NULL,             -- e.g. 'Treat Club Gold'
    street        TEXT NOT NULL,             -- dog-themed, fictional (used as the Treats ship-to)
    city          TEXT NOT NULL,
    state         TEXT NOT NULL
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

-- Tucker's Treats catalog. The store page shows exactly this table; checkout prices come only from here.
CREATE TABLE demo.products (
    sku           TEXT PRIMARY KEY,           -- e.g. TT-101
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL,              -- treat / toy / comfort
    price_usd     NUMERIC(8,2) NOT NULL CHECK (price_usd > 0),
    blurb         TEXT NOT NULL,
    image         TEXT NOT NULL,              -- file name under site/assets/products/
    tucker_rating INT NOT NULL CHECK (tucker_rating BETWEEN 1 AND 5),
    sort_order    INT NOT NULL
);

-- Orders from Tucker's Treats. History (ids 1-50) came with the demo data; new web orders are added by
-- demo.place_order() (ids from 1001). Nobody can edit or delete an order: not the store, not the chat.
CREATE TABLE demo.orders (
    id          SERIAL PRIMARY KEY,
    order_ref   TEXT UNIQUE NOT NULL,         -- e.g. TT-3F9A21
    customer_id INT NOT NULL REFERENCES demo.customers(id),
    card_id     INT NOT NULL REFERENCES demo.cards(id),
    paid_by     TEXT NOT NULL,                -- 'customer' (history) or 'tucker' (web orders are on Tucker)
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    subtotal    NUMERIC(10,2) NOT NULL,
    shipping    NUMERIC(10,2) NOT NULL,
    tax         NUMERIC(10,2) NOT NULL,
    total       NUMERIC(10,2) NOT NULL,
    status      TEXT NOT NULL,                -- approved / declined / refunded / disputed / pending
    ship_to     TEXT NOT NULL,
    source      TEXT NOT NULL                 -- 'history' or 'web'
);
ALTER SEQUENCE demo.orders_id_seq RESTART WITH 1001;

CREATE TABLE demo.order_items (
    id          SERIAL PRIMARY KEY,
    order_id    INT NOT NULL REFERENCES demo.orders(id),
    sku         TEXT NOT NULL REFERENCES demo.products(sku),
    qty         INT NOT NULL CHECK (qty BETWEEN 1 AND 5),
    unit_price  NUMERIC(8,2) NOT NULL,
    line_total  NUMERIC(10,2) NOT NULL
);

-- Card transactions, numbered 1-30 (6 per customer) so visitors can ask about "transaction 12". Each one is a
-- Tucker's Treats purchase: amount = that order's total.
CREATE TABLE demo.transactions (
    id           INT PRIMARY KEY,
    customer_id  INT NOT NULL REFERENCES demo.customers(id),
    card_id      INT NOT NULL REFERENCES demo.cards(id),
    order_id     INT NOT NULL REFERENCES demo.orders(id),
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


-- Limit counters (purchases per day, chat messages per IP...). The "subject" is an anonymous code:
-- an HMAC of the visitor's IP or cookie with a secret that changes every day, so the same visitor
-- can't be recognized from one day to the next and no IP address is ever stored here.
-- Wiped every night at midnight by db/nightly_reset.sql.
CREATE TABLE ops.usage_events (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT NOT NULL,                -- 'chat_ip', 'purchase_ip', 'purchase_cookie', ...
    subject     TEXT NOT NULL,                -- anonymous daily code, never a raw IP
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX usage_events_lookup ON ops.usage_events (kind, subject, created_at);

-- The ONLY way to add an order. It re-prices every item from demo.products, computes shipping and NJ tax,
-- checks the shopper is a real demo customer, and charges Tucker's card on file. Runs with the rights of
-- the order_writer role (which owns it), so the store's own login needs no direct table access at all.
-- p_items is JSON like [{"sku":"TT-101","qty":2}]; anything else in it is ignored.
CREATE FUNCTION demo.place_order(p_customer_ref TEXT, p_items JSONB)
RETURNS TABLE (order_ref TEXT, ship_to TEXT, subtotal NUMERIC, shipping NUMERIC, tax NUMERIC, total NUMERIC)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, demo, pg_temp AS $$
DECLARE
    v_customer   demo.customers%ROWTYPE;
    v_card_id    INT;
    v_order_id   INT;
    v_ref        TEXT;
    v_sub        NUMERIC(10,2);
    v_ship       NUMERIC(10,2);
    v_tax        NUMERIC(10,2);
    v_cart       JSONB;
BEGIN
    SELECT * INTO v_customer FROM demo.customers c
     WHERE c.customer_ref = upper(p_customer_ref) AND c.customer_ref <> 'TPP-0001';
    IF NOT FOUND THEN RAISE EXCEPTION 'unknown shopper'; END IF;

    SELECT ca.id INTO v_card_id FROM demo.cards ca JOIN demo.customers cu ON cu.id = ca.customer_id
     WHERE cu.customer_ref = 'TPP-0001' AND ca.status = 'active' ORDER BY ca.id LIMIT 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'tucker card unavailable'; END IF;

    -- Clean cart: known SKUs only, whole quantities, capped at 5 each, duplicates merged. Prices come from here.
    SELECT jsonb_agg(jsonb_build_object('sku', x.sku, 'qty', x.qty, 'price', x.price_usd)), SUM(x.price_usd * x.qty)
      INTO v_cart, v_sub
      FROM (SELECT p.sku, p.price_usd, LEAST(SUM((i->>'qty')::INT), 5) AS qty
              FROM jsonb_array_elements(p_items) i
              JOIN demo.products p ON p.sku = i->>'sku'
             WHERE (i->>'qty') ~ '^[0-9]{1,2}$' AND (i->>'qty')::INT > 0
             GROUP BY p.sku, p.price_usd) x;
    IF v_cart IS NULL THEN RAISE EXCEPTION 'empty cart'; END IF;
    IF (SELECT SUM((c->>'qty')::INT) FROM jsonb_array_elements(v_cart) c) > 25 THEN
        RAISE EXCEPTION 'cart over 25 items';      -- same generous cap the app enforces
    END IF;

    v_ship := CASE WHEN v_sub >= 25 THEN 0 ELSE 4.99 END;
    v_tax  := round(v_sub * 0.06625, 2);
    v_ref  := 'TT-' || upper(substr(md5(random()::TEXT || clock_timestamp()::TEXT), 1, 6));

    INSERT INTO demo.orders (order_ref, customer_id, card_id, paid_by, subtotal, shipping, tax, total, status, ship_to, source)
    VALUES (v_ref, v_customer.id, v_card_id, 'tucker', v_sub, v_ship, v_tax, v_sub + v_ship + v_tax, 'approved',
            v_customer.street || ', ' || v_customer.city || ', ' || v_customer.state || ' ' || v_customer.zip, 'web')
    RETURNING id INTO v_order_id;

    INSERT INTO demo.order_items (order_id, sku, qty, unit_price, line_total)
    SELECT v_order_id, c.sku, c.qty, c.price, c.price * c.qty
      FROM jsonb_to_recordset(v_cart) AS c(sku TEXT, qty INT, price NUMERIC);

    RETURN QUERY SELECT o.order_ref, o.ship_to, o.subtotal, o.shipping, o.tax, o.total
                   FROM demo.orders o WHERE o.id = v_order_id;
END $$;
