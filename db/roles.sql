-- Least-privilege database roles. Run once as the postgres superuser, after schema.sql.
-- No passwords at all: the app runs as the Linux user 'tucker_app' and connects over the local Unix socket,
-- where PostgreSQL's peer authentication checks the OS user (see deploy/ for the pg_ident mapping that lets
-- that same Linux user log in as tucker_store). The database is never reachable over the network.
--
--   tucker_app    the chat (and page reads): SELECT on demo data, append-only ops logs. Cannot change anything.
--   tucker_store  the store's checkout: may only EXECUTE demo.place_order() and append ops logs.
--                 It has no direct access to any demo table, so it can't edit or delete an order either.
--   order_writer  NOLOGIN owner of demo.place_order(): the only role that can INSERT orders.
--                 Nobody can UPDATE or DELETE orders.
-- Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tucker_app')   THEN CREATE ROLE tucker_app LOGIN;   END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tucker_store') THEN CREATE ROLE tucker_store LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'order_writer') THEN CREATE ROLE order_writer NOLOGIN; END IF;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA demo, ops FROM tucker_app, tucker_store, order_writer;

-- Chat: read-only on the fictional company data (including orders), append-only on its own logs.
GRANT USAGE ON SCHEMA demo, ops TO tucker_app;
GRANT SELECT ON ALL TABLES IN SCHEMA demo TO tucker_app;
GRANT SELECT, INSERT ON ops.ai_usage, ops.chat_events, ops.usage_events TO tucker_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ops TO tucker_app;

-- order_writer: just enough to build an order.
GRANT USAGE ON SCHEMA demo TO order_writer;
GRANT SELECT ON demo.customers, demo.cards, demo.products TO order_writer;
GRANT SELECT, INSERT ON demo.orders, demo.order_items TO order_writer;
GRANT USAGE ON SEQUENCE demo.orders_id_seq, demo.order_items_id_seq TO order_writer;
ALTER FUNCTION demo.place_order(TEXT, JSONB) OWNER TO order_writer;

-- Store: one door in (the function), plus its log line. Functions are executable by everyone by default,
-- so that default is removed first.
REVOKE ALL ON FUNCTION demo.place_order(TEXT, JSONB) FROM PUBLIC;
GRANT USAGE ON SCHEMA demo, ops TO tucker_store;
GRANT EXECUTE ON FUNCTION demo.place_order(TEXT, JSONB) TO tucker_store;
GRANT INSERT ON ops.chat_events TO tucker_store;
GRANT USAGE ON SEQUENCE ops.chat_events_id_seq TO tucker_store;
