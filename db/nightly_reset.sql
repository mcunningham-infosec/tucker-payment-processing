-- nightly_reset.sql - put Tucker's Treats back to a known state every night at midnight (Eastern).
-- Run by the tucker-reset systemd timer as the postgres superuser:
--   psql -q -d tucker -f /opt/tucker/db/nightly_reset.sql
-- Clears what visitors created today: web orders, event logs and limit counters.
-- KEEPS: the 30 seeded historical orders (6 per customer), the catalog and customers, and ops.ai_usage
--        (the AI spend tally that the monthly cap is counted from).
-- Attack blocks (V2) are NOT reset here: each one expires on its own after a full 24 hours.
-- Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
BEGIN;
DELETE FROM demo.order_items WHERE order_id IN (SELECT id FROM demo.orders WHERE source = 'web');
DELETE FROM demo.orders WHERE source = 'web';
ALTER SEQUENCE demo.orders_id_seq RESTART WITH 1001;
TRUNCATE ops.chat_events;
-- Limit counters reset nightly, EXCEPT Cipher attack blocks: each one lasts a full 24 hours on its own.
DELETE FROM ops.usage_events WHERE kind NOT LIKE 'cipher_%' OR created_at < now() - interval '2 days';
-- Slide the seeded history forward so its newest purchase is always yesterday: every customer has
-- recent activity on any day a visitor shows up. Orders and their transactions move together.
WITH shift AS (SELECT (current_date - 1) - max(created_at)::date AS days FROM demo.orders WHERE source = 'history')
UPDATE demo.orders o SET created_at = o.created_at + make_interval(days => shift.days)
  FROM shift WHERE o.source = 'history' AND shift.days <> 0;
UPDATE demo.transactions t SET created_at = o.created_at FROM demo.orders o WHERE o.id = t.order_id AND t.created_at <> o.created_at;
COMMIT;
