-- nightly_reset.sql - put Tucker's Treats back to a known state every night at midnight (Eastern).
-- Run by the tucker-reset systemd timer as the postgres superuser:
--   psql -q -d tucker -f /opt/tucker/db/nightly_reset.sql
-- Clears what visitors created today: web orders, event logs and limit counters.
-- KEEPS: the 50 seeded historical orders, the catalog and customers, and ops.ai_usage
--        (the AI spend tally that the monthly $8 cap is counted from).
-- Attack blocks (V2) are NOT reset here: each one expires on its own after a full 24 hours.
BEGIN;
DELETE FROM demo.order_items WHERE order_id IN (SELECT id FROM demo.orders WHERE source = 'web');
DELETE FROM demo.orders WHERE source = 'web';
ALTER SEQUENCE demo.orders_id_seq RESTART WITH 1001;
TRUNCATE ops.chat_events, ops.usage_events;
COMMIT;
