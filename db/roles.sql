-- Least-privilege database role for the web app. Run once as the postgres superuser.
-- No password at all: the app runs as the Linux user 'tucker_app' and connects over the local
-- Unix socket, where PostgreSQL's peer authentication checks the OS user. Nothing to steal or leak,
-- and the database is never reachable over the network.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tucker_app') THEN
    CREATE ROLE tucker_app LOGIN;
  END IF;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA demo FROM tucker_app;
REVOKE ALL ON ALL TABLES IN SCHEMA ops FROM tucker_app;

-- demo: read-only. The app (and therefore the AI's tools) can look, never change.
GRANT USAGE ON SCHEMA demo TO tucker_app;
GRANT SELECT ON ALL TABLES IN SCHEMA demo TO tucker_app;

-- ops: append-only operational records (no UPDATE, no DELETE).
GRANT USAGE ON SCHEMA ops TO tucker_app;
GRANT SELECT, INSERT ON ops.ai_usage, ops.chat_events TO tucker_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ops TO tucker_app;
