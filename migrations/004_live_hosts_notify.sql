-- 004_live_hosts_notify.sql
-- Опционально: триггер для мгновенного уведомления SCRIPT2

CREATE OR REPLACE FUNCTION live_hosts_notify_new() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('live_hosts_new', '');
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS live_hosts_notify_new ON live_hosts;

CREATE TRIGGER live_hosts_notify_new
    AFTER INSERT ON live_hosts
    FOR EACH STATEMENT EXECUTE FUNCTION live_hosts_notify_new();
