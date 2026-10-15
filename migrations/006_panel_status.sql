-- 006_panel_status.sql
-- Колонка для статуса в админ-панели

ALTER TABLE checked_hosts
    ADD COLUMN IF NOT EXISTS panel_status text;

CREATE INDEX CONCURRENTLY IF NOT EXISTS checked_hosts_panel_status_idx
    ON checked_hosts (panel_status) WHERE panel_status IS NOT NULL;
