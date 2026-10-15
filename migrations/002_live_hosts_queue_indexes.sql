-- 002_live_hosts_queue_indexes.sql
-- Индексы для очереди (CONCURRENTLY — вне транзакции)

CREATE INDEX CONCURRENTLY IF NOT EXISTS live_hosts_queue_idx
    ON live_hosts (id) WHERE check_status IN ('new', 'retry');

CREATE INDEX CONCURRENTLY IF NOT EXISTS live_hosts_lease_idx
    ON live_hosts (locked_until) WHERE check_status = 'in_progress';
