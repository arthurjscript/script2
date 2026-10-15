-- 003_checked_hosts.sql
-- Таблица результатов проверки

CREATE TABLE IF NOT EXISTS checked_hosts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id bigint NOT NULL REFERENCES live_hosts (id),
    attempt integer NOT NULL,

    -- Копия бизнес-колонок live_hosts (те же типы)
    host inet NOT NULL,
    port smallint NOT NULL,
    scheme smallint NOT NULL,
    status text,
    content_type text,
    content_length bigint,
    server text,
    check_id bigint,
    created_at timestamptz,

    -- Результаты проверки SCRIPT2
    is_alive boolean NOT NULL,
    latency_ms integer,
    has_openapi boolean NOT NULL DEFAULT false,
    spec_path text,
    spec_title text,
    total_endpoints integer NOT NULL DEFAULT 0,
    vulnerable_count integer NOT NULL DEFAULT 0,
    protected_count integer NOT NULL DEFAULT 0,
    public_count integer NOT NULL DEFAULT 0,
    data_patterns text[] NOT NULL DEFAULT '{}',
    severity text NOT NULL DEFAULT 'LOW',
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    checked_at timestamptz NOT NULL DEFAULT now(),
    worker_id text NOT NULL,

    -- Уникальность: одна попытка на source_id
    CONSTRAINT checked_hosts_source_attempt_uq UNIQUE (source_id, attempt)
);

-- BRIN индекс для time-series запросов
CREATE INDEX IF NOT EXISTS checked_hosts_checked_at_brin
    ON checked_hosts USING brin (checked_at);

-- Индекс для поиска уязвимых
CREATE INDEX IF NOT EXISTS checked_hosts_vulnerable_idx
    ON checked_hosts (vulnerable_count) WHERE vulnerable_count > 0;

-- Индекс для поиска по severity
CREATE INDEX IF NOT EXISTS checked_hosts_severity_idx
    ON checked_hosts (severity) WHERE severity IN ('HIGH', 'CRITICAL');
