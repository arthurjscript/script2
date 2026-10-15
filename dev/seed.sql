-- seed.sql
-- Схема live_hosts (создаётся SCRIPT1, здесь для dev/тестов)

CREATE TABLE IF NOT EXISTS live_hosts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host inet NOT NULL,
    port smallint NOT NULL,
    scheme smallint NOT NULL DEFAULT 0,  -- 0=http, 1=https
    status text,
    content_type text,
    content_length bigint,
    server text,
    check_id bigint,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Индекс для поиска по host:port
CREATE INDEX IF NOT EXISTS live_hosts_host_port_idx ON live_hosts (host, port);

-- Тестовые данные
INSERT INTO live_hosts (host, port, scheme, status, server) VALUES
    ('93.184.216.34', 80, 0, '200', 'nginx'),
    ('151.101.1.69', 443, 1, '200', 'cloudflare'),
    ('142.250.185.206', 80, 0, '200', 'gws'),
    ('157.240.1.35', 443, 1, '200', 'proxygen')
ON CONFLICT DO NOTHING;
