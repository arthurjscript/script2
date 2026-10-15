-- 001_live_hosts_queue_columns.sql
-- Добавляет колонки очереди в live_hosts

ALTER TABLE live_hosts
    ADD COLUMN IF NOT EXISTS check_status text NOT NULL DEFAULT 'new',
    ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_by text,
    ADD COLUMN IF NOT EXISTS locked_until timestamptz,
    ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz,
    ADD COLUMN IF NOT EXISTS checked_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_error text;

-- CHECK constraint: добавляем NOT VALID чтобы не блокировать таблицу
DO $$ BEGIN
    ALTER TABLE live_hosts ADD CONSTRAINT live_hosts_check_status_chk
        CHECK (check_status IN ('new', 'in_progress', 'retry', 'done', 'failed')) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Валидируем constraint отдельно
ALTER TABLE live_hosts VALIDATE CONSTRAINT live_hosts_check_status_chk;
