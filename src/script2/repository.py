# -*- coding: utf-8 -*-
"""Репозиторий: весь SQL в одном месте."""
import asyncpg

from .config import Settings
from .models import HostRow, CheckResult


SQL_CLAIM = """
WITH picked AS (
    SELECT lh.id
    FROM live_hosts lh
    WHERE lh.check_status IN ('new', 'retry')
      AND (lh.next_attempt_at IS NULL OR lh.next_attempt_at <= now())
      -- Пропускаем если такой host:port уже проверен
      AND NOT EXISTS (
          SELECT 1 FROM checked_hosts ch
          WHERE ch.host = lh.host AND ch.port = lh.port
      )
    ORDER BY lh.id
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE live_hosts AS h
SET check_status = 'in_progress',
    locked_by = $2,
    locked_until = now() + make_interval(secs => $3),
    attempts = h.attempts + 1
FROM picked
WHERE h.id = picked.id
RETURNING h.id, h.attempts, h.host, h.port, h.scheme,
          h.status, h.content_type, h.content_length, h.server, h.check_id, h.created_at
"""

SQL_MARK_DONE = """
UPDATE live_hosts
SET check_status = 'done',
    checked_at = now(),
    locked_by = NULL,
    locked_until = NULL,
    last_error = NULL
WHERE id = $1 AND locked_by = $2 AND check_status = 'in_progress'
RETURNING attempts
"""

SQL_INSERT_RESULT = """
INSERT INTO checked_hosts (
    source_id, attempt, host, port, scheme, status, content_type, content_length, server, check_id, created_at,
    is_alive, latency_ms, has_openapi, spec_path, spec_title,
    total_endpoints, vulnerable_count, protected_count, public_count,
    data_patterns, severity, result, worker_id, panel_status
)
SELECT
    h.id, $2, h.host, h.port, h.scheme, h.status, h.content_type, h.content_length, h.server, h.check_id, h.created_at,
    $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    (SELECT prev.panel_status FROM checked_hosts prev
     WHERE prev.source_id = h.id ORDER BY prev.attempt DESC LIMIT 1)
FROM live_hosts AS h
WHERE h.id = $1
ON CONFLICT (source_id, attempt) DO NOTHING
"""

SQL_MARK_RETRY = """
UPDATE live_hosts
SET check_status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'retry' END,
    next_attempt_at = now() + make_interval(secs => $4 * power(2, attempts - 1)),
    last_error = left($5, 2000),
    locked_by = NULL,
    locked_until = NULL
WHERE id = $1 AND locked_by = $2 AND check_status = 'in_progress'
"""

SQL_REAP_EXPIRED = """
UPDATE live_hosts
SET check_status = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'retry' END,
    -- бэкофф: экспонента от числа попыток, кап 60 минут
    next_attempt_at = now() + make_interval(
        secs => LEAST(power(2, GREATEST(attempts - 1, 0)) * $2, 3600)),
    last_error = 'lease expired, locked_by=' || locked_by,
    locked_by = NULL,
    locked_until = NULL
WHERE check_status = 'in_progress' AND locked_until < now()
RETURNING id
"""

SQL_RELEASE_MINE = """
UPDATE live_hosts
SET check_status = 'retry',
    attempts = greatest(attempts - 1, 0),
    locked_by = NULL,
    locked_until = NULL
WHERE locked_by = $1 AND check_status = 'in_progress'
RETURNING id
"""

SQL_MARK_DUPLICATES_DONE = """
UPDATE live_hosts lh
SET check_status = 'done',
    checked_at = now()
WHERE lh.check_status IN ('new', 'retry')
  AND EXISTS (
      SELECT 1 FROM checked_hosts ch
      WHERE ch.host = lh.host AND ch.port = lh.port
  )
RETURNING id
"""

SQL_MARK_IGNORED = """
UPDATE live_hosts
SET check_status = 'done',
    checked_at = now(),
    locked_by = NULL,
    locked_until = NULL,
    last_error = left('ignored body: ' || $3, 2000)
WHERE id = $1 AND locked_by = $2 AND check_status = 'in_progress'
RETURNING id
"""


class Repository:
    """Работа с БД: claim, save, retry, reap."""

    def __init__(self, pool: asyncpg.Pool, cfg: Settings) -> None:
        self.pool = pool
        self.cfg = cfg
        self.worker_id = cfg.worker_id

    async def claim(self, limit: int) -> list[HostRow]:
        """Забирает записи для проверки (CLAIM)."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                SQL_CLAIM,
                limit,
                self.worker_id,
                self.cfg.lease_seconds,
            )
            return [
                HostRow(
                    id=r["id"],
                    host=r["host"],
                    port=r["port"],
                    scheme=r["scheme"],
                    attempts=r["attempts"],
                    status=r.get("status"),
                    content_type=r.get("content_type"),
                    content_length=r.get("content_length"),
                    server=r.get("server"),
                    check_id=r.get("check_id"),
                    created_at=r.get("created_at"),
                )
                for r in rows
            ]

    async def save_result(self, row_id: int, attempt: int, res: CheckResult) -> bool:
        """Сохраняет результат проверки (SAVE)."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                returned_attempt = await conn.fetchval(
                    SQL_MARK_DONE, row_id, self.worker_id
                )
                if returned_attempt is None:
                    return False

                await conn.execute(
                    SQL_INSERT_RESULT,
                    row_id,
                    attempt,
                    res.is_alive,
                    res.latency_ms,
                    res.has_openapi,
                    res.spec_path,
                    res.spec_title,
                    res.total_endpoints,
                    res.vulnerable_count,
                    res.protected_count,
                    res.public_count,
                    res.data_patterns,
                    res.severity,
                    res.data,
                    self.worker_id,
                )
                return True

    async def mark_retry(self, row_id: int, error: str) -> None:
        """Помечает запись для повторной попытки (RETRY)."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                SQL_MARK_RETRY,
                row_id,
                self.worker_id,
                self.cfg.max_attempts,
                self.cfg.retry_base_seconds,
                error,
            )

    async def reap_expired(self) -> list[int]:
        """Освобождает записи с истёкшей арендой (REAPER).

        После экспирации - экспоненциальный бэкофф от числа попыток
        (2^n * retry_base_seconds, кап 60 минут) - иначе хост сразу
        перезахватывался и долбился снова без паузы.
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                SQL_REAP_EXPIRED,
                self.cfg.max_attempts,
                self.cfg.retry_base_seconds,
            )
            return [r["id"] for r in rows]

    async def release_mine(self) -> list[int]:
        """Освобождает свои записи при остановке."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(SQL_RELEASE_MINE, self.worker_id)
            return [r["id"] for r in rows]

    async def mark_duplicates_done(self) -> list[int]:
        """Помечает дубликаты как done (уже есть в checked_hosts)."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(SQL_MARK_DUPLICATES_DONE)
            return [r["id"] for r in rows]

    async def mark_ignored(self, row_id: int, marker: str) -> bool:
        """Помечает хост как ignored (декой по маркеру в теле).

        Снимает лизу, ставит done + last_error. В checked_hosts НЕ пишем.
        Возвращает True если запись обновлена, False при потере лизы.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchval(
                SQL_MARK_IGNORED,
                row_id,
                self.worker_id,
                marker or "unknown",
            )
            return row is not None
