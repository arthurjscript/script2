#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Одноразовая очистка checked_hosts от декоев по маркерам в теле.

Запуск: python scripts/cleanup_ignored.py [--dry-run] [--requeue]

Читает маркеры из IGNORE_BODY_MARKERS/IGNORE_BODY_FILE (те же переменные, что воркер).
Удаляет строки из checked_hosts, где result содержит маркер.
С --requeue: возвращает удалённые host:port в очередь (check_status='new').
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

import asyncpg


def load_markers() -> list[str]:
    """Загружает маркеры из env-переменных (как воркер)."""
    markers: list[str] = []
    seen: set[str] = set()

    # inline
    inline = os.getenv("IGNORE_BODY_MARKERS", "")
    for m in inline.split(","):
        m = m.strip()
        if m and m not in seen:
            seen.add(m)
            markers.append(m)

    # файл
    fpath = os.getenv("IGNORE_BODY_FILE", "")
    if fpath:
        path = Path(fpath)
        if path.exists():
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in seen:
                        seen.add(line)
                        markers.append(line)

    return markers


def escape_like(s: str) -> str:
    """Экранирует спецсимволы LIKE."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Удаляет декои из checked_hosts по маркерам в теле")
    parser.add_argument("--dry-run", action="store_true", help="Только показать, не удалять")
    parser.add_argument("--requeue", action="store_true", help="Вернуть удалённые host:port в очередь")
    args = parser.parse_args()

    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL not set", file=sys.stderr)
        sys.exit(1)

    markers = load_markers()
    if not markers:
        print("No markers loaded (IGNORE_BODY_MARKERS/IGNORE_BODY_FILE empty)")
        sys.exit(0)

    print(f"Loaded {len(markers)} markers")

    conn = await asyncpg.connect(db_url)
    try:
        total_deleted = 0
        total_requeued = 0

        for marker in markers:
            pattern = "%" + escape_like(marker) + "%"

            if args.dry_run:
                # Показать совпадения
                rows = await conn.fetch(
                    """
                    SELECT id, host, port
                    FROM checked_hosts
                    WHERE left(result::text, 100000) LIKE $1 ESCAPE '\\'
                    """,
                    pattern,
                )
                if rows:
                    print(f"  [{marker}]: {len(rows)} matches")
                    for r in rows[:5]:
                        print(f"    id={r['id']} host={r['host']}:{r['port']}")
                    if len(rows) > 5:
                        print(f"    ... and {len(rows) - 5} more")
                    total_deleted += len(rows)
            else:
                # Удалить
                if args.requeue:
                    # Сначала получим host:port для requeue
                    rows = await conn.fetch(
                        """
                        SELECT DISTINCT host, port
                        FROM checked_hosts
                        WHERE left(result::text, 100000) LIKE $1 ESCAPE '\\'
                        """,
                        pattern,
                    )
                    # Удалить
                    deleted = await conn.execute(
                        """
                        DELETE FROM checked_hosts
                        WHERE left(result::text, 100000) LIKE $1 ESCAPE '\\'
                        """,
                        pattern,
                    )
                    count = int(deleted.split()[-1]) if deleted else 0
                    if count:
                        print(f"  [{marker}]: deleted {count}")
                        total_deleted += count
                    # Requeue
                    for r in rows:
                        result = await conn.execute(
                            """
                            UPDATE live_hosts
                            SET check_status = 'new',
                                attempts = 0,
                                locked_by = NULL,
                                locked_until = NULL,
                                last_error = NULL
                            WHERE host = $1 AND port = $2 AND check_status = 'done'
                            """,
                            r["host"],
                            r["port"],
                        )
                        if "UPDATE 1" in result:
                            total_requeued += 1
                else:
                    deleted = await conn.execute(
                        """
                        DELETE FROM checked_hosts
                        WHERE left(result::text, 100000) LIKE $1 ESCAPE '\\'
                        """,
                        pattern,
                    )
                    count = int(deleted.split()[-1]) if deleted else 0
                    if count:
                        print(f"  [{marker}]: deleted {count}")
                        total_deleted += count

        if args.dry_run:
            print(f"\nDry-run: would delete {total_deleted} rows")
        else:
            print(f"\nDeleted {total_deleted} rows")
            if args.requeue:
                print(f"Requeued {total_requeued} hosts")

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
