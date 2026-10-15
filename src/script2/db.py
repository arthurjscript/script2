# -*- coding: utf-8 -*-
"""Подключение к PostgreSQL через asyncpg."""
import json
import asyncpg

from .config import Settings


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Инициализация соединения: jsonb кодек."""
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )


async def create_pool(cfg: Settings) -> asyncpg.Pool:
    """Создаёт пул соединений с PostgreSQL."""
    pool = await asyncpg.create_pool(
        dsn=cfg.database_url,
        min_size=1,
        max_size=cfg.db_pool_size,
        command_timeout=30,
        max_inactive_connection_lifetime=300,
        init=_init_connection,
        server_settings={"application_name": f"script2:{cfg.worker_id}"},
    )
    if pool is None:
        raise RuntimeError("Failed to create database pool")
    return pool
