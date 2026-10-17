# -*- coding: utf-8 -*-
"""Конфигурация из переменных окружения."""
import os
import socket
from pydantic_settings import BaseSettings


def default_worker_id() -> str:
    """hostname-pid для уникальной идентификации воркера."""
    return f"{socket.gethostname()}-{os.getpid()}"


class Settings(BaseSettings):
    """Настройки SCRIPT2."""

    # База данных
    database_url: str
    db_pool_size: int = 10

    # Воркер
    worker_id: str = ""
    concurrency: int = 100
    batch_size: int = 50

    # Таймауты
    check_timeout: int = 2
    host_timeout: int = 90  # бюджет на сканирование всего хоста (все запросы)
    lease_seconds: int = 300
    shutdown_timeout: int = 30

    # Retry
    max_attempts: int = 3
    retry_base_seconds: int = 30

    # Polling
    poll_interval: int = 5
    reaper_interval: int = 60
    use_notify: bool = False

    # AI key verification (валидность/баланс у провайдеров)
    ai_key_checks: bool = True
    ai_key_max: int = 5

    # Proxy
    proxy_file: str = ""
    proxy_url: str = ""

    # Health
    heartbeat_file: str = "/tmp/heartbeat"
    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.worker_id:
            self.worker_id = default_worker_id()
