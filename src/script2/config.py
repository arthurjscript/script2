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

    # Telegram bot verification (getMe + платёжные команды)
    telegram_bot_checks: bool = True
    telegram_bot_max: int = 5

    # AWS key verification (STS GetAccessKeyInfo, без подписи)
    aws_key_checks: bool = True
    aws_key_max: int = 3

    # DSN reachability/auth check (TCP + postgres login)
    dsn_checks: bool = True
    dsn_max: int = 3

    # Service secret verification (stripe/slack/discord/github/..., read-only)
    secret_checks: bool = True
    secret_max: int = 10
    # Discord: max tokens per host, чтобы не ловить rate-limit от API
    discord_verify_max: int = 5

    # Twilio AccountSid+AuthToken pair (HTTP Basic, read-only)
    twilio_checks: bool = True
    twilio_max: int = 3

    # Twitter/X app bearer (context extraction, read-only)
    twitter_checks: bool = True
    twitter_max: int = 2

    # Twitter/X сессии аккаунтов (cookies auth_token+ct0 из чекер-панелей)
    twitter_session_max: int = 3

    # Exchange API keypairs: binance/bybit/okx/kucoin (HMAC, баланс+вывод)
    exchange_checks: bool = True
    exchange_max: int = 3

    # Крипто-платёжки с выплатами: heleket/cryptomus/nowpayments/plisio
    cryptopay_checks: bool = True
    cryptopay_max: int = 3

    # WordPress finder: wp_user/wp_password из тел + активный пробер /api/sites,
    # верификация read-only GET /wp-json/wp/v2/users/me (Basic, app passwords)
    wp_checks: bool = True
    wp_verify_max: int = 10

    # id-fuzz: id'шники из тел подставляются в GET-шаблоны с {param}
    # (второй проход по тем же детекторам/экстракторам). Лимит на
    # идентичный GET-эндпоинт поднят: 50 id на шаблон, 10 шаблонов,
    # до 5 раундов каскада (новые id из ответов -> следующий раунд)
    id_fuzz: bool = True
    id_fuzz_max: int = 50
    id_fuzz_templates_max: int = 10
    id_fuzz_rounds: int = 5

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
