# -*- coding: utf-8 -*-
"""Модели данных."""
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any


@dataclass
class HostRow:
    """Запись из live_hosts для проверки."""

    id: int
    host: IPv4Address | IPv6Address
    port: int
    scheme: int  # 0=http, 1=https
    attempts: int = 1

    # Дополнительные поля из live_hosts
    status: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    check_id: int | None = None
    created_at: datetime | None = None

    @property
    def protocol(self) -> str:
        """Возвращает протокол по scheme."""
        return "https" if self.scheme == 1 else "http"

    @property
    def base_url(self) -> str:
        """Возвращает базовый URL."""
        return f"{self.protocol}://{self.host}:{self.port}"


@dataclass
class CheckResult:
    """Результат проверки хоста."""

    is_alive: bool
    latency_ms: int | None = None
    data: dict[str, Any] = field(default_factory=dict)

    # OpenAPI-специфичные поля
    has_openapi: bool = False
    spec_path: str | None = None
    spec_title: str | None = None
    total_endpoints: int = 0
    vulnerable_count: int = 0
    protected_count: int = 0
    public_count: int = 0

    # Найденные паттерны
    data_patterns: list[str] = field(default_factory=list)
    severity: str = "LOW"

    # Ответы эндпоинтов (для анализа)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
