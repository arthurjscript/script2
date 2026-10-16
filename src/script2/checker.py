# -*- coding: utf-8 -*-
"""Проверка хоста: OpenAPI discovery + auth check."""
import asyncio
import json
import re
import ssl
import time
from typing import Any
from concurrent.futures import ThreadPoolExecutor

import aiohttp

from .config import Settings
from .models import HostRow, CheckResult


# Пути для поиска OpenAPI
OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/api-docs",
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
    "/rest/openapi.json",
    "/service/openapi.json",
]

# Паттерны чувствительных данных (из prototype/auth_checker/crypto_detect.py)
SENSITIVE_PATTERNS = {
    # CRITICAL - прямые деньги
    "password": re.compile(r'"(?:password|passwd|email_password|user_password|admin_password)"\s*:\s*"([^"]{3,})"', re.I),
    "private_key_pem": re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "evm_private_key": re.compile(r'"(?:private_key|privateKey|privKey|priv_key)"\s*:\s*"(?:0x)?[0-9a-fA-F]{64}"'),
    "bitcoin_wif": re.compile(r'"(?:private_key|wif|priv)"\s*:\s*"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}"'),
    "extended_key": re.compile(r'\b(xprv|yprv|zprv|tprv)[1-9A-HJ-NP-Za-km-z]{50,}\b'),
    "solana_key": re.compile(r'"(?:private_key|secret_key|solana_key)"\s*:\s*"[1-9A-HJ-NP-Za-km-z]{87,88}"'),
    # seed_phrase: 12+ слов через пробел (BIP-39)
    "seed_phrase": re.compile(r'"(?:seed|seed_phrase|seedphrase|mnemonic|backup_phrase|recovery_phrase)"\s*:\s*"([a-z]+(?:\s+[a-z]+){11,})"', re.I),
    # secret_key: hex формат 32+ символов
    "secret_key": re.compile(r'"(?:secret_key|master_key|secretKey)"\s*:\s*"[0-9a-fA-F]{32,}"'),
    # otp_secret: base32 формат (A-Z, 2-7)
    "otp_secret": re.compile(r'"(?:otp_secret|totp_secret)"\s*:\s*"[A-Z2-7]{16,}"'),
    "stripe_live": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "stripe_restricted": re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),

    # HIGH - доступ к системам
    "facebook_access_token": re.compile(r'"(?:access_token|page_access_token)"\s*:\s*"(EAA[A-Za-z0-9]{50,})"'),
    "github_token": re.compile(r'gh[ps]_[A-Za-z0-9]{36,}'),
    "gitlab_token": re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
    "telegram_bot": re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    "discord_token": re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
    "discord_webhook": re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
    "sendgrid_key": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    "twilio_key": re.compile(r'SK[0-9a-fA-F]{32}'),
    "exchange_secret": re.compile(r'"(?:api_secret|apiSecret|secret_key|secretKey)"\s*:\s*"[A-Za-z0-9]{64}"'),
    # HIGH - auth tokens
    "refresh_token": re.compile(r'"refresh_token"\s*:\s*"[^"]{16,}"', re.I),
    "auth_token": re.compile(r'"auth_token"\s*:\s*"[^"]{16,}"', re.I),
    "bearer_token": re.compile(r'"bearer"\s*:\s*"[^"]{16,}"', re.I),
    "jwt_token": re.compile(r'"jwt"\s*:\s*"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"'),
    # HIGH - AWS
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(r'"(?:aws_secret|secret_access_key|aws_secret_access_key)"\s*:\s*"[A-Za-z0-9/+=]{40}"'),
    # HIGH - Exchange
    "binance_key": re.compile(r'"(?:api_key|apiKey)"\s*:\s*"[A-Za-z0-9]{64}"'),
    # HIGH - SMTP/DB credentials
    "smtp_password": re.compile(r'"(?:smtp_pass|smtp_password)"\s*:\s*"[^"]{4,}"', re.I),
    "database_url": re.compile(r'"(?:database_url|db_url|dsn|connection_string)"\s*:\s*"[^"]+"', re.I),
    "credential": re.compile(r'"(?:credential|credentials)"\s*:\s*"[^"]{8,}"', re.I),
    # HIGH - generic access_token (not Facebook-specific)
    "access_token": re.compile(r'"access_token"\s*:\s*"[^"]{20,}"', re.I),
    # HIGH - API keys with strict patterns
    "google_api_key": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "openai_key": re.compile(r'sk-[A-Za-z0-9]{48,}'),
    "mailgun_key": re.compile(r'key-[0-9a-f]{32}'),
    "npm_token": re.compile(r'npm_[A-Za-z0-9]{36}'),
    "pypi_token": re.compile(r'pypi-[A-Za-z0-9_-]{80,}'),
    "shopify_key": re.compile(r'shpat_[a-fA-F0-9]{32}'),
    "dropbox_token": re.compile(r'sl\.[A-Za-z0-9_-]{130,}'),

    # MEDIUM - DSN с credentials (требуют user:pass@)
    "postgres_dsn": re.compile(r'postgres(?:ql)?://[^\s"]+:[^\s"]+@[^\s"]+'),
    "mysql_dsn": re.compile(r'mysql://[^\s"]+:[^\s"]+@[^\s"]+'),
    "mongodb_dsn": re.compile(r'mongodb(?:\+srv)?://[^\s"]+:[^\s"]+@[^\s"]+'),
    "redis_dsn": re.compile(r'redis://[^\s"]+:[^\s"]+@[^\s"]+'),
    "amqp_dsn": re.compile(r'amqp://[^\s"]+:[^\s"]+@[^\s"]+'),
    "smtp_dsn": re.compile(r'smtp://[^\s"]+:[^\s"]+@[^\s"]+'),

    # MEDIUM - PII and session tokens
    "email": re.compile(r'"(?:email|e-mail)"\s*:\s*"[^"@]+@[^"]+"', re.I),
    "session_id": re.compile(r'"session_id"\s*:\s*"[^"]{8,}"', re.I),
    "session_token": re.compile(r'"session_token"\s*:\s*"[^"]{8,}"', re.I),

    # TEST - проверить и удалить ненужные
    "admin_password": re.compile(r'"admin_password"\s*:\s*"[^"]{3,}"', re.I),
    "balance": re.compile(r'"balance"\s*:\s*"?[\d.]+', re.I),
    "wp_auth_key": re.compile(r'"(?:auth_key|secure_auth_key|logged_in_key|nonce_key)"\s*:\s*"[^"]{16,}"', re.I),
    "wp_salt": re.compile(r'"(?:auth_salt|secure_auth_salt|logged_in_salt|nonce_salt)"\s*:\s*"[^"]{16,}"', re.I),
    "db_password": re.compile(r'"(?:db_password|DB_PASSWORD)"\s*:\s*"[^"]{3,}"'),
    "checker": re.compile(r'"checker"\s*:\s*"[^"]+"', re.I),
}

# Маскированные значения (игнорируем)
MASKED_VALUES = {"*", "**", "***", "****", "*****", "******", "********"}

# Placeholder хосты в DSN (примеры из документации)
PLACEHOLDER_HOSTS = {
    "host", "hostname", "localhost", "127.0.0.1",
    "example.com", "example.org", "your-host", "your-server",
    "db-host", "database-host", "server", "dbserver",
}

# AWS example keys (из документации)
AWS_EXAMPLE_KEYS = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "AKIAEXAMPLEKEY",
}

# Placeholder значения (когда значение = название поля)
PLACEHOLDER_VALUES = {
    "password", "passwd", "secret", "token", "key", "api_key", "apikey",
    "email", "username", "user", "login", "string", "your_password",
    "your_token", "your_key", "your_secret", "enter_password", "test",
    "example", "sample", "demo", "placeholder", "changeme", "change_me",
}


def is_placeholder_value(field: str, value: str) -> bool:
    """Проверяет что значение - placeholder (совпадает с именем поля или типичный пример)."""
    val_lower = value.lower().strip()
    field_lower = field.lower().replace("_", "").replace("-", "")
    # Значение совпадает с полем: "password": "Password"
    if val_lower == field_lower or val_lower.replace("_", "") == field_lower:
        return True
    # Типичные placeholder значения
    if val_lower in PLACEHOLDER_VALUES:
        return True
    return False


def is_aws_example_key(key: str) -> bool:
    """Проверяет что AWS ключ - пример из документации."""
    return key in AWS_EXAMPLE_KEYS or "EXAMPLE" in key.upper()


def is_placeholder_dsn(dsn: str) -> bool:
    """Проверяет что DSN - placeholder/пример."""
    lower = dsn.lower()
    # user:pass@host - явный пример
    if "user:pass@" in lower or "username:password@" in lower:
        return True
    # Проверяем хост после @
    if "@" in lower:
        host_part = lower.split("@")[1].split("/")[0].split(":")[0]
        if host_part in PLACEHOLDER_HOSTS:
            return True
    return False


def is_masked_value(value: str) -> bool:
    """Проверяет что значение маскировано."""
    return value in MASKED_VALUES or set(value) == {"*"}


# Severity по паттернам (из prototype/auth_checker/crypto_detect.py)
SEVERITY_MAP = {
    # CRITICAL - прямые деньги
    "password": "CRITICAL",
    "private_key_pem": "CRITICAL",
    "evm_private_key": "CRITICAL",
    "bitcoin_wif": "CRITICAL",
    "extended_key": "CRITICAL",
    "solana_key": "CRITICAL",
    "seed_phrase": "CRITICAL",
    "secret_key": "CRITICAL",
    "otp_secret": "CRITICAL",
    "stripe_live": "CRITICAL",
    "stripe_restricted": "CRITICAL",
    # HIGH - доступ к системам
    "facebook_access_token": "HIGH",
    "github_token": "HIGH",
    "gitlab_token": "HIGH",
    "telegram_bot": "HIGH",
    "slack_token": "HIGH",
    "discord_token": "HIGH",
    "discord_webhook": "MEDIUM",
    "sendgrid_key": "HIGH",
    "twilio_key": "HIGH",
    "exchange_secret": "HIGH",
    "refresh_token": "HIGH",
    "auth_token": "HIGH",
    "bearer_token": "HIGH",
    "jwt_token": "HIGH",
    "aws_access_key": "HIGH",
    "aws_secret_key": "HIGH",
    "binance_key": "HIGH",
    "smtp_password": "HIGH",
    "database_url": "HIGH",
    "credential": "HIGH",
    "access_token": "HIGH",
    "google_api_key": "HIGH",
    "openai_key": "HIGH",
    "mailgun_key": "HIGH",
    "npm_token": "HIGH",
    "pypi_token": "HIGH",
    "shopify_key": "HIGH",
    "dropbox_token": "HIGH",
    # MEDIUM - DSN
    "postgres_dsn": "MEDIUM",
    "mysql_dsn": "MEDIUM",
    "mongodb_dsn": "MEDIUM",
    "redis_dsn": "MEDIUM",
    "amqp_dsn": "MEDIUM",
    "smtp_dsn": "MEDIUM",
    # MEDIUM - PII and sessions
    "email": "MEDIUM",
    "session_id": "MEDIUM",
    "session_token": "MEDIUM",
    # TEST patterns
    "admin_password": "CRITICAL",
    "balance": "MEDIUM",
    "wp_auth_key": "HIGH",
    "wp_salt": "HIGH",
    "db_password": "CRITICAL",
    "checker": "MEDIUM",
}


def is_openapi_spec(text: str) -> bool:
    """Проверяет что текст похож на OpenAPI спецификацию."""
    t = text[:2000].lower()
    if text.strip().startswith("{"):
        return any(kw in t for kw in ['"openapi"', '"swagger"', '"paths"', '"info"'])
    if "openapi:" in t or "swagger:" in t:
        return True
    return False


def classify_response(body: str) -> tuple[list[str], str]:
    """Классифицирует ответ по паттернам (логика из prototype/auth_checker)."""
    patterns_found: list[str] = []
    max_severity = "LOW"
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    for name, pattern in SENSITIVE_PATTERNS.items():
        match = pattern.search(body)
        if match:
            # Для password проверяем что значение не маскировано и не placeholder
            if name in ("password", "admin_password", "db_password", "smtp_password"):
                val_match = re.search(r'"(\w+)"\s*:\s*"([^"]*)"', match.group(0))
                if val_match:
                    field, val = val_match.group(1), val_match.group(2)
                    if is_masked_value(val) or is_placeholder_value(field, val):
                        continue

            # Для AWS ключей проверяем что не пример
            if name == "aws_access_key":
                if is_aws_example_key(match.group(0)):
                    continue

            # Для DSN проверяем что не placeholder
            if name.endswith("_dsn") and is_placeholder_dsn(match.group(0)):
                continue

            patterns_found.append(name)
            sev = SEVERITY_MAP.get(name, "LOW")
            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev

    return patterns_found, max_severity


async def check_host(row: HostRow, cfg: Settings, proxy: str | None = None) -> CheckResult:
    """
    Проверяет хост: ищет OpenAPI, тестирует эндпоинты.

    Эта функция ничего не знает про БД — только сеть.
    """
    base_url = row.base_url  # protocol://host:port

    started = time.perf_counter()
    result = CheckResult(is_alive=False)

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    timeout = aiohttp.ClientTimeout(total=cfg.check_timeout)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=10)

    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
        ) as session:
            # 1. TCP alive check
            result.is_alive = True
            result.latency_ms = int((time.perf_counter() - started) * 1000)

            # 2. Поиск OpenAPI спецификации
            spec = None
            spec_path = None

            for path in OPENAPI_PATHS:
                try:
                    url = base_url.rstrip("/") + path
                    async with session.get(url, allow_redirects=False, proxy=proxy) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if is_openapi_spec(text):
                                spec = json.loads(text)
                                spec_path = path
                                break
                except (json.JSONDecodeError, aiohttp.ClientError):
                    continue

            if spec is None:
                result.has_openapi = False
                return result

            # 3. Парсим спецификацию
            result.has_openapi = True
            result.spec_path = spec_path
            result.spec_title = spec.get("info", {}).get("title", "Unknown")

            paths = spec.get("paths", {})
            security_schemes = spec.get("components", {}).get("securitySchemes", {})
            global_security = spec.get("security", [])
            has_global_security = bool(global_security) or bool(security_schemes)

            endpoints_data: list[dict[str, Any]] = []
            all_patterns: list[str] = []
            max_severity = "LOW"
            severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

            # 4. Тестируем эндпоинты
            for path_template, methods in paths.items():
                if not isinstance(methods, dict):
                    continue

                for method, details in methods.items():
                    if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        continue

                    # Проверяем security на уровне операции
                    op_security = details.get("security", None)
                    expects_auth = has_global_security if op_security is None else bool(op_security)

                    # Подставляем параметры пути
                    test_path = re.sub(r'\{[^}]+\}', '1', path_template)
                    url = base_url.rstrip("/") + test_path

                    ep_data: dict[str, Any] = {
                        "path": path_template,
                        "method": method.upper(),
                        "expects_auth": expects_auth,
                        "status_code": None,
                        "verdict": None,
                        "patterns": [],
                        "response": None,
                    }

                    try:
                        async with session.request(
                            method.upper(),
                            url,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=cfg.check_timeout),
                            proxy=proxy,
                        ) as resp:
                            ep_data["status_code"] = resp.status
                            body = await resp.text()

                            if resp.status == 200:
                                # Классифицируем ответ
                                patterns, sev = classify_response(body[:100_000])
                                ep_data["patterns"] = patterns
                                all_patterns.extend(patterns)

                                if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                                    max_severity = sev

                                # Логика verdict:
                                # VULNERABLE - есть паттерны (реальные данные)
                                # EXPOSED - expects_auth но доступен без auth (потенциальная проблема)
                                # PUBLIC_OK - публичный эндпоинт
                                if patterns:
                                    ep_data["verdict"] = "VULNERABLE"
                                    result.vulnerable_count += 1
                                elif expects_auth:
                                    ep_data["verdict"] = "EXPOSED"
                                    result.public_count += 1  # считаем как exposed, не vulnerable
                                else:
                                    ep_data["verdict"] = "PUBLIC_OK"
                                    result.public_count += 1

                                # Сохраняем JSON ответ (до 50KB) только для важных
                                if patterns:
                                    try:
                                        ep_data["response"] = json.loads(body[:50_000])
                                    except json.JSONDecodeError:
                                        ep_data["response"] = body[:50_000]

                            elif resp.status in (401, 403):
                                ep_data["verdict"] = "PROTECTED"
                                result.protected_count += 1
                            else:
                                ep_data["verdict"] = "ERROR"

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        ep_data["verdict"] = "ERROR"

                    endpoints_data.append(ep_data)
                    result.total_endpoints += 1

            result.endpoints = endpoints_data
            result.data_patterns = list(set(all_patterns))
            result.severity = max_severity

            # Фильтруем только эндпоинты с паттернами (реальные находки)
            vulnerable_eps = [
                {
                    "path": ep["path"],
                    "method": ep["method"],
                    "status": ep["status_code"],
                    "verdict": ep["verdict"],
                    "patterns": ep["patterns"],
                    "response": ep.get("response"),
                }
                for ep in endpoints_data
                if ep.get("patterns")  # только с реальными паттернами
            ]

            result.data = {
                "spec_title": result.spec_title,
                "endpoints_tested": result.total_endpoints,
                "vulnerable": vulnerable_eps,
            }

    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        result.is_alive = False
        result.data = {"error": type(exc).__name__}

    return result
