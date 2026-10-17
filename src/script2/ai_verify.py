# -*- coding: utf-8 -*-
"""Проверка AI API-ключей: валидность и баланс у провайдеров.

Использует только бесплатные эндпоинты (список моделей / инфо ключа),
без списания средств с аккаунта.
"""
import re
from typing import Any

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
            elif resp.status in (401, 403):
                result["status"] = "invalid"
                result["detail"] = f"HTTP {resp.status}"
            else:
                result["status"] = "error"
                result["detail"] = f"HTTP {resp.status}"
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        result["detail"] = type(exc).__name__
    return result
