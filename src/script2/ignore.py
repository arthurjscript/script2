# -*- coding: utf-8 -*-
"""Игнор хостов по маркерам в теле ответа (декои/teapots)."""
import logging
from pathlib import Path

from .config import Settings

log = logging.getLogger(__name__)


def load_ignore_markers(cfg: Settings) -> list[str]:
    """Загружает маркеры из файла + inline-строки, trim, без дубликатов.

    Ошибки чтения файла не роняют воркер — логируем WARNING, продолжаем.
    """
    markers: list[str] = []
    seen: set[str] = set()

    # inline-маркеры через запятую
    if cfg.ignore_body_markers:
        for m in cfg.ignore_body_markers.split(","):
            m = m.strip()
            if m and m not in seen:
                seen.add(m)
                markers.append(m)

    # файл: один маркер на строку
    if cfg.ignore_body_file:
        path = Path(cfg.ignore_body_file)
        try:
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and line not in seen:
                            seen.add(line)
                            markers.append(line)
            else:
                log.warning("Ignore body file not found: %s", cfg.ignore_body_file)
        except Exception as exc:
            log.warning("Failed to read ignore body file %s: %s", cfg.ignore_body_file, exc)

    return markers


def match_ignore_marker(text: str, markers: list[str] | None) -> str | None:
    """Возвращает первый маркер (подстрока) найденный в text[:100_000], иначе None.

    Регистрозависимый поиск. Пустой/None список -> сразу None.
    """
    if not markers:
        return None
    chunk = text[:100_000]
    for m in markers:
        if m in chunk:
            return m
    return None
