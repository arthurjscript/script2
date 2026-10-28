# -*- coding: utf-8 -*-
"""Точка входа: сигналы, pool, worker + reaper, shutdown."""
import asyncio
import logging
import signal
import sys
from pathlib import Path

from .config import Settings
from .db import create_pool
from .ignore import load_ignore_markers
from .repository import Repository
from .worker import Worker, reaper_loop


def load_proxies(cfg: Settings) -> list[str]:
    """Загружает список прокси из файла или URL."""
    proxies: list[str] = []

    if cfg.proxy_url:
        proxies.append(cfg.proxy_url)

    if cfg.proxy_file:
        path = Path(cfg.proxy_file)
        if path.exists():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith(("http://", "https://", "socks")):
                            line = f"http://{line}"
                        proxies.append(line)

    return proxies


def setup_logging(level: str) -> None:
    """Настраивает структурированные логи."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def install_stop_handlers(
    loop: asyncio.AbstractEventLoop,
    stop: asyncio.Event,
) -> None:
    """Устанавливает обработчики сигналов для graceful shutdown."""
    def handle_signal() -> None:
        logging.info("Received stop signal")
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            # Windows: loop.add_signal_handler не работает
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))

    # Windows: SIGBREAK (Ctrl+Break / остановка службы)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, lambda *_: loop.call_soon_threadsafe(stop.set))


async def main() -> None:
    """Главная async-функция."""
    cfg = Settings()
    setup_logging(cfg.log_level)

    log = logging.getLogger(__name__)
    log.info("Starting SCRIPT2 worker_id=%s", cfg.worker_id)

    # Загружаем прокси
    proxies = load_proxies(cfg)
    if proxies:
        log.info("Loaded %d proxies", len(proxies))

    # Загружаем маркеры игнора по телу (декои/teapots)
    markers = load_ignore_markers(cfg)
    if markers:
        log.info("Loaded %d ignore body markers", len(markers))
    else:
        log.info("Body ignore disabled (no markers)")

    stop = asyncio.Event()
    install_stop_handlers(asyncio.get_running_loop(), stop)

    # Создаём пул соединений
    pool = await create_pool(cfg)
    log.info("Database pool created size=%d", cfg.db_pool_size)

    repo = Repository(pool, cfg)
    worker = Worker(repo, cfg, stop, proxies=proxies, markers=markers)

    try:
        # Запускаем worker и reaper параллельно
        await asyncio.gather(
            worker.run(),
            reaper_loop(repo, cfg, stop),
        )
    finally:
        # Graceful shutdown: освобождаем свои записи
        released = await repo.release_mine()
        if released:
            log.info("Released %d in-progress records", len(released))

        await pool.close()
        log.info("Database pool closed")


def run() -> None:
    """Синхронная точка входа."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
