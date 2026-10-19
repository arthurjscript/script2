# -*- coding: utf-8 -*-
"""Воркер: цикл обработки записей."""
import asyncio
import itertools
import logging
import os
import time
from pathlib import Path

from .checker import check_host
from .config import Settings
from .models import HostRow
from .repository import Repository

log = logging.getLogger(__name__)


class Worker:
    """Воркер обработки записей из live_hosts."""

    def __init__(
        self,
        repo: Repository,
        cfg: Settings,
        stop: asyncio.Event,
        proxies: list[str] | None = None,
    ) -> None:
        self.repo = repo
        self.cfg = cfg
        self.stop = stop
        self.proxies = proxies or []
        self.proxy_cycle = itertools.cycle(self.proxies) if self.proxies else None

        # Счётчики
        self.claimed = 0
        self.done_alive = 0
        self.done_dead = 0
        self.retry_count = 0
        self.failed_count = 0
        self.lost_lease = 0

    def get_proxy(self) -> str | None:
        """Возвращает следующий прокси из ротации."""
        if self.proxy_cycle:
            return next(self.proxy_cycle)
        return None

    def touch_heartbeat(self) -> None:
        """Обновляет файл heartbeat для HEALTHCHECK."""
        try:
            Path(self.cfg.heartbeat_file).touch()
        except OSError:
            pass

    async def process_one(self, row: HostRow) -> None:
        """Обрабатывает одну запись."""
        proxy = self.get_proxy()
        log.debug("Processing id=%d ip=%s:%d proxy=%s", row.id, row.host, row.port, proxy)

        try:
            result = await asyncio.wait_for(
                check_host(row, self.cfg, proxy=proxy),
                timeout=self.cfg.host_timeout,
            )
        except Exception as exc:
            log.warning("Check failed id=%d error=%s", row.id, repr(exc))
            await self.repo.mark_retry(row.id, repr(exc))
            self.retry_count += 1
            return

        saved = await self.repo.save_result(row.id, row.attempts, result)

        if not saved:
            log.warning("Lost lease id=%d", row.id)
            self.lost_lease += 1
            return

        if result.is_alive:
            self.done_alive += 1
            if result.data.get("withdraw_capable"):
                classes: dict[str, int] = {}
                for ep in result.data.get("vulnerable") or []:
                    for p in ep.get("patterns") or []:
                        if p.startswith("withdraw_"):
                            classes[p] = classes.get(p, 0) + 1
                log.warning(
                    "WITHDRAW_CAPABLE id=%d ip=%s:%d severity=%s classes=%s",
                    row.id,
                    row.host,
                    row.port,
                    result.severity,
                    classes,
                )
            if result.vulnerable_count > 0:
                log.info(
                    "VULNERABLE id=%d ip=%s:%d vuln=%d patterns=%s severity=%s",
                    row.id,
                    row.host,
                    row.port,
                    result.vulnerable_count,
                    result.data_patterns,
                    result.severity,
                )
            for chk in result.data.get("ai_key_checks") or []:
                if chk.get("status") == "valid":
                    log.info(
                        "AI_KEY_VALID id=%d ip=%s:%d provider=%s uncensored=%s %s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("provider"),
                        chk.get("uncensored", False),
                        chk.get("detail") or "",
                    )
            for chk in result.data.get("telegram_checks") or []:
                if chk.get("status") == "valid":
                    if chk.get("money"):
                        money_bits = list(chk.get("money_commands") or []) + list(chk.get("money_text") or [])
                        log.warning(
                            "TELEGRAM_BOT_MONEY id=%d ip=%s:%d bot=@%s signals=%s",
                            row.id,
                            row.host,
                            row.port,
                            chk.get("username") or "?",
                            " | ".join(money_bits)[:200],
                        )
                    else:
                        log.info(
                            "TELEGRAM_BOT_VALID id=%d ip=%s:%d bot=@%s",
                            row.id,
                            row.host,
                            row.port,
                            chk.get("username") or "?",
                        )
            for chk in result.data.get("secret_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "SECRET_VALID id=%d ip=%s:%d kind=%s %s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("kind"),
                        chk.get("detail") or "",
                    )
            for chk in result.data.get("wp_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "WP_ADMIN_VALID id=%d ip=%s:%d site=%s user=%s %s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("site") or "?",
                        chk.get("user") or "?",
                        chk.get("detail") or "",
                    )
            for chk in result.data.get("integration_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "INTEGRATION_VALID id=%d ip=%s:%d service=%s %s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("service") or "?",
                        chk.get("detail") or "",
                    )
            # token replay: access_token открыл protected GET (auth bypass)
            for ep in result.data.get("vulnerable") or []:
                if "token_replay" in (ep.get("patterns") or []):
                    log.warning(
                        "TOKEN_REPLAY id=%d ip=%s:%d path=%s",
                        row.id,
                        row.host,
                        row.port,
                        (ep.get("path") or "?").split("#")[0],
                    )
            for chk in result.data.get("twilio_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "TWILIO_PAIR_VALID id=%d ip=%s:%d sid=%s %s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("sid"),
                        chk.get("detail") or "",
                    )
            for chk in result.data.get("twitter_checks") or []:
                if chk.get("status") == "valid":
                    log.info(
                        "TWITTER_VALID id=%d ip=%s:%d",
                        row.id,
                        row.host,
                        row.port,
                    )
            for chk in result.data.get("twitter_session_checks") or []:
                if chk.get("status") == "valid":
                    log.info(
                        "TWITTER_SESSION_VALID id=%d ip=%s:%d user=%s %s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("username") or "?",
                        chk.get("detail") or "",
                    )
            for chk in result.data.get("exchange_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "EXCHANGE_KEY_VALID id=%d ip=%s:%d exch=%s balances=%s withdraw=%s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("exchange"),
                        chk.get("detail") or "",
                        chk.get("withdraw_enabled"),
                    )
            if "money_target" in (result.data_patterns or []):
                log.warning(
                    "MONEY_TARGET id=%d ip=%s:%d withdraw endpoints + verified money keys",
                    row.id,
                    row.host,
                    row.port,
                )
            for chk in result.data.get("cryptopay_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "CRYPTOPAY_KEY_VALID id=%d ip=%s:%d service=%s balances=%s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("service"),
                        chk.get("detail") or "",
                    )
            for chk in result.data.get("aws_key_checks") or []:
                if chk.get("status") == "valid":
                    log.warning(
                        "AWS_KEY_VALID id=%d ip=%s:%d account=%s arn=%s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("account") or "?",
                        chk.get("arn") or "?",
                    )
            for chk in result.data.get("dsn_checks") or []:
                if chk.get("status") == "auth_ok":
                    log.warning(
                        "DSN_AUTH_OK id=%d ip=%s:%d dsn=%s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("dsn"),
                    )
                elif chk.get("status") == "reachable":
                    log.info(
                        "DSN_REACHABLE id=%d ip=%s:%d dsn=%s",
                        row.id,
                        row.host,
                        row.port,
                        chk.get("dsn"),
                    )
        else:
            self.done_dead += 1

    async def run(self) -> None:
        """Основной цикл воркера."""
        log.info(
            "Worker started worker_id=%s concurrency=%d",
            self.cfg.worker_id,
            self.cfg.concurrency,
        )

        inflight: set[asyncio.Task[None]] = set()
        last_stats = time.time()

        while not self.stop.is_set():
            self.touch_heartbeat()

            # Выводим статистику раз в 60 секунд
            if time.time() - last_stats >= 60:
                log.info(
                    "Stats: claimed=%d alive=%d dead=%d retry=%d failed=%d lost=%d inflight=%d",
                    self.claimed,
                    self.done_alive,
                    self.done_dead,
                    self.retry_count,
                    self.failed_count,
                    self.lost_lease,
                    len(inflight),
                )
                last_stats = time.time()

            # Забираем записи под свободные слоты
            free = self.cfg.concurrency - len(inflight)
            if free > 0:
                limit = min(free, self.cfg.batch_size)
                try:
                    rows = await self.repo.claim(limit)
                except Exception as exc:
                    log.error("Claim failed: %s", exc)
                    await asyncio.sleep(self.cfg.poll_interval)
                    continue

                self.claimed += len(rows)

                for row in rows:
                    task = asyncio.create_task(self.process_one(row))
                    inflight.add(task)
                    task.add_done_callback(inflight.discard)

                if rows:
                    continue

            # Ждём завершения задач или таймаут
            if inflight:
                done, _ = await asyncio.wait(
                    inflight,
                    timeout=self.cfg.poll_interval,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            else:
                await asyncio.sleep(self.cfg.poll_interval)

        # Graceful shutdown: ждём завершения текущих задач
        if inflight:
            log.info("Shutdown: waiting for %d tasks...", len(inflight))
            done, pending = await asyncio.wait(
                inflight,
                timeout=self.cfg.shutdown_timeout,
            )
            if pending:
                log.warning("Shutdown: %d tasks still pending", len(pending))
                for task in pending:
                    task.cancel()

        log.info(
            "Worker stopped: claimed=%d alive=%d dead=%d",
            self.claimed,
            self.done_alive,
            self.done_dead,
        )


async def reaper_loop(repo: Repository, cfg: Settings, stop: asyncio.Event) -> None:
    """Фоновая задача: освобождает записи с истёкшей арендой."""
    log.info("Reaper started interval=%ds", cfg.reaper_interval)

    while not stop.is_set():
        try:
            await asyncio.sleep(cfg.reaper_interval)
            if stop.is_set():
                break

            reaped = await repo.reap_expired()
            if reaped:
                log.info("Reaped %d expired leases: %s", len(reaped), reaped[:10])

            # Помечаем дубликаты как done
            duplicates = await repo.mark_duplicates_done()
            if duplicates:
                log.info("Marked %d duplicates as done", len(duplicates))

        except Exception as exc:
            log.error("Reaper error: %s", exc)

    log.info("Reaper stopped")
