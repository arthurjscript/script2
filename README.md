# SCRIPT2 — OpenAPI Auth Checker Microservice

Микросервис для проверки OpenAPI эндпоинтов на уязвимости аутентификации.

## Архитектура

```
PostgreSQL
┌──────────────┐     ┌──────────────┐
│ live_hosts   │ ──► │checked_hosts │
│ (от SCRIPT1) │     │ (результаты) │
└──────────────┘     └──────────────┘
       │                    ▲
       │ CLAIM              │ SAVE
       ▼                    │
┌──────────────────────────────────┐
│         SCRIPT2 × N              │
│  asyncio + asyncpg + aiohttp     │
└──────────────────────────────────┘
```

## Быстрый старт

### 1. Подготовка .env файлов

```bash
cp .env.example .env
cp .env.migrate.example .env.migrate
# Отредактируйте оба файла
```

### 2. Запуск через Docker Compose

```bash
# Сборка образа
docker compose build

# Применить миграции + запустить 3 реплики
docker compose up -d

# Масштабирование на ходу
docker compose up -d --scale script2=5

# Логи
docker compose logs -f script2

# Остановка (graceful)
docker compose stop script2
```

### 3. Локальная разработка

```bash
# Поднять dev-базу
docker compose --profile dev up -d postgres-dev

# Установить зависимости
pip install -e ".[dev]"

# Запустить миграции
export MIGRATIONS_DATABASE_URL="postgresql://postgres:dev@localhost:5433/hosts"
export SCRIPT2_DB_PASSWORD="dev"
for f in migrations/*.sql; do psql "$MIGRATIONS_DATABASE_URL" -f "$f"; done

# Запустить воркер
export DATABASE_URL="postgresql://script2:dev@localhost:5433/hosts"
python -m script2
```

## Конфигурация

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| DATABASE_URL | — | PostgreSQL URL (роль script2) |
| WORKER_ID | hostname-pid | Уникальный ID воркера |
| CONCURRENCY | 100 | Макс. одновременных проверок |
| BATCH_SIZE | 50 | Записей за один CLAIM |
| DB_POOL_SIZE | 10 | Размер пула соединений |
| CHECK_TIMEOUT | 10 | Таймаут проверки (сек) |
| LEASE_SECONDS | 300 | Срок аренды записи |
| MAX_ATTEMPTS | 3 | Макс. попыток |
| POLL_INTERVAL | 5 | Интервал опроса (сек) |
| REAPER_INTERVAL | 60 | Интервал reaper (сек) |

## Схема БД

### live_hosts (существующая)
```sql
id bigint
host inet
port smallint
scheme smallint  -- 0=http, 1=https
status text
content_type text
content_length bigint
server text
check_id bigint
created_at timestamptz
-- Добавляются SCRIPT2:
check_status text DEFAULT 'new'
attempts int DEFAULT 0
locked_by text
locked_until timestamptz
```

### checked_hosts (новая)
```sql
source_id bigint → live_hosts.id
attempt int
-- копия live_hosts
host, port, scheme, ...
-- результаты
is_alive boolean
vulnerable_count int
severity text
data_patterns text[]
result jsonb
```

## Мониторинг

```sql
-- Состояние очереди
SELECT count(*) FILTER (WHERE check_status IN ('new', 'retry')) AS queue,
       count(*) FILTER (WHERE check_status = 'in_progress') AS in_work,
       count(*) FILTER (WHERE check_status = 'in_progress' AND locked_until < now()) AS stuck,
       count(*) FILTER (WHERE check_status = 'failed') AS failed
FROM live_hosts;

-- Скорость за час
SELECT date_trunc('minute', checked_at) AS minute,
       count(*) AS checked,
       sum(vulnerable_count) AS vulnerabilities
FROM checked_hosts
WHERE checked_at > now() - interval '1 hour'
GROUP BY 1 ORDER BY 1;

-- Соединения SCRIPT2
SELECT application_name, state, count(*)
FROM pg_stat_activity
WHERE application_name LIKE 'script2:%'
GROUP BY 1, 2;
```

## Игнор по телу

Декои (teapots) — хосты, возвращающие на все пути одинаковый SPA-HTML или
маскированный env-dump. Чтобы они не попадали в результаты:

| Переменная | Формат | Описание |
|------------|--------|----------|
| IGNORE_BODY_FILE | путь | Файл с маркерами: один на строку, `#` — комментарий |
| IGNORE_BODY_MARKERS | строка | Inline-маркеры через запятую (дополняет файл) |

**Семантика**: если первое 2xx-тело (openapi-пути или generic-probe) содержит
любой маркер (подстрока, регистрозависимо) — проверка прекращается, хост
помечается `done` с `last_error='ignored body: <marker>'`, в `checked_hosts`
строка НЕ создаётся.

Пример `ignore_markers.txt`:
```
GlobalProtect Portal
AKIAEEB860A128BE1E58
```

Очистка существующих результатов:
```bash
python scripts/cleanup_ignored.py --dry-run  # показать
python scripts/cleanup_ignored.py            # удалить
python scripts/cleanup_ignored.py --requeue  # удалить + вернуть в очередь
```

## Тесты

```bash
# Поднять тестовую базу
docker compose --profile dev up -d postgres-dev

# Запустить тесты
TEST_DATABASE_URL="postgresql://postgres:dev@localhost:5433/hosts" pytest
```
