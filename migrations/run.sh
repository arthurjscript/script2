#!/bin/sh
# Применяет миграции по порядку (идемпотентно)
set -eu

for f in /migrations/[0-9][0-9][0-9]_*.sql; do
    echo "Applying $f"
    psql "$MIGRATIONS_DATABASE_URL" \
        -v ON_ERROR_STOP=1 \
        -v script2_password="$SCRIPT2_DB_PASSWORD" \
        -f "$f"
done

echo "Migrations completed"
