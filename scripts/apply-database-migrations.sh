#!/usr/bin/env bash

set -euo pipefail

if (( EUID != 0 )); then
    echo "This migration runner must be run as root." >&2
    exit 1
fi

relic_dir="${RELIC_DIR:-/srv/relic}"
database_name="${RELIC_DATABASE:-relic}"
migration_file="$relic_dir/database/migrations/002-mmr-checkpoints.sql"

if [[ ! -f "$migration_file" ]]; then
    echo "Migration file not found: $migration_file" >&2
    exit 1
fi

already_applied="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN to_regclass('catalogue.mmr_checkpoint') IS NULL THEN 0 ELSE 1 END"
)"

if [[ "$already_applied" == "1" ]]; then
    echo "MMR checkpoint table is already installed."
    exit 0
fi

runuser -u postgres -- psql --no-psqlrc -X \
    -v ON_ERROR_STOP=1 \
    -d "$database_name" \
    -f "$migration_file"

echo "Installed catalogue.mmr_checkpoint."
