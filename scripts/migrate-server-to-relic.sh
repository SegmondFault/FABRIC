#!/usr/bin/env bash

set -euo pipefail

if (( EUID != 0 )); then
    echo "This migration must be run as root." >&2
    exit 1
fi

old_dir="${RELIC_OLD_DIR:-/srv/fabric}"
new_dir="${RELIC_DIR:-/srv/relic}"
repo_url="${RELIC_REPO_URL:-https://github.com/SegmondFault/RELIC.git}"

if [[ -e "$old_dir" && -e "$new_dir" ]]; then
    echo "Refusing to continue: both $old_dir and $new_dir exist." >&2
    exit 1
fi

if [[ -d "$old_dir/.git" ]]; then
    mv "$old_dir" "$new_dir"
elif [[ ! -d "$new_dir/.git" ]]; then
    echo "No Git checkout found at $old_dir or $new_dir." >&2
    exit 1
fi

git -C "$new_dir" remote set-url origin "$repo_url"

postgres_value() {
    runuser -u postgres -- psql --no-psqlrc -X -d postgres -Atqc "$1"
}

rename_role_if_needed() {
    local old_role="$1"
    local new_role="$2"
    local old_exists
    local new_exists

    old_exists="$(postgres_value "SELECT 1 FROM pg_roles WHERE rolname = '$old_role'")"
    new_exists="$(postgres_value "SELECT 1 FROM pg_roles WHERE rolname = '$new_role'")"

    if [[ "$old_exists" == "1" && "$new_exists" == "1" ]]; then
        echo "Refusing to rename PostgreSQL role: both $old_role and $new_role exist." >&2
        exit 1
    fi

    if [[ "$old_exists" == "1" ]]; then
        runuser -u postgres -- psql --no-psqlrc -X -d postgres \
            -v ON_ERROR_STOP=1 -c "ALTER ROLE $old_role RENAME TO $new_role;"
    fi
}

rename_role_if_needed fabric_owner relic_owner
rename_role_if_needed fabric_app relic_app

old_database_exists="$(postgres_value "SELECT 1 FROM pg_database WHERE datname = 'fabric'")"
new_database_exists="$(postgres_value "SELECT 1 FROM pg_database WHERE datname = 'relic'")"

if [[ "$old_database_exists" == "1" && "$new_database_exists" == "1" ]]; then
    echo "Refusing to rename PostgreSQL database: both fabric and relic exist." >&2
    exit 1
fi

if [[ "$old_database_exists" == "1" ]]; then
    runuser -u postgres -- psql --no-psqlrc -X -d postgres \
        -v ON_ERROR_STOP=1 \
        -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'fabric' AND pid <> pg_backend_pid();"
    runuser -u postgres -- psql --no-psqlrc -X -d postgres \
        -v ON_ERROR_STOP=1 -c "ALTER DATABASE fabric RENAME TO relic;"
fi

echo "RELIC server migration complete."
echo "Checkout: $new_dir"
echo "Repository: $repo_url"
echo "Database: relic"
