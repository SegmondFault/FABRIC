#!/usr/bin/env bash

set -euo pipefail

if (( EUID != 0 )); then
    echo "This updater must be run as root." >&2
    exit 1
fi

relic_dir="${RELIC_DIR:-/srv/relic}"

if [[ ! -d "$relic_dir/.git" ]]; then
    echo "RELIC is not checked out at $relic_dir" >&2
    exit 1
fi

if [[ -n "$(git -C "$relic_dir" status --porcelain)" ]]; then
    echo "Refusing to update: $relic_dir has uncommitted changes." >&2
    exit 1
fi

git -C "$relic_dir" fetch origin main
git -C "$relic_dir" merge --ff-only origin/main

echo "RELIC is up to date at $(git -C "$relic_dir" rev-parse --short HEAD)."
