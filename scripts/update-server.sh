#!/usr/bin/env bash

set -euo pipefail

fabric_dir="${FABRIC_DIR:-/srv/fabric}"

if [[ ! -d "$fabric_dir/.git" ]]; then
    echo "FABRIC is not checked out at $fabric_dir" >&2
    exit 1
fi

if [[ -n "$(git -C "$fabric_dir" status --porcelain)" ]]; then
    echo "Refusing to update: $fabric_dir has uncommitted changes." >&2
    exit 1
fi

git -C "$fabric_dir" fetch origin main
git -C "$fabric_dir" merge --ff-only origin/main

echo "FABRIC is up to date at $(git -C "$fabric_dir" rev-parse --short HEAD)."
