#!/usr/bin/env bash
# Keeps cargo's build cache from filling the disk. Test runs leave a new copy
# of every test binary behind each time, so target/debug grows without limit
# (it reached 122 GB once and the disk filled up). Called by preflight.sh and
# release.sh before they build:
#
#   scripts/trim-target.sh [MAX_GB]   default 40
#
# Deletes target/debug when it is larger than MAX_GB (cargo rebuilds it), then
# refuses to go on when less than 15 GB is free, before a build can fail with
# "no space left on device" halfway through.
set -euo pipefail
cd "$(dirname "$0")/.."
MAX_GB=${1:-40}
if [ -d target/debug ]; then
  size_gb=$(( $(du -sk target/debug | cut -f1) / 1024 / 1024 ))
  if [ "$size_gb" -gt "$MAX_GB" ]; then
    echo "target/debug is ${size_gb} GB (limit ${MAX_GB} GB): deleting it, cargo rebuilds what it needs"
    rm -rf target/debug
  fi
fi
free_gb=$(( $(df -k . | awk 'NR==2 {print $4}') / 1024 / 1024 ))
if [ "$free_gb" -lt 15 ]; then
  echo "only ${free_gb} GB free on this disk; free some space before building" >&2
  exit 1
fi
