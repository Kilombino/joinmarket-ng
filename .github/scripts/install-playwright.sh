#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PLAYWRIGHT_DIR="${PROJECT_ROOT}/tests/playwright"

for command_name in node npm npx timeout; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Required Playwright command not found: %s\n' "$command_name" >&2
        exit 1
    fi
done

cd "$PLAYWRIGHT_DIR"
# Refresh populated local installs too, ignoring any old lockfile.
npm update --no-save --package-lock=false --include=dev

for attempt in 1 2 3; do
    printf 'Playwright browser install attempt %s...\n' "$attempt"
    if timeout 240 npx playwright install chromium; then
        printf 'Playwright browsers installed.\n'
        break
    fi
    if [ "$attempt" -eq 3 ]; then
        printf 'Playwright browser install failed after 3 attempts.\n' >&2
        exit 1
    fi
    printf 'Attempt %s failed or timed out; retrying...\n' "$attempt"
    sleep 5
done

if [ "$(id -u)" -eq 0 ]; then
    env DEBIAN_FRONTEND=noninteractive npx playwright install-deps chromium
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo -n env DEBIAN_FRONTEND=noninteractive npx playwright install-deps chromium
else
    printf '%s\n' \
        'Skipping Playwright OS dependency installation (noninteractive sudo unavailable).' \
        'Existing host dependencies will be validated when Chromium starts.' >&2
fi
