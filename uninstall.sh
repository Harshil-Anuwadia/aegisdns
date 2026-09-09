#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'AegisDNS removal requires Python 3.10 or newer.' 'Your installation has not been changed. Install python3 and retry.' >&2
    exit 1
fi
exec python3 "$ROOT/scripts/setup.py" uninstall "$@"
