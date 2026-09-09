#!/usr/bin/env bash
# Keep the entry point small; Linux and Windows share the same setup workflow.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'AegisDNS setup requires Python 3.10 or newer.' 'Install python3 using your system package manager, then rerun ./install.sh.' >&2
    exit 1
fi
exec python3 "$ROOT/scripts/setup.py" install "$@"
