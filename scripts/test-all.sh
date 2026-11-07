#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

(cd "$ROOT" && PYTHONPATH=src python -m unittest discover -s tests -v \
  && PYTHONPATH=src python -m privacyflow.cli validate config.example.toml >/dev/null \
  && PYTHONPATH=src python -m privacyflow.cli rotation-plan config.example.toml >/dev/null)

python -m compileall -q "$ROOT/src"
python scripts/syntax-checks.py "$ROOT"
python scripts/scan-secrets.py "$ROOT"
