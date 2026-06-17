#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$DIR"
exec "$DIR/venv/bin/python" "$DIR/main.py" "$@"
