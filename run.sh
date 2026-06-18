#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$DIR"
# Ensure project bin/ and Go bins are on PATH
export PATH="$DIR/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"
exec "$DIR/venv/bin/python" "$DIR/main.py" "$@"
