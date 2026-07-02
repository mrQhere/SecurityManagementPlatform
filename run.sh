#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Security Management Platform — Launch Script
# ─────────────────────────────────────────────────────────────────────────────
DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$DIR"
export PATH="$DIR/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

# ── Safety Banner ─────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════════════════════════════════╗"
echo "  ║          Security Management Platform — Starting Up...              ║"
echo "  ╠══════════════════════════════════════════════════════════════════════╣"
echo "  ║                                                                      ║"
echo "  ║  ⚠️   DO NOT press Ctrl+C in this terminal window!                  ║"
echo "  ║                                                                      ║"
echo "  ║  Pressing Ctrl+C will forcefully kill SMP and may interrupt         ║"
echo "  ║  database write operations, causing data loss.                      ║"
echo "  ║                                                                      ║"
echo "  ║  ✅  To close SMP safely: click the  ✕  button inside the app.     ║"
echo "  ║  ✅  A confirmation dialog will appear and databases will be saved. ║"
echo "  ║                                                                      ║"
echo "  ╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Launch SMP
"$DIR/venv/bin/python" "$DIR/main.py" "$@"
EXIT_CODE=$?

# ── Shutdown Report ───────────────────────────────────────────────────────────
echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "  ╔══════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ✅  SMP closed successfully. All databases saved.                  ║"
    echo "  ╚══════════════════════════════════════════════════════════════════════╝"
elif [ $EXIT_CODE -eq 130 ]; then
    echo "  ╔══════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ⚠️   SMP was interrupted via Ctrl+C (exit code 130).              ║"
    echo "  ║  Some data may not have been fully saved. Check logs/ for details. ║"
    echo "  ╚══════════════════════════════════════════════════════════════════════╝"
else
    echo "  ╔══════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ⚠️   SMP exited with code $EXIT_CODE. Check logs/ for details.      ║"
    echo "  ╚══════════════════════════════════════════════════════════════════════╝"
fi
echo ""
