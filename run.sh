#!/bin/bash
# SMP V6.5 - Runner
echo "🚀 Starting Security Management Platform V6.5..."
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python3 main.py
