#!/bin/bash
# SMP V6.0 - Runner
echo "🚀 Starting Security Management Platform V6.0..."
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python3 main.py
