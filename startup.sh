#!/bin/bash

# Activate Azure's auto-created virtualenv
VENV_PATH=$(find /tmp -type d -name "antenv" | head -n 1)

if [ -n "$VENV_PATH" ]; then
  echo "[INFO] Activating Azure virtual environment at $VENV_PATH"
  source "$VENV_PATH/bin/activate"
fi

# Install dependencies (optional if already built, but safe)
pip install -r requirements.txt

# Fix Python path and working directory
export PYTHONPATH=./backend
exec gunicorn app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
