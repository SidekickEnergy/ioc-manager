#!/bin/bash

echo "[DEBUG] startup.sh triggered"

VENV_PATH=$(find /tmp -type d -name "antenv" | head -n 1)

if [ -n "$VENV_PATH" ]; then
  echo "[INFO] Activating Azure virtual environment at $VENV_PATH"
  source "$VENV_PATH/bin/activate"
else
  echo "[WARN] Virtual environment not found!"
fi

# Optional: Debug installed packages
echo "[DEBUG] Installed packages:"
pip list

echo "[DEBUG] Starting gunicorn"
export PYTHONPATH=./backend
exec "$VENV_PATH/bin/gunicorn" app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
