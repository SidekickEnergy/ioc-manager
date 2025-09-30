#!/bin/sh

echo "[DEBUG] startup.sh triggered"

VENV_PATH=$(find /tmp -type d -name "antenv" | head -n 1)

if [ -n "$VENV_PATH" ]; then
  echo "[INFO] Activating virtual environment at $VENV_PATH"
  . "$VENV_PATH/bin/activate"
else
  echo "[WARN] Virtual environment not found"
fi

echo "[DEBUG] Installed packages:"
pip list

echo "[DEBUG] Starting gunicorn"
export PYTHONPATH=$(pwd)/backend
exec gunicorn app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
