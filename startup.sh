#!/bin/bash

echo "[DEBUG] startup.sh triggered"

# Find and activate the Azure virtual environment
VENV_PATH=$(find /tmp -type d -name "antenv" | head -n 1)

if [ -n "$VENV_PATH" ]; then
  echo "[INFO] Activating Azure virtual environment at $VENV_PATH"
  source "$VENV_PATH/bin/activate"
else
  echo "[WARN] Virtual environment not found!"
fi

# Install your dependencies
echo "[DEBUG] Installing Python packages..."
pip install -r requirements.txt

# Optional: Debug installed packages
echo "[DEBUG] Installed packages:"
pip list

# Start your app using global gunicorn
echo "[DEBUG] Starting gunicorn"
export PYTHONPATH=./backend
exec gunicorn app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
