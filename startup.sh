#!/bin/bash
# 

echo "[DEBUG] startup.sh triggered"

# Set working directory to where api.py lives
cd backend

# Activate Azure-created virtual environment if available
if [ -d "/antenv" ]; then
  echo "[INFO] Activating Azure venv"
  source /antenv/bin/activate
else
  echo "[WARN] Azure virtual environment not found"
fi

# Debug: list installed packages
echo "[DEBUG] Installed packages:"
pip list

# Start the app
echo "[DEBUG] Starting gunicorn"
export PYTHONPATH=.
exec gunicorn app.api:app --bind=0.0.0.0:8000 --timeout 300
