#!/bin/bash

# Look for Azure's default virtualenv folder
VENV_PATH=$(find /tmp -type d -name "antenv" | head -n 1)

if [ -n "$VENV_PATH" ]; then
  echo "[INFO] Activating Azure virtual environment at $VENV_PATH"
  source "$VENV_PATH/bin/activate"
fi

# Install and run app
pip install -r requirements.txt

export PYTHONPATH=./backend
exec gunicorn app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
