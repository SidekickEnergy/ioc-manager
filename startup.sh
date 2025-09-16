#!/bin/bash

# Activate Azure's virtual environment if it exists
if [ -e "$HOME/antenv/bin/activate" ]; then
  echo "[INFO] Activating virtual environment..."
  source "$HOME/antenv/bin/activate"
fi

# Install (if needed) and start Gunicorn
pip install -r requirements.txt

export PYTHONPATH=./backend
exec gunicorn app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
