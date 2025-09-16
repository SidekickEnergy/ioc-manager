#!/bin/bash
pip install -r requirements.txt
export PYTHONPATH=./backend
exec gunicorn app.api:app --chdir backend --bind=0.0.0.0:8000 --timeout 300
