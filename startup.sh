#!/bin/bash
pip install -r requirements.txt
exec gunicorn backend.app.api:app --bind=0.0.0.0:8000 --timeout 300

