# in startup.sh
source antenv/bin/activate   # if available
pip install -r requirements.txt
export PYTHONPATH=./backend
exec gunicorn app.api:app --chdir backend --bind 0.0.0.0:8000 --timeout 300
