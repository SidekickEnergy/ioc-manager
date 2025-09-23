# app.py (root)
from api import app  # exposes the Flask "app" from api.py
# If you want to be extra compatible with some platforms:
application = app
