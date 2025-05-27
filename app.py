
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///sslscan.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Add custom Jinja2 filters
import json

@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string to Python object"""
    try:
        return json.loads(value) if value else []
    except (json.JSONDecodeError, TypeError):
        return []

def create_tables():
    with app.app_context():
        # Import models to ensure tables are created
        import models  # noqa: F401
        db.create_all()

def register_routes():
    # Import routes after app is configured
    import routes  # noqa: F401

# Initialize everything
create_tables()
register_routes()
