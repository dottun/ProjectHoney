# models.py
import json
from datetime import datetime
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy.ext.mutable import MutableDict
from flask_login import UserMixin

# IMPORTANT: Import the db instance from extensions.
# This ensures that the 'db' object initialized in extensions.py is used.
from extensions import db

# Custom type for JSON data for storing dictionaries/JSON in database columns
class JsonEncodedDict(TypeDecorator):
    impl = TEXT
    cache_ok = True # Improves performance for repeated use

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value

# Associate JsonEncodedDict with MutableDict for detecting in-place changes to dictionaries
MutableDict.associate_with(JsonEncodedDict)

# --- Database Models ---

class User(db.Model, UserMixin): # Inherit from db.Model for SQLAlchemy and UserMixin for Flask-Login
    __tablename__ = 'users' # Explicitly name the table for clarity

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

    # Flask-Login required properties (get_id, is_authenticated, is_active, is_anonymous)
    # are automatically handled by UserMixin as long as you have an 'id' column.
    # No need to explicitly define them unless you have custom logic.


class Attack(db.Model):
    __tablename__ = 'attacks'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    attack_vector = db.Column(db.String(255), nullable=True) # e.g., 'SQLi', 'XSS', 'Login Brute Force'
    payload = db.Column(db.Text, nullable=True) # Actual malicious payload if captured
    user_agent = db.Column(db.String(500), nullable=True)
    referer = db.Column(db.String(500), nullable=True)
    path = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    ai_prediction = db.Column(db.String(100), nullable=True) # e.g., 'Malicious', 'Benign', 'Suspicious'
    rl_action_taken = db.Column(db.String(100), nullable=True) # e.g., 'Block IP', 'Redirect', 'Log'
    headers = db.Column(JsonEncodedDict, nullable=True) # Store request headers as JSON
    geolocation_data = db.Column(JsonEncodedDict, nullable=True) # Store dict as JSON
    ip_reputation_data = db.Column(JsonEncodedDict, nullable=True) # Store dict as JSON
    attack_type = db.Column(db.String(100), nullable=True) # e.g., 'SQL_Injection_Attempt', 'XSS_Attempt'
 # --- NEW COLUMNS FOR GEOLOCATION AND SERVICE FOR EASIER QUERYING ---
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    

    def __repr__(self):
        return f'<Attack {self.ip_address} - {self.attack_type} at {self.timestamp}>'


class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) # When the block was initiated
    reason = db.Column(db.String(255), nullable=True) # Reason for blocking

    def __repr__(self):
        return f'<BlockedIP {self.ip_address} until {self.blocked_until}>'