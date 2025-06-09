# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from extensions import db
from app import db # Assuming db is initialized in __init__.py or a similar structure
import json
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy.ext.mutable import MutableDict

class JsonEncodedDict(TypeDecorator):
    impl = TEXT
    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value
    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value

MutableDict.associate_with(JsonEncodedDict) # Associate for mutable dict behavior



# Initialize SQLAlchemy outside of the app factory for flexibility


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # attacks = db.relationship('Attack', backref='user', lazy=True) # Optional: link attacks to users

    def __repr__(self):
        return f'<User {self.username}>'
# Flask-Login integration
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


class Attack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    attack_vector = db.Column(db.String(255), nullable=True) # e.g., 'SQLi', 'XSS', 'Login Brute Force'
    payload = db.Column(db.Text, nullable=True) # Actual malicious payload if captured
    user_agent = db.Column(db.String(500), nullable=True)
    referer = db.Column(db.String(500), nullable=True)
    path = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    ai_prediction = db.Column(db.String(100), nullable=True) # e.g., 'Malicious', 'Benign'
    rl_action_taken = db.Column(db.String(100), nullable=True) # e.g., 'Block IP', 'Redirect'
    geolocation_data = db.Column(db.JSON, nullable=True) # Store dict as JSON
    ip_reputation_data = db.Column(db.JSON, nullable=True) # Store dict as JSON
    status_code = db.Column(db.Integer) # HTTP status code of the response

    headers = db.Column(db.Text)
    geolocation_data = db.Column(JsonEncodedDict) # Or db.Text
    ip_reputation_data = db.Column(JsonEncodedDict) # Or db.Text
    
    attack_type = db.Column(db.String(100), nullable=True) # Or nullable=False if you always have a type
    # --- END ADD THIS NEW LINE ---

    
    user_agent = db.Column(db.Text) # User-Agent string from the request header
    referer = db.Column(db.Text)    # Referer header
    payload = db.Column(db.Text)    # Raw request body/payload
    geolocation_data = db.Column(db.JSON) # Store GeoIP data (e.g., {'city': '...', 'country': '...'})
    ip_reputation_data = db.Column(db.JSON) # Store IP reputation data (e.g., {'is_malicious': True, 'reason': '...'})
    # Note: For SQLite, db.JSON just stores as TEXT internally.

    def __repr__(self):
        return f'<Attack {self.ip_address} - {self.attack_vector} at {self.timestamp}>'



    # Helper to store complex data as JSON strings
    def set_geolocation_data(self, data):
        self.country = data.get('country')
        self.city = data.get('city')
        self.latitude = data.get('latitude')
        self.longitude = data.get('longitude')

    def get_geolocation_data(self):
        return {
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude
        }

    def set_ip_reputation_data(self, data):
        self.ip_reputation_is_malicious = data.get('is_malicious')
        self.ip_reputation_reason = data.get('reason')

    def get_ip_reputation_data(self):
        return {
            'is_malicious': self.ip_reputation_is_malicious,
            'reason': self.ip_reputation_reason
        }

# NEW MODEL FOR PERSISTENT BLOCKED IPS
class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False) # Unique IP address
    blocked_until = db.Column(db.DateTime, nullable=False) # When the block expires
    reason = db.Column(db.String(255), default="Suspicious activity") # Reason for blocking
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow) # When the IP was blocked

    def __repr__(self):
        return f"<BlockedIP {self.ip_address} blocked until {self.blocked_until}>"
