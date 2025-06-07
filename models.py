# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from extensions import db
#from app import db # <--- This is correct for models.py to get 'db' from app.py


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

    def __repr__(self):
        return f'<Attack {self.ip_address} - {self.attack_vector} at {self.timestamp}>'