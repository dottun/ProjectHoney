# config.py
import os
import secrets
from datetime import timedelta

class Config:
    # Generate a secure secret key for session management
    # For production, this should be set as an environment variable
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Login Remember Me Cookie Duration
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # API Keys
    IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY', 'ef7810b0485258') # Replace with your actual key or set as env var

    # Email Configuration for Alerts (Flask-Mail)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com') # e.g., 'smtp.gmail.com' for Gmail
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587)) # 587 for TLS, 465 for SSL
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('true', '1', 't')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'your_email@example.com') # Replace with your email
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'your_email_password') # Replace with your email password or app password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME', 'your_email@example.com')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin_alerts@example.com') # Recipient for alerts

    # Honeypot Specific Settings (can be added here if needed)
    # E.g., BLOCK_DURATION_MINUTES = 60