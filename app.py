# app.py (Top part)
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import json
from functools import wraps
from sqlalchemy import func, distinct
import numpy as np
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_migrate import Migrate
from flask_limiter.util import get_remote_address
import os
import secrets
import logging
import ipaddress
import requests
import random
import time

# NEW IMPORTS FOR SCALING (these are fine at the top)
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

from flask_mail import Message, Mail
import threading # For non-blocking emails



# Initialize Flask app
app = Flask(__name__)

# --- Configuration ---
# Generate a secure secret key for session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['IPINFO_API_KEY'] = os.environ.get('IPINFO_API_KEY')

# In app.py, near your other app.config settings

# Email Configuration for Alerts
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com' # e.g., 'smtp.gmail.com' for Gmail
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT') or 587) # 587 for TLS, 465 for SSL
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS') is not None # True if present
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL') is not None # True if present (use one of TLS/SSL)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # Your email address
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Your email password/app password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME') # Sender will be your email
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL') or 'your_admin_email@example.com' # The recipient of alerts

mail = Mail(app) # Initialize Flask-Mail


def send_async_email(app_context, msg):
    with app_context:
        try:
            mail.send(msg)
            app.logger.info(f"Email sent to {msg.recipients}")
        except Exception as e:
            app.logger.error(f"Failed to send email: {e}")

def send_alert_email(subject, body, recipient_email=None):
    if not app.config.get('MAIL_SERVER'):
        app.logger.warning("Email server not configured. Skipping email alert.")
        return

    if recipient_email is None:
        recipient_email = app.config.get('ADMIN_EMAIL')

    if not recipient_email:
        app.logger.error("No recipient email defined for alerts. Skipping email alert.")
        return

    msg = Message(
        subject,
        sender=app.config['MAIL_DEFAULT_SENDER'],
        recipients=[recipient_email]
    )
    msg.body = body
    # Send email in a separate thread to avoid blocking the main request
    threading.Thread(target=send_async_email, args=(app.app_context(), msg)).start()


# Mock GeoIP lookup function (for local testing without external API dependency)
def get_country_from_ip(ip_address):
    """
    Mocks a GeoIP lookup.
    If the IP is localhost, returns 'Nigeria' (as per your current location).
    Otherwise, returns 'Unknown' for other local/private IPs or a placeholder.
    For real deployment, replace with a proper GeoIP library/service.
    """
    if ip_address == '127.0.0.1' or ip_address == '::1':
        return 'Nigeria' # Explicitly setting based on your context
    elif ip_address.startswith('192.168.') or \
         ip_address.startswith('10.') or \
         ip_address.startswith('172.16.'):
        return 'Private Network'
    # In a real scenario, you'd use a library like geoip2-python or an API
    # For now, let's just make up a few for demonstration if we get varied IPs
    # This is highly simplified!
    elif ip_address.startswith('8.8.8.8'): # Google DNS for example
        return 'United States'
    elif ip_address.startswith('1.1.1.1'): # Cloudflare DNS for example
        return 'United States'
    else:
        return 'Unknown' # Default for others

# Configure SQLite database (easy for simplified version)
app.config['SECRET_KEY'] = 'CHEGBE@1234' # <--- Make sure this is a strong, unique key for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)


db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="moving-window"
)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
app.logger.info("Application starting up...")

# --- Import Database Models (MOVE THIS BLOCK DOWN HERE!) ---

from models import User, Attack, BlockedIP
app.logger.info("DEBUG: Models imported successfully into app.py!")


# --- User Management (using database) ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # Fetch user by ID from DB


def honeypot_trap(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_ip = request.remote_addr # Get IP from Flask's request context
        app.logger.info(f"Honeypot trap triggered for IP: {user_ip}")

        # Perform GeoIP and IP reputation lookups
        geolocation_info = get_geolocation_info(user_ip) # Assuming this function exists
        ip_reputation = get_ip_reputation(user_ip) # Assuming this function exists

        # Check if IP is blocked before processing further
        if is_ip_blocked(user_ip):
            app.logger.warning(f"Blocked IP {user_ip} attempted access.")
            return "Access Denied (Blocked)", 403

        # Prepare request data for AI analysis
        request_data = {
            'path': request.path,
            'method': request.method,
            'headers': dict(request.headers),
            'payload': request.get_data(as_text=True) # Get payload for POST/PUT requests
        }

        # Call the detection and logging function
        ai_prediction, rl_action = detect_and_log_attack(
            request_data, user_ip, ip_reputation, geolocation_info
        )

        # Apply deception/response based on RL action
        if rl_action == "block":
            # This block is already handled by block_ip, but for clarity:
            return "Access Denied (Blocked by RL Agent)", 403
        elif rl_action == "redirect_to_fake_page":
            app.logger.info(f"RL action: Redirecting {user_ip} to a fake page.")
            return redirect(url_for('fake_page')) # You'd need a 'fake_page' route
        elif rl_action == "serve_fake_error":
            app.logger.info(f"RL action: Serving fake error to {user_ip}.")
            return "Internal Server Error (Fake)", 500 # Serve a fake 500
        # Add more RL actions here
        
        # If RL action is 'log_only' or no specific action taken, proceed to original route
        return f(*args, **kwargs)
    return decorated_function

# Global dictionary for blocked IPs (still in-memory for simplicity, can be moved to DB later)
blocked_ips = {}
# Key: IP address (str)
# Value: datetime object when the block expires

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = LogisticRegression(random_state=42) # A simple classification model
        self.pipeline = Pipeline([
            ('scaler', self.scaler),
            ('classifier', self.model)
        ])
        
        app.logger.info("AnomalyDetector initialized. Preparing to train a basic ML model.")
        self._train_dummy_model() # Train a simple model on startup

    def _generate_dummy_data(self):
        """
        Generates a small, simulated dataset for training the anomaly detector.
        Features correspond to the ones extracted in _extract_features.
        Labels: 0 for Benign, 1 for Malicious.
        """
        X = [] # Features
        y = [] # Labels (0: Benign, 1: Malicious)

        # Benign examples (features: ip_octet_1, user_agent_len, path_len, method_is_post, payload_len, select, script, union, num_special_chars_payload)
        X.append([192, 50, 20, 0, 0, 0, 0, 0, 0]) # Normal GET request
        X.append([10, 70, 30, 0, 10, 0, 0, 0, 1]) # Normal POST, small payload
        X.append([172, 60, 25, 0, 5, 0, 0, 0, 0]) # Another normal GET
        y.extend([0, 0, 0])

        # Malicious examples (features indicative of attacks)
        X.append([5, 30, 40, 1, 100, 1, 0, 0, 15]) # SQLi attempt (high special chars, select in payload)
        X.append([100, 20, 60, 0, 80, 0, 1, 0, 10]) # XSS attempt (script in payload)
        X.append([200, 40, 50, 1, 120, 0, 0, 1, 20]) # Union-based attack
        X.append([150, 10, 15, 0, 5, 0, 0, 0, 0]) # Suspicious IP, but benign-looking request
        y.extend([1, 1, 1, 0]) # Last one is 'suspicious' but let's label it benign for simplicity for this model

        # More complex examples, possibly borderline or suspicious
        X.append([8, 10, 10, 0, 0, 0, 0, 0, 0]) # Low user agent length, looks very basic
        y.append(0) # Label as benign, model should learn to identify

        return np.array(X), np.array(y)

    def _train_dummy_model(self):
        """
        Trains the ML model on a dummy dataset.
        In a real system, you would load a large, pre-processed dataset.
        """
        X_dummy, y_dummy = self._generate_dummy_data()

        # Split data (optional for such small data, but good practice)
        # X_train, X_test, y_train, y_test = train_test_split(X_dummy, y_dummy, test_size=0.2, random_state=42)
        
        # Train the pipeline
        try:
            self.pipeline.fit(X_dummy, y_dummy) # Use X_dummy and y_dummy for training
            app.logger.info("Anomaly Detector model trained on dummy data.")
            
            # Optional: print a simple report
            # y_pred = self.pipeline.predict(X_test)
            # app.logger.info(f"Dummy model classification report:\n{classification_report(y_test, y_pred, zero_division=0)}")
            
        except Exception as e:
            app.logger.error(f"Error training dummy Anomaly Detector model: {e}")

    def _extract_features(self, request_data):
        """
        Converts raw request data into numerical features for the ML model.
        This must be consistent with the features used for training.
        """
        ip_address = request_data.get('ip_address', '0.0.0.0')
        user_agent = request_data.get('user_agent', '')
        path = request_data.get('path', '')
        method = request_data.get('method', 'GET')
        payload = request_data.get('payload', '')

        # Basic IP octet for feature, handle IPv6 or non-standard IPs gracefully
        try:
            ip_octet_1 = int(ip_address.split('.')[0]) if '.' in ip_address else 0
        except ValueError:
            ip_octet_1 = 0 # Default for non-parseable IPs

        features_dict = {
            'ip_octet_1': ip_octet_1,
            'user_agent_len': len(user_agent),
            'path_len': len(path),
            'method_is_post': 1 if method.upper() == 'POST' else 0,
            'payload_len': len(payload),
            'payload_contains_select': 1 if 'select' in payload.lower() else 0,
            'payload_contains_script': 1 if '<script' in payload.lower() else 0,
            'payload_contains_union': 1 if 'union' in payload.lower() else 0,
            'num_special_chars_payload': sum(1 for char in payload if not char.isalnum() and char not in [' ', '\t', '\n', '\r'])
        }
        
        # Convert dictionary to a consistent list/array for ML model input
        # This order must be IDENTICAL to how the model was trained in _generate_dummy_data
        feature_vector = [
            features_dict['ip_octet_1'],
            features_dict['user_agent_len'],
            features_dict['path_len'],
            features_dict['method_is_post'],
            features_dict['payload_len'],
            features_dict['payload_contains_select'],
            features_dict['payload_contains_script'],
            features_dict['payload_contains_union'],
            features_dict['num_special_chars_payload']
        ]
        return np.array([feature_vector]) # Return as a 2D array (1 sample, N features)

    def detect(self, request_data):
        """
        Uses the trained ML model to predict if a request is an anomaly.
        """
        app.logger.info(f"Anomaly detection for request: {request_data.get('path')} from {request_data.get('ip_address')}")

        # 1. Feature Extraction
        features_array = self._extract_features(request_data)

        # 2. Model Prediction
        # The pipeline handles scaling and prediction
        prediction = self.pipeline.predict(features_array)[0]
        prediction_proba = self.pipeline.predict_proba(features_array)[0] # Probability of [Benign, Malicious]

        app.logger.info(f"ML Model Raw Prediction: {prediction}, Probabilities: {prediction_proba}")

        # Map numerical prediction back to descriptive string
        if prediction == 1: # Our dummy model predicts 1 for malicious
            if prediction_proba[1] > 0.8: # High confidence malicious
                return "Malicious"
            else: # Lower confidence, but still malicious prediction
                return "Suspicious"
        else:
            if prediction_proba[0] > 0.95: # High confidence benign
                return "Benign"
            else: # Lower confidence benign, could be suspicious
                return "Suspicious"

class HoneypotRLAgent:
    def __init__(self, logger):
        self.logger = logger  # <--- Corrected indentation here
        app.logger.info("HoneypotRLAgent initialized. (Rule-based Deception Logic)")

    def determine_action(self, state: dict) -> str:
        """
        Determines an action based on the AI prediction and IP reputation.
        This mimics adaptive behavior without full RL training.
        """
        # Ensure that you use self.logger here, not app.logger directly,
        # for consistency with how the logger is passed to the class instance.
        self.logger.info(f"RL Agent determining action for state: {state}")

        ai_prediction = state.get('ai_prediction', 'Benign')
        ip_reputation_is_malicious = state.get('ip_reputation_is_malicious', False)

        # Rule-based decision making
        if ai_prediction == "Malicious":
            if ip_reputation_is_malicious:
                self.logger.info("ACTION RULE: Malicious prediction + Malicious IP reputation -> Block IP (High Confidence Threat)")
                return "block_ip"
            else:
                self.logger.info("ACTION RULE: Malicious prediction + Clean IP -> Redirect to fake page (Test Deception)")
                return "redirect_to_fake_page"
        elif ai_prediction == "Suspicious":
            if ip_reputation_is_malicious:
                self.logger.info("ACTION RULE: Suspicious prediction + Malicious IP -> Serve fake error (Frustrate/Delay)")
                return "serve_fake_error"
            else:
                self.logger.info("ACTION RULE: Suspicious prediction + Clean IP -> Log and observe (Gather more info)")
                return "log" # Or maybe serve_fake_error occasionally
        else: # Benign
            self.logger.info("ACTION RULE: Benign prediction -> Log only.")
            return "log"
    
# Instantiate your AI models outside of the request context
anomaly_detector = AnomalyDetector()
app.logger.info("Anomaly Detector model loaded successfully.")
# app.py, around line 255
# Pass the Flask application's logger when initializing the RL agent
honeypot_rl_agent = HoneypotRLAgent(app.logger)
app.logger.info("RL Agent model loaded successfully.")


# ADD parameters: user_ip, ip_reputation, AND geolocation_info
def detect_and_log_attack(request_data, user_ip, ip_reputation, geolocation_info=None): # <--- ADD geolocation_info
    """
    Analyzes a request using the Anomaly Detector and RL Agent,
    then logs the attack to the database with detailed information.
    """
    ip_address = user_ip

    path = request_data.get('path')
    payload = request_data.get('payload')
    method = request_data.get('method')
    user_agent = request_data.get('user_agent')
    referer = request_data.get('referer')

    # Ensure payload is a string for storage
    if isinstance(payload, bytes):
        try:
            payload = payload.decode('utf-8')
        except UnicodeDecodeError:
            payload = str(payload) # Fallback for undecodable bytes

    # Capture GeoIP and IP Reputation data correctly for the Attack model
    # These should be the direct dicts you get from your lookup functions
    # For now, if lookup functions aren't integrated yet, they might be None or dummy
    # We'll assume `ip_reputation` and `geolocation_info` are dictionaries or None.
    logged_geolocation_data = geolocation_info if geolocation_info is not None else {'city': 'N/A', 'country': 'N/A'}
    logged_ip_reputation_data = ip_reputation if ip_reputation is not None else {'is_malicious': False, 'reason': 'N/A'}

     # ... (your code for payload, logged_geolocation_data, logged_ip_reputation_data, ai_prediction, rl_action) ...

    # Convert dictionaries to JSON strings before passing to the Attack model
    # MAKE SURE 'import json' is at the top of your app.py
    json_geolocation_data = json.dumps(logged_geolocation_data)
    json_ip_reputation_data = json.dumps(logged_ip_reputation_data)
    # The headers line was already correct in your snippet:
    json_headers = json.dumps(request_data.get('headers', {}))

    ip_reputation_is_malicious = logged_ip_reputation_data.get('is_malicious', False) # <--- CORRECTED

    # 1. Anomaly Detection
    try:
        ai_prediction = anomaly_detector.detect(request_data)
    except Exception as e:
        app.logger.error(f"Error during anomaly detection: {e}")
        ai_prediction = "Detection_Error" # Assign a value even if detection fails
    # --- END FIX ---

    # 2. RL Agent determines action
    rl_state = {
        "ip_address": ip_address,
        "ai_prediction": ai_prediction,
        "ip_reputation_is_malicious": ip_reputation_is_malicious
    }
    rl_action = honeypot_rl_agent.determine_action(rl_state)

    # Apply RL Action (e.g., block if the action is 'block')
    if rl_action == "block": # Assuming 'block' is the string the RL agent returns for blocking
        block_ip(ip_address, duration_minutes=60, reason=f"RL Agent Block: AI={ai_prediction}")
        app.logger.info(f"IP {ip_address} blocked by RL agent. Reason: {rl_action}")
    # Add other RL actions like redirect, deceive, etc. here later


    
    # --- FIX for NameError: 'attack_type' not defined ---
    # Determine attack_type based on your logic
    ai_prediction = "Unknown" # or "Benign" if that's a safer default for your system
    attack_type = "Generic" # Default type if no specific conditions are met

    # Example logic to define attack_type (adjust as needed for your project)
    if ai_prediction == "Malicious":
        attack_type = "AI_Malicious"
    elif "SQL" in payload.upper() or "OR '1'='1" in payload:
        attack_type = "SQL_Injection_Attempt"
    elif "<SCRIPT" in payload.upper() or "ALERT(" in payload.upper():
        attack_type = "XSS_Attempt"
    elif any(keyword in path.lower() for keyword in ["admin", "login", "phpmyadmin", "wp-login"]):
        attack_type = "Auth_Bypass_Attempt"
    # Add more rules as needed for your specific honeypot
    # --- END FIX for NameError ---


    # 3. Log the attack to the database
    attack_log = Attack(
        ip_address=ip_address,
        timestamp=datetime.utcnow(), # Use utcnow() for consistency
        path=path,
        method=method,
        payload=payload,
        user_agent=user_agent,
        referer=referer,
        attack_type=attack_type,
        ai_prediction=ai_prediction,
        rl_action_taken=rl_action,
        headers=json.dumps(request_data.get('headers', {})),
        geolocation_data=logged_geolocation_data, # NEW
        ip_reputation_data=logged_ip_reputation_data # NEW
    )
    db.session.add(attack_log)
    db.session.commit()
    app.logger.info(f"Attack logged: IP={ip_address}, Path={path}, AI={ai_prediction}, RL={rl_action}")

    # --- NEW: Send Email Alert for significant actions ---
    alert_subject = None
    alert_body = None

    if ai_prediction == "Malicious": # Assuming AI prediction 'Malicious' triggers alert
        alert_subject = f"Honeypot ALERT: Malicious Activity Detected from {user_ip}"
        alert_body = (
            f"Malicious activity detected by AI:\n"
            f"IP Address: {user_ip}\n"
            f"Path: {request_data['path']}\n"
            f"Method: {request_data['method']}\n"
            f"User Agent: {request_data['user_agent']}\n"
            f"Payload: {request_data['payload']}\n"
            f"AI Prediction: {ai_prediction}\n"
            f"RL Action: {rl_action}\n"
            f"IP Reputation: {logged_ip_reputation_data.get('status', 'N/A')} - {logged_ip_reputation_data.get('reason', '')}\n" # Using logged_ip_reputation_data
            f"Location: {logged_geolocation_data.get('city', 'N/A')}, {logged_geolocation_data.get('country', 'N/A')}\n" # Using logged_geolocation_data
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n" # Use utcnow()
            f"Check Admin Dashboard for more details: {url_for('admin_dashboard', _external=True)}"
        )
    elif rl_action in ["block", "redirect_to_fake_page", "serve_fake_error"]: # Assuming these are the RL actions that trigger alerts
        alert_subject = f"Honeypot ALERT: Deception Action Taken for {user_ip}"
        alert_body = (
            f"Honeypot took action '{rl_action}' against IP:\n"
            f"IP Address: {user_ip}\n"
            f"Path: {request_data['path']}\n"
            f"Method: {request_data['method']}\n"
            f"User Agent: {request_data['user_agent']}\n"
            f"AI Prediction: {ai_prediction}\n"
            f"RL Action: {rl_action}\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n" # Use utcnow()
            f"Check Admin Dashboard for more details: {url_for('admin_dashboard', _external=True)}"
        )

    if alert_subject and alert_body:
        # Assuming you have a send_alert_email function configured
        # You'll need to ensure send_alert_email is properly defined and email settings are configured
        # For now, if not setup, this will just not send emails.
        send_alert_email(alert_subject, alert_body)
    # --- END NEW EMAIL ALERT ---

    return ai_prediction, rl_action # <--- UNCOMMENT and use rl_action

# --- Utility Functions ---
def get_geolocation_data(ip_address, logger, ipinfo_api_key):
    # app.logger.info(f"DEBUG: Getting geolocation for IP: {ip_address}") # Keep for debugging if needed

    if ip_address == "127.0.0.1" or ipaddress.ip_address(ip_address).is_private:
        return {"country": "Local", "city": "N/A", "latitude": None, "longitude": None}

    if not ipinfo_api_key:
        logger.warning("IPINFO_API_KEY not set in get_geolocation_data. Cannot perform geo-location lookup.")
        return {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None}

    try:
        url = f"https://ipinfo.io/{ip_address}/json?token={ipinfo_api_key}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "latitude": data.get("loc", "N/A").split(',')[0] if "loc" in data and data.get("loc") != "N/A" else None,
            "longitude": data.get("loc", "N/A").split(',')[1] if "loc" in data and data.get("loc") != "N/A" else None
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching geolocation data: {e}")
        return {"country": "Error", "city": "Error", "latitude": None, "longitude": None}

def check_ip_reputation(ip_address, logger):
    # app.logger.info(f"DEBUG: Checking IP reputation for {ip_address}") # Keep for debugging if needed
    # Dummy logic: simulate checking against a threat intelligence feed
    if ip_address == "127.0.0.1" or ipaddress.ip_address(ip_address).is_private:
        return {"is_malicious": False, "reason": "Local IP"}

    malicious_ips = ["1.2.3.4", "5.6.7.8"] # Example public malicious IPs
    if ip_address in malicious_ips:
        return {"is_malicious": True, "reason": "Known malicious IP (dummy list)"}

    if random.random() < 0.05: # 5% chance of an unknown IP being flagged
        return {"is_malicious": True, "reason": "Suspicious activity detected (dummy chance)"}

    return {"is_malicious": False, "reason": "No threats detected (dummy check)"}

def block_ip(ip_address, duration_minutes=60, reason="Suspicious activity"): # Added 'reason' parameter
    block_until = datetime.utcnow() + timedelta(minutes=duration_minutes)

    # 1. Add/Update the IP in the database
    existing_block = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if existing_block:
        # Update existing block (e.g., extend expiry or update reason)
        existing_block.blocked_until = block_until
        existing_block.reason = reason
        existing_block.blocked_at = datetime.utcnow() # Update blocked_at to current time
        db.session.merge(existing_block) # Use merge for potential detached instances
        app.logger.info(f"ACTION: IP {ip_address} block updated in DB until {block_until.isoformat()} for reason: {reason}")
    else:
        # Create a new block entry in the database
        new_block = BlockedIP(ip_address=ip_address, blocked_until=block_until, reason=reason)
        db.session.add(new_block)
        app.logger.info(f"ACTION: New IP {ip_address} BLOCKED in DB until {block_until.isoformat()} for reason: {reason}")

    # 2. Add/Update the IP in the in-memory dictionary for quick lookups
    blocked_ips[ip_address] = block_until

    db.session.commit() # Commit the database changes
    app.logger.info(f"ACTION: IP {ip_address} BLOCKED (DB & In-memory) until {block_until.isoformat()}")


def is_ip_blocked(ip_address):
    # First, check the in-memory cache for speed
    if ip_address in blocked_ips:
        if datetime.utcnow() < blocked_ips[ip_address]:
            return True
        else:
            # Block expired in memory, remove it
            del blocked_ips[ip_address]
            app.logger.info(f"ACTION: Expired in-memory block for IP {ip_address} removed.")
            # Continue to check DB to ensure consistency and clean up if needed
            
    # Now, check the database for persistent blocks
    block_entry = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if block_entry:
        if datetime.utcnow() < block_entry.blocked_until:
            # Still blocked in DB, ensure it's in memory for future quick checks
            blocked_ips[ip_address] = block_entry.blocked_until
            return True
        else:
            # Block expired in DB, remove it from DB and in-memory
            db.session.delete(block_entry)
            db.session.commit()
            if ip_address in blocked_ips:
                del blocked_ips[ip_address]
            app.logger.info(f"ACTION: Expired DB block for IP {ip_address} removed.")
    return False

def unblock_ip(ip_address):
    # 1. Remove from the database
    block_entry = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if block_entry:
        db.session.delete(block_entry)
        db.session.commit()
        app.logger.info(f"ACTION: IP {ip_address} unblocked in DB.")

    # 2. Remove from the in-memory dictionary
    if ip_address in blocked_ips:
        del blocked_ips[ip_address]
        app.logger.info(f"ACTION: Manually unblocked IP {ip_address} from in-memory.")



# --- Routes ---
@app.before_request
def check_ip_block():
    user_ip = request.remote_addr
    if is_ip_blocked(user_ip):
        flash('Your IP address has been temporarily blocked due to suspicious activity.', 'danger')
        return render_template('blocked.html')

@app.route("/")
@app.route("/home")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html', title='Home')


@app.route("/signup", methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # This block handles POST requests (when the form is submitted)
    if request.method == 'POST': # <--- This is the correct way to handle POST logic
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'danger')
            return render_template('signup.html', title='Sign Up', username=username, email=email)

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('signup.html', title='Sign Up', username=username, email=email)

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('signup.html', title='Sign Up', username=username, email=email)

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please choose a different one or log in.', 'danger')
            return render_template('signup.html', title='Sign Up', username=username, email=email)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if this is the first user, make them admin
        is_admin_user = True if User.query.count() == 0 else False

        new_user = User(username=username, email=email, password_hash=hashed_password, is_admin=is_admin_user)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        app.logger.info(f"New user registered: {username} (Admin: {is_admin_user})")
        return redirect(url_for('login'))

    # This handles GET requests (when the user just visits the signup page)
    return render_template('signup.html', title='Sign Up')



@app.route("/login", methods=['GET', 'POST'])
@honeypot_trap
@login_required # <--- Corrected spelling
@limiter.limit("3 per minute") # Keep your rate limiting
def login():
    if current_user.is_authenticated:
        # If user is already logged in, redirect them
        return redirect(url_for('dashboard'))

    # Get IP and reputation data regardless of GET or POST for logging/detection
    user_ip = request.remote_addr
    ip_reputation = check_ip_reputation(user_ip, app.logger)
    # Geolocation data might also be useful for logging here, though not directly used in RL state
    geolocation_data = get_geolocation_data(user_ip, app.logger, app.config['IPINFO_API_KEY'])


    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me') == 'on'

        # Prepare request_data for detection and logging
        request_data = {
            'ip_address': user_ip,
            'user_agent': request.headers.get('User-Agent', ''),
            'path': request.path,
            'method': request.method,
            'payload': json.dumps(request.form.to_dict()), # For POST, payload is typically form data
            'referer': request.headers.get('Referer', ''), # Include referer
            'headers': dict(request.headers)
        }

        # Call the updated detect_and_log_attack and capture its return values
        ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

        # Handle immediate RL actions based on prediction during login attempt
        if ai_prediction == "Malicious" or ai_prediction == "Suspicious":
            app.logger.warning(f"AI Prediction: {ai_prediction} for IP: {user_ip} during login attempt. Action: {rl_action_taken}")
            flash(f"Security Alert during login! AI detected {ai_prediction} activity. Action taken: {rl_action_taken}", 'warning')

            if rl_action_taken == "block_ip":
                block_ip(user_ip, duration_minutes=30)
                flash('Your IP has been temporarily blocked.', 'danger')
                return redirect(url_for('blocked')) # Redirect to a generic blocked page
            elif rl_action_taken == "redirect_to_fake_page":
                flash('You have been redirected to a deceptive page.', 'warning')
                return redirect(url_for('fake_login_page')) # Needs a fake_login_page route/template
            elif rl_action_taken == "serve_fake_error":
                flash('An unexpected error occurred (simulated).', 'danger')
                return render_template('fake_error.html') # Needs a fake_error.html template

        # Continue with standard login logic ONLY if no immediate RL action was taken
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=remember_me)
            app.logger.info(f"User logged in: {username}")
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            app.logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password.', 'danger')

    # For GET requests to /login, just render the form
    return render_template('login.html', title='Login')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required
def dashboard():
    user_ip = request.remote_addr
    geolocation = get_geolocation_data(user_ip, app.logger, app.config['IPINFO_API_KEY'])
    ip_reputation = check_ip_reputation(user_ip, app.logger) # Always perform reputation check

    # Combine request data for AI detection and logging
    request_data = {
        'ip_address': user_ip,
        'user_agent': request.headers.get('User-Agent', ''), # Use .get with default for safety
        'path': request.path,
        'method': request.method,
        'payload': str(request.get_data() or b''), # Ensure payload is a string, even if empty
        'referer': request.headers.get('Referer', '') # Add referer if you use it
    }

    # Call detect_and_log_attack ONCE and capture its return values
    ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

    # Now, use the returned prediction and action to handle flash messages and redirects
    if ai_prediction == "Malicious" or ai_prediction == "Suspicious":
        flash(f"Security Alert! AI detected {ai_prediction} activity. Action taken: {rl_action_taken}", 'warning')

        # Execute RL agent's determined action (this logic is now only here in the route)
        if rl_action_taken == "block_ip":
            block_ip(user_ip, duration_minutes=30)
            flash('Your IP has been temporarily blocked.', 'danger')
            return redirect(url_for('blocked')) # Redirect to a generic blocked page or home
        elif rl_action_taken == "redirect_to_fake_page":
            flash('You have been redirected to a deceptive page.', 'warning')
            return redirect(url_for('fake_login_page')) # Needs a fake_login_page route/template
        elif rl_action_taken == "serve_fake_error":
            flash('An unexpected error occurred (simulated).', 'danger')
            return render_template('fake_error.html') # Needs a fake_error.html template

    # Prepare context for the dashboard template
    context = {
        'username': current_user.username,
        'ip_address': user_ip,
        'ip_reputation': ip_reputation,
        'geolocation': geolocation,
        'is_admin': current_user.is_admin,
        'latest_ai_prediction': ai_prediction, # Pass the latest prediction to the template
        'latest_rl_action': rl_action_taken # Pass the latest RL action to the template
    }

    return render_template('dashboard.html', title='Dashboard', **context)

# New API endpoint to receive attack reports from other honeypot instances
@app.route("/report_attack", methods=['POST'])
def report_attack():
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    
    # Basic validation for required fields
    required_fields = ['ip_address', 'attack_vector', 'path', 'method']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required attack data fields"}), 400

    ip_address = data.get('ip_address')
    attack_vector = data.get('attack_vector')
    payload = data.get('payload')
    user_agent = data.get('user_agent')
    referer = data.get('referer')
    path = data.get('path')
    method = data.get('method')

    # Get geo and reputation data for the reported IP
    geolocation = get_geolocation_data(ip_address, app.logger, app.config['IPINFO_API_KEY'])
    ip_reputation = check_ip_reputation(ip_address, app.logger)

    # Perform AI detection on the reported attack data
    attack_data_for_ai = {
        'ip_address': ip_address,
        'user_agent': user_agent,
        'path': path,
        'method': method,
        'payload': payload
    }
    ai_prediction = anomaly_detector.detect(attack_data_for_ai)
    
    # Determine RL action for the reported attack
    rl_state = {
        'ip_address': ip_address,
        'ai_prediction': ai_prediction,
        'ip_reputation_is_malicious': ip_reputation.get('is_malicious', False)
    }
    rl_action_taken = honeypot_rl_agent.determine_action(rl_state)

    # Log the attack to the database
    new_attack = Attack(
        ip_address=ip_address,
        attack_vector=attack_vector,
        payload=payload,
        user_agent=user_agent,
        referer=referer,
        path=path,
        method=method,
        ai_prediction=ai_prediction,
        rl_action_taken=rl_action_taken,
        geolocation_data=geolocation,
        ip_reputation_data=ip_reputation
    )
    db.session.add(new_attack)
    db.session.commit()

    app.logger.info(f"Received and logged attack from {ip_address} ({attack_vector}). AI: {ai_prediction}, RL Action: {rl_action_taken}")

    return jsonify({"message": "Attack reported successfully", "ai_prediction": ai_prediction, "rl_action": rl_action_taken}), 200



# --- HONEYPOT LURES (FAKE ENDPOINTS) ---

@app.route("/admin/config", methods=['GET', 'POST'])
@app.route("/config", methods=['GET', 'POST'])
@app.route("/settings", methods=['GET', 'POST'])
def lure_admin_config():
    user_ip = request.remote_addr
    ip_reputation = check_ip_reputation(user_ip, app.logger)

    request_data = {
        'ip_address': user_ip,
        'user_agent': request.headers.get('User-Agent', ''),
        'path': request.path,
        'method': request.method,
        'payload': json.dumps(request.form.to_dict()) if request.method == 'POST' else '',
        'referer': request.headers.get('Referer', '')
    }

    app.logger.warning(f"Honeypot Lure Hit: Admin/Config probe from {user_ip} on path {request.path}")
    ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

    # Apply RL action - could be block, redirect, or just serve a fake error
    if rl_action_taken == "block_ip":
        block_ip(user_ip, duration_minutes=30)
        flash('Your IP has been temporarily blocked.', 'danger')
        return redirect(url_for('blocked'))
    elif rl_action_taken == "redirect_to_fake_page":
        flash('You have been redirected to a deceptive page.', 'warning')
        return redirect(url_for('fake_login_page'))
    elif rl_action_taken == "serve_fake_error":
        flash('An unexpected error occurred (simulated).', 'danger')
        return render_template('fake_error.html')

    # Default lure response: redirect to login or serve a generic error
    flash("Access Denied.", 'danger')
    return render_template('fake_error.html', title='Access Denied') # Or return redirect(url_for('login'))


@app.route("/wp-login.php", methods=['GET', 'POST'])
@app.route("/wp-admin", methods=['GET', 'POST'])
def lure_wordpress():
    user_ip = request.remote_addr
    ip_reputation = check_ip_reputation(user_ip, app.logger)

    request_data = {
        'ip_address': user_ip,
        'user_agent': request.headers.get('User-Agent', ''),
        'path': request.path,
        'method': request.method,
        'payload': json.dumps(request.form.to_dict()) if request.method == 'POST' else '',
        'referer': request.headers.get('Referer', '')
    }

    app.logger.warning(f"Honeypot Lure Hit: WordPress probe from {user_ip} on path {request.path}")
    ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

    if rl_action_taken == "block_ip":
        block_ip(user_ip, duration_minutes=30)
        flash('Your IP has been temporarily blocked.', 'danger')
        return redirect(url_for('blocked'))
    elif rl_action_taken == "redirect_to_fake_page":
        flash('You have been redirected to a deceptive page.', 'warning')
        return redirect(url_for('fake_login_page'))
    elif rl_action_taken == "serve_fake_error":
        flash('An unexpected error occurred (simulated).', 'danger')
        return render_template('fake_error.html')

    flash("Page Not Found.", 'info')
    return render_template('fake_error.html', title='Page Not Found') # Or a 404 template

@app.route("/phpmyadmin", methods=['GET', 'POST'])
def lure_phpmyadmin():
    user_ip = request.remote_addr
    ip_reputation = check_ip_reputation(user_ip, app.logger)

    request_data = {
        'ip_address': user_ip,
        'user_agent': request.headers.get('User-Agent', ''),
        'path': request.path,
        'method': request.method,
        'payload': json.dumps(request.form.to_dict()) if request.method == 'POST' else '',
        'referer': request.headers.get('Referer', '')
    }

    app.logger.warning(f"Honeypot Lure Hit: phpMyAdmin probe from {user_ip} on path {request.path}")
    ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

    if rl_action_taken == "block_ip":
        block_ip(user_ip, duration_minutes=30)
        flash('Your IP has been temporarily blocked.', 'danger')
        return redirect(url_for('blocked'))
    elif rl_action_taken == "redirect_to_fake_page":
        flash('You have been redirected to a deceptive page.', 'warning')
        return redirect(url_for('fake_login_page'))
    elif rl_action_taken == "serve_fake_error":
        flash('An unexpected error occurred (simulated).', 'danger')
        return render_template('fake_error.html')

    flash("Login Required.", 'warning')
    return redirect(url_for('login')) # Redirect them back to the login page

@app.route("/api/v1/user", methods=['GET', 'POST', 'PUT', 'DELETE'])
def lure_api_endpoint():
    user_ip = request.remote_addr
    ip_reputation = check_ip_reputation(user_ip, app.logger)

    # For API endpoints, payload might be JSON body, not form data
    payload_data = {}
    if request.is_json:
        try:
            payload_data = request.get_json()
        except Exception as e:
            app.logger.error(f"Failed to parse JSON payload: {e}")
    elif request.method == 'POST':
        payload_data = request.form.to_dict() # Fallback for form data

    request_data = {
        'ip_address': user_ip,
        'user_agent': request.headers.get('User-Agent', ''),
        'path': request.path,
        'method': request.method,
        'payload': json.dumps(payload_data),
        'referer': request.headers.get('Referer', '')
    }

    app.logger.warning(f"Honeypot Lure Hit: API probe from {user_ip} on path {request.path}")
    ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

    if rl_action_taken == "block_ip":
        block_ip(user_ip, duration_minutes=30)
        # For API, return JSON error not redirect
        return jsonify({"status": "error", "message": "Access blocked"}), 403
    elif rl_action_taken == "redirect_to_fake_page":
        return redirect(url_for('fake_login_page'))
    elif rl_action_taken == "serve_fake_error":
        return render_template('fake_error.html')

    # For API lures, it's often best to return a JSON response
    return jsonify({"status": "error", "message": "Authentication Required"}), 401


@app.route("/forgot_password")
def forgot_password():
    return render_template('forgot_password.html', title='Forgot Password')

@app.route('/attack_logs')
@login_required
def attack_logs():
    # Only allow admins to view this page
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch all attack logs, ordered by timestamp descending
    all_attacks = Attack.query.order_by(Attack.timestamp.desc()).all()
    # You can add pagination here later if you have too many logs

    return render_template('attack_logs.html', title='Attack Logs', all_attacks=all_attacks)


@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to view the admin dashboard.', 'danger')
        return redirect(url_for('dashboard'))

    # ... (your existing POST request handling for manual_block_ip) ...

    # For GET request (and after POST redirect), fetch data
    users = User.query.all()
    active_blocked_ips_db = BlockedIP.query.filter(BlockedIP.blocked_until > datetime.utcnow()).all()

    # Fetch dashboard data
    users = User.query.all()
    active_blocked_ips_db = BlockedIP.query.filter(BlockedIP.blocked_until > datetime.utcnow()).all()

    total_interactions = Attack.query.count()
    unique_ips = db.session.query(distinct(Attack.ip_address)).count()
    total_alerts = db.session.query(Attack).filter(
        (Attack.ai_prediction == 'Malicious') | (Attack.rl_action_taken == 'block')
    ).count()

    now = datetime.utcnow()
    one_day_ago = now - timedelta(days=1)

    # Data for "Total Attacks Over Time" Chart
    attacks_over_time_data = db.session.query(
        func.strftime('%Y-%m-%d %H:00', Attack.timestamp).label('time_label'),
        func.count(Attack.id)
    ).filter(Attack.timestamp >= one_day_ago).group_by(
        func.strftime('%Y-%m-%d %H:00', Attack.timestamp)
    ).order_by(
        func.strftime('%Y-%m-%d %H:00', Attack.timestamp)
    ).all()

    attack_chart_labels = [row.time_label for row in attacks_over_time_data]
    attack_chart_data = [row[1] for row in attacks_over_time_data]

    # Data for "Top 5 Source IP Addresses" Chart
    top_ips_data = db.session.query(
        Attack.ip_address,
        func.count(Attack.id).label('ip_count')
    ).filter(Attack.timestamp >= one_day_ago).group_by(
        Attack.ip_address
    ).order_by(
        func.count(Attack.id).desc()
    ).limit(5).all()

    top_ip_labels = [row.ip_address for row in top_ips_data]
    top_ip_counts = [row.ip_count for row in top_ips_data]

    # Data for Geographic Distribution
    all_attack_ips = db.session.query(Attack.ip_address).filter(Attack.timestamp >= one_day_ago).all()

    country_counts = {}
    for ip_row in all_attack_ips:
        country = get_country_from_ip(ip_row.ip_address)
        country_counts[country] = country_counts.get(country, 0) + 1

    sorted_countries = sorted(country_counts.items(), key=lambda item: item[1], reverse=True)

    total_attacks_for_geo = sum(country_counts.values())
    geographic_distribution_data = []
    if total_attacks_for_geo > 0:
        for country, count in sorted_countries:
            percentage = (count / total_attacks_for_geo) * 100
            geographic_distribution_data.append({
                'country': country,
                'percentage': f"{percentage:.1f}%",
                'width': f"{percentage:.1f}%"
            })
    geographic_distribution_data = geographic_distribution_data[:5]


    # --- NEW: Data for AI Functions/Insights ---
    # Get counts of AI predictions
    ai_prediction_counts = db.session.query(
        Attack.ai_prediction,
        func.count(Attack.id)
    ).filter(Attack.timestamp >= one_day_ago).group_by(
        Attack.ai_prediction
    ).all()

    # Get counts of RL actions
    rl_action_counts = db.session.query(
        Attack.rl_action_taken,
        func.count(Attack.id)
    ).filter(Attack.timestamp >= one_day_ago).group_by(
        Attack.rl_action_taken
    ).all()

    # Format the data for display
    ai_insights = {}
    for pred, count in ai_prediction_counts:
        ai_insights[f"Predicted {pred.capitalize()} Attacks"] = count

    for action, count in rl_action_counts:
        if action == 'block':
            ai_insights[f"RL Blocked {count} IPs"] = count
        elif action == 'log':
            ai_insights[f"RL Logged {count} Attacks"] = count

    # Fetch recent high-alert AI decisions (optional, for specific notes)
    # Let's take the latest 3 attacks that were 'Malicious' or 'block' action
    recent_ai_alerts = db.session.query(Attack).filter(
        (Attack.ai_prediction == 'Malicious') | (Attack.rl_action_taken == 'block')
    ).order_by(Attack.timestamp.desc()).limit(3).all()

    # Prepare a list of strings for recent AI alerts
    ai_alert_notes = []
    for alert in recent_ai_alerts:
        note = f"AI: '{alert.ai_prediction}' for IP {alert.ip_address}. RL: '{alert.rl_action_taken}' (Path: {alert.path})"
        ai_alert_notes.append(note)


    return render_template(
        'admin_dashboard.html',
        title='Admin Dashboard',
        total_interactions=total_interactions,
        unique_ips=unique_ips,
        total_alerts=total_alerts,
        users=users,
        active_blocked_ips=active_blocked_ips_db,
        attack_chart_labels=json.dumps(attack_chart_labels),
        attack_chart_data=json.dumps(attack_chart_data),
        top_ip_labels=json.dumps(top_ip_labels),
        top_ip_counts=json.dumps(top_ip_counts),
        geographic_distribution_data=geographic_distribution_data,
        ai_insights=ai_insights, # Pass the new AI insights data
        ai_alert_notes=ai_alert_notes # Pass recent AI alert notes
    )


# app.py

# ... (your existing imports and app setup) ...

@app.route('/trap', methods=['GET', 'POST', 'PUT', 'DELETE']) # Or whatever methods you want to allow
def trap_honeypot():
    ip_address = request.remote_addr
    path = request.path
    method = request.method
    headers = dict(request.headers)
    
    # Try to get payload from different sources (form, json, query params)
    payload = None
    if request.method == 'POST':
        if request.is_json:
            payload = request.json
        else:
            payload = request.form.to_dict()
    elif request.method == 'GET':
        payload = request.args.to_dict()
    
    # Convert payload to string for storage if it's a dict
    if payload:
        payload_str = str(payload)
    else:
        payload_str = ""

    # Dummy AI/RL decisions for now, as real models are external
    ai_prediction = 'Benign' # Default
    rl_action_taken = 'log'  # Default
    attack_type = 'Generic'  # Default

    # Simple logic to simulate AI/RL for common attacks
    if "admin'%20OR%20'1'='1" in payload_str or "SELECT" in payload_str or "UNION" in payload_str:
        attack_type = 'SQL Injection'
        ai_prediction = 'Malicious'
        rl_action_taken = 'block'
    elif "<script>" in payload_str or "onerror=" in payload_str:
        attack_type = 'XSS'
        ai_prediction = 'Malicious'
        rl_action_taken = 'block'
    elif "../" in payload_str or "/etc/passwd" in payload_str:
        attack_type = 'LFI/Directory Traversal'
        ai_prediction = 'Malicious'
        rl_action_taken = 'block'
    elif "cmd=" in payload_str or "exec(" in payload_str:
        attack_type = 'Command Injection'
        ai_prediction = 'Malicious'
        rl_action_taken = 'block'

    # Save attack details to database
    new_attack = Attack(
        ip_address=ip_address,
        path=path,
        method=method,
        headers=json.dumps(headers), # Store headers as JSON string
        payload=payload_str,
        attack_type=attack_type,
        ai_prediction=ai_prediction,
        rl_action_taken=rl_action_taken
    )
    db.session.add(new_attack)
    db.session.commit()

    # Return a generic "404 Not Found" page to the attacker
    # This makes the honeypot less obvious that it's logging
    return render_template('404.html'), 404 # Assuming you have a 404.html template

# ... (rest of your routes and app.run) ...


# Dummy page for RL agent redirect
@app.route("/fake_login_page")
def fake_login_page():
    """
    Renders a deceptive login page to capture attacker credentials.
    """
    # Ensure it's not cached aggressively
    response = make_response(render_template('fake_login_page.html', title='System Login'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/fake_login_submit", methods=['POST'])
def fake_login_submit():
    """
    Endpoint to capture credentials from the fake login page.
    Logs the captured data as a potential attack.
    """
    user_ip = request.remote_addr
    username_attempt = request.form.get('username', 'N/A')
    password_attempt = request.form.get('password', 'N/A')

    app.logger.warning(f"Fake Login Page Interaction: IP={user_ip}, User: {username_attempt}, Pass: {password_attempt}")

    # You might want to get more detailed IP reputation here if not already done
    ip_reputation = check_ip_reputation(user_ip, app.logger)
    geolocation = get_geolocation_data(user_ip, app.logger, app.config['IPINFO_API_KEY'])

    # Prepare request_data for detection and logging
    request_data = {
        'ip_address': user_ip,
        'user_agent': request.headers.get('User-Agent', ''),
        'path': request.path,
        'method': request.method,
        'payload': json.dumps({'username': username_attempt, 'password': password_attempt}),
        'referer': request.headers.get('Referer', '')
    }

    # Log this interaction as a specific type of attack
    ai_prediction = "Credential Harvesting Attempt" # You can hardcode this or pass it to RL agent
    rl_action_taken = "log" # Default action, as we already have the credentials

    # Log it to your attack log
    attack_log = Attack(
        ip_address=user_ip,
        timestamp=datetime.now(),
        path=request_data['path'],
        method=request_data['method'],
        payload=request_data['payload'],
        user_agent=request_data['user_agent'],
        referer=request_data['referer'],
        ai_prediction=ai_prediction, # Overwrite with specific type
        rl_action_taken=rl_action_taken,
        geolocation_data=geolocation,
        ip_reputation_data=ip_reputation,
        status_code=200
    )
    db.session.add(attack_log)
    db.session.commit()
    app.logger.info(f"Logged credential harvesting attempt from {user_ip}")

    # After capturing, you can redirect them to a fake error or another honeypot page,
    # or even back to the real login page to confuse them.
    flash("Login failed. Please try again.", 'danger') # A generic message
    return render_template('fake_error.html', title='Error') # Or redirect to the real login, etc.


@app.route("/admin/unblock_ip", methods=['POST'])
@login_required
def admin_unblock_ip():
    if not current_user.is_admin:
        flash('Access Denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    ip_to_unblock = request.form.get('ip_address')
    if ip_to_unblock:
        if ip_to_unblock in blocked_ips:
            del blocked_ips[ip_to_unblock] # Remove from the in-memory block list
            flash(f'IP {ip_to_unblock} has been unblocked.', 'success')
            app.logger.info(f"Admin {current_user.username} unblocked IP: {ip_to_unblock}")
        else:
            flash(f'IP {ip_to_unblock} was not found in the active block list.', 'warning')
    else:
        flash('No IP address provided for unblocking.', 'danger')

    return redirect(url_for('admin_dashboard'))


# Dummy page for RL agent serving a fake error
@app.route("/fake_error")
def fake_error():
    flash('An internal error occurred (simulated honeypot response).', 'danger')
    return render_template('fake_error.html', title='Simulated Error') # Needs fake_error.html


@app.route("/blocked")
def blocked():
    """
    Displays a page indicating that the user's IP has been blocked.
    """
    return render_template('blocked.html', title='Access Blocked')

# --- Error Handlers (to log 404s as potential attacks) ---
@app.errorhandler(404)
def page_not_found(e):
    user_ip = request.remote_addr # Get user IP here
    ip_reputation = check_ip_reputation(user_ip, app.logger) # Get IP reputation here

    # Log the 404 request as a potential attack
    request_data = {
        'ip_address': user_ip, # Use user_ip
        'user_agent': request.headers.get('User-Agent', ''), # Add default for safety
        'path': request.path,
        'method': request.method,
        'payload': '', # Use empty string for consistency if no payload
        'referer': request.headers.get('Referer', '') # Add referer if needed
    }
    app.logger.warning(f"404 Not Found triggered for path: {request.path} from {user_ip}")

    # Now pass all required arguments
    ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

    # You could optionally apply RL action here too, e.g., for very aggressive 404 scans
    if rl_action_taken == "block_ip":
        block_ip(user_ip, duration_minutes=30)
        return render_template('blocked.html'), 403 # Return 403 Forbidden with blocked page
    elif rl_action_taken == "redirect_to_fake_page":
        return redirect(url_for('fake_login_page'))
    elif rl_action_taken == "serve_fake_error":
        return render_template('fake_error.html'), 500 # Return 500 with fake error

    # Render the 404 template (assuming you have a 404.html)
    # If you don't have a specific 404.html, Flask will use its default or your custom fake_error.html if triggered by RL
    return render_template('404.html', title='Page Not Found'), 404
    # If you don't have 404.html, you can try returning render_template('fake_error.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    user_ip = request.remote_addr
    # Log the rate limit event
    app.logger.warning(f"Rate limit exceeded for IP: {user_ip}. Limit: {e.description}")

    # You could also potentially call block_ip here if you want ALL rate limits to result in a hard block,
    # but be careful not to double-block if your RL agent also blocks.
    # For now, let's just show the blocked page directly.
    return render_template('blocked.html', message="You have made too many requests. Please try again later."), 429

@app.errorhandler(500)
def internal_server_error(e):
    # Log the 500 error for debugging
    app.logger.error(f"500 Internal Server Error: {e}", exc_info=True)
    # Rollback session in case of a database error
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
        # Add a default admin user if no users exist
        if User.query.count() == 0:
            admin_password_hash = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
            default_admin = User(username='admin', email='admin@example.com', password_hash=admin_password_hash, is_admin=True)
            db.session.add(default_admin)
            db.session.commit()
            app.logger.info("Default admin user 'admin' created (password: adminpassword)")

    if not app.config['IPINFO_API_KEY']:
        app.logger.warning("IPINFO_API_KEY not set. Geo-location features will be limited.")
        
    app.run(debug=True, host='0.0.0.0')