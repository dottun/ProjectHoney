# app.py (Top part)
from flask import Flask, render_template, request, url_for, redirect, flash, current_app, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import json
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



# Initialize Flask app
app = Flask(__name__)

# --- Configuration ---
# Generate a secure secret key for session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['IPINFO_API_KEY'] = os.environ.get('IPINFO_API_KEY')

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

from models import User, Attack
app.logger.info("DEBUG: Models imported successfully into app.py!")


# --- User Management (using database) ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # Fetch user by ID from DB


# --- Honeypot Specifics (AI Models - Integrating Basic ML) ---

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
    def __init__(self):
        self.model = "Rule-based Deception Logic" # Updated description
        app.logger.info("HoneypotRLAgent initialized. (Rule-based Deception Logic)")

    def determine_action(self, state):
        """
        Determines an action based on the AI prediction and IP reputation.
        This mimics adaptive behavior without full RL training.
        """
        app.logger.info(f"RL Agent determining action for state: {state}")
        
        ai_prediction = state.get('ai_prediction', 'Benign')
        ip_reputation_is_malicious = state.get('ip_reputation_is_malicious', False)
        
        # Rule-based decision making
        if ai_prediction == "Malicious":
            if ip_reputation_is_malicious:
                app.logger.info("ACTION RULE: Malicious prediction + Malicious IP reputation -> Block IP (High Confidence Threat)")
                return "block_ip"
            else:
                app.logger.info("ACTION RULE: Malicious prediction + Clean IP -> Redirect to fake page (Test Deception)")
                return "redirect_to_fake_page"
        elif ai_prediction == "Suspicious":
            if ip_reputation_is_malicious:
                app.logger.info("ACTION RULE: Suspicious prediction + Malicious IP -> Serve fake error (Frustrate/Delay)")
                return "serve_fake_error"
            else:
                app.logger.info("ACTION RULE: Suspicious prediction + Clean IP -> Log and observe (Gather more info)")
                return "log" # Or maybe serve_fake_error occasionally
        else: # Benign
            app.logger.info("ACTION RULE: Benign prediction -> Log only.")
            return "log"

# Instantiate your AI models outside of the request context
anomaly_detector = AnomalyDetector()
app.logger.info("Anomaly Detector model loaded successfully.")
honeypot_rl_agent = HoneypotRLAgent()
app.logger.info("RL Agent model loaded successfully.")

# --- Helper function for AI detection and logging ---
# ADD parameters: user_ip and ip_reputation
def detect_and_log_attack(request_data, user_ip, ip_reputation):
    """
    Analyzes a request using the Anomaly Detector and RL Agent,
    then logs the attack to the database.
    """
    # ip_address is already in request_data, but for clarity/consistency with user_ip param:
    ip_address = user_ip # Use the user_ip passed directly for consistency

    path = request_data.get('path')
    payload = request_data.get('payload')
    method = request_data.get('method')
    user_agent = request_data.get('user_agent')

    # Now use the ip_reputation passed as a parameter for RL agent
    ip_reputation_is_malicious = ip_reputation.get('is_malicious', False) # <--- USE THIS

    # 1. Anomaly Detection
    ai_prediction = anomaly_detector.detect(request_data)

    # 2. RL Agent determines action
    rl_state = {
        "ip_address": ip_address,
        "ai_prediction": ai_prediction,
        "ip_reputation_is_malicious": ip_reputation_is_malicious # <--- USE THIS
    }
    rl_action = honeypot_rl_agent.determine_action(rl_state)

    # 3. Log the attack to the database
    attack_log = Attack(
        ip_address=ip_address,
        timestamp=datetime.now(),
        path=path,
        method=method,
        payload=payload,
        user_agent=user_agent,
        ai_prediction=ai_prediction,
        rl_action_taken=rl_action,
        status_code=200 # Assuming it was a processed request
    )
    db.session.add(attack_log)
    db.session.commit()
    app.logger.info(f"Attack logged: IP={ip_address}, Path={path}, AI={ai_prediction}, RL={rl_action}")

    return ai_prediction, rl_action

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

def block_ip(ip_address, duration_minutes=60):
    block_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
    blocked_ips[ip_address] = block_until
    app.logger.info(f"ACTION: IP {ip_address} BLOCKED until {block_until.isoformat()}")

def is_ip_blocked(ip_address):
    if ip_address in blocked_ips:
        if datetime.utcnow() < blocked_ips[ip_address]:
            return True
        else:
            del blocked_ips[ip_address]
            app.logger.info(f"ACTION: Expired block for IP {ip_address} removed.")
    return False

def unblock_ip(ip_address):
    if ip_address in blocked_ips:
        del blocked_ips[ip_address]
        app.logger.info(f"ACTION: Manually unblocked IP {ip_address}.")


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
    if request.method == 'POST':
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
    return render_template('signup.html', title='Sign Up')

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Keep your rate limiting
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
            'referer': request.headers.get('Referer', '') # Include referer
        }

        # Call the updated detect_and_log_attack and capture its return values
        ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation)

        # Handle immediate RL actions based on prediction during login attempt
        if ai_prediction == "Malicious" or ai_prediction == "Suspicious":
            app.logger.warning(f"AI Prediction: {ai_prediction} for IP: {user_ip} during login attempt. Action: {rl_action_taken}")
            flash(f"Security Alert during login! AI detected {ai_prediction} activity. Action taken: {rl_action_taken}", 'warning')

            if rl_action_taken == "block_ip":
                block_ip(user_ip, duration_minutes=5)
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
            block_ip(user_ip, duration_minutes=5)
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


@app.route("/forgot_password")
def forgot_password():
    return render_template('forgot_password.html', title='Forgot Password')

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access Denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Fetch all users and attacks for admin view
    all_users = User.query.all()
    all_attacks = Attack.query.order_by(Attack.timestamp.desc()).limit(100).all() # Last 100 attacks

    # Example of showing active blocked IPs (still in-memory for simplicity)
    active_blocks = {ip: until.isoformat() for ip, until in blocked_ips.items() if datetime.utcnow() < until}

    return render_template('admin_dashboard.html', title='Admin Dashboard', 
                           blocked_ips=active_blocks,
                           all_users=all_users,
                           all_attacks=all_attacks)

# Dummy page for RL agent redirect
@app.route("/fake_login_page")
def fake_login_page():
    flash('You have been redirected to a suspicious login page. Your activity is being monitored.', 'warning')
    return render_template('fake_login_page.html', title='Suspicious Login') # Needs fake_login_page.html

# Dummy page for RL agent serving a fake error
@app.route("/fake_error")
def fake_error():
    flash('An internal error occurred (simulated honeypot response).', 'danger')
    return render_template('fake_error.html', title='Simulated Error') # Needs fake_error.html

@app.route("/blocked")
def blocked():
    return render_template('blocked.html', title='Blocked')

# --- Error Handlers (to log 404s as potential attacks) ---
@app.errorhandler(404)
def page_not_found(e):
    # Log the 404 request as a potential attack
    request_data = {
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'path': request.path,
        'method': request.method,
        'payload': None # 404s usually don't have a payload
    }
    app.logger.warning(f"404 Not Found triggered for path: {request.path} from {request.remote_addr}")
    detect_and_log_attack(request_data) # Trigger AI detection for 404s

    # Render the 404 template (assuming you have a 404.html)
    # If you don't have a specific 404.html, Flask will use its default or your custom fake_error.html if triggered by RL
    return render_template('404.html'), 404 # Assuming you have a 404.html template
    # If you don't have 404.html, you can try returning render_template('fake_error.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.exception("An internal server error occurred.") # Log the actual exception
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