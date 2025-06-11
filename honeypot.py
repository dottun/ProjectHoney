# honeypot.py
import json
import logging
import os
import secrets
import ipaddress
import requests
import random
import time
from datetime import datetime, timedelta
from functools import wraps

import numpy as np
from flask import request, redirect, url_for, flash, current_app
from sqlalchemy import func, distinct
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from werkzeug.security import generate_password_hash, check_password_hash

# Import db and BlockedIP from your models and extensions, but avoid circular imports
# We'll pass `current_app.logger` and `db` where necessary, or rely on app context.
from extensions import db
from models import Attack, BlockedIP

# Global dictionary for in-memory blocked IPs (for quick lookups)
blocked_ips = {}
# Key: IP address (str)
# Value: datetime object when the block expires

# --- Utility Functions ---

def get_geolocation_data(ip_address, logger, ipinfo_api_key):
    """
    Fetches geolocation data for an IP address using ipinfo.io.
    Mocks for local/private IPs.
    """
    if ip_address == "127.0.0.1" or ipaddress.ip_address(ip_address).is_private:
        return {"country": "Local", "city": "N/A", "latitude": None, "longitude": None}

    if not ipinfo_api_key or ipinfo_api_key == 'YOUR_IPINFO_API_KEY':
        logger.warning("IPINFO_API_KEY not set or is placeholder. Cannot perform geo-location lookup.")
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
        logger.error(f"Error fetching geolocation data for {ip_address}: {e}")
        return {"country": "Error", "city": "Error", "latitude": None, "longitude": None}

def check_ip_reputation(ip_address, logger):
    """
    Checks IP reputation against a dummy list/simulated threat intelligence.
    For production, integrate with real threat intelligence APIs.
    """
    if ip_address == "127.0.0.1" or ipaddress.ip_address(ip_address).is_private:
        return {"is_malicious": False, "reason": "Local IP"}

    malicious_ips = ["1.2.3.4", "5.6.7.8"] # Example public malicious IPs
    if ip_address in malicious_ips:
        return {"is_malicious": True, "reason": "Known malicious IP (dummy list)"}

    if random.random() < 0.05: # 5% chance of an unknown IP being flagged
        return {"is_malicious": True, "reason": "Suspicious activity detected (dummy chance)"}

    return {"is_malicious": False, "reason": "No threats detected (dummy check)"}

def block_ip(ip_address, duration_minutes=60, reason="Suspicious activity"):
    """
    Blocks an IP address by adding it to the database and in-memory cache.
    """
    block_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
    
    with current_app.app_context():
        existing_block = BlockedIP.query.filter_by(ip_address=ip_address).first()
        if existing_block:
            existing_block.blocked_until = block_until
            existing_block.reason = reason
            existing_block.blocked_at = datetime.utcnow()
            db.session.merge(existing_block)
            current_app.logger.info(f"ACTION: IP {ip_address} block updated in DB until {block_until.isoformat()} for reason: {reason}")
        else:
            new_block = BlockedIP(ip_address=ip_address, blocked_until=block_until, reason=reason, blocked_at=datetime.utcnow())
            db.session.add(new_block)
            current_app.logger.info(f"ACTION: New IP {ip_address} BLOCKED in DB until {block_until.isoformat()} for reason: {reason}")
        db.session.commit()

    blocked_ips[ip_address] = block_until
    current_app.logger.info(f"ACTION: IP {ip_address} BLOCKED (DB & In-memory) until {block_until.isoformat()}")

def is_ip_blocked(ip_address):
    """
    Checks if an IP address is currently blocked. Checks in-memory first, then DB.
    """
    # First, check the in-memory cache for speed
    if ip_address in blocked_ips:
        if datetime.utcnow() < blocked_ips[ip_address]:
            return True
        else:
            # Block expired in memory, remove it
            del blocked_ips[ip_address]
            current_app.logger.info(f"ACTION: Expired in-memory block for IP {ip_address} removed.")
            
    # Now, check the database for persistent blocks
    with current_app.app_context():
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
                current_app.logger.info(f"ACTION: Expired DB block for IP {ip_address} removed.")
                return False
    return False

def unblock_ip(ip_address):
    """
    Manually unblocks an IP address from the database and in-memory.
    """
    with current_app.app_context():
        block_entry = BlockedIP.query.filter_by(ip_address=ip_address).first()
        if block_entry:
            db.session.delete(block_entry)
            db.session.commit()
            current_app.logger.info(f"ACTION: IP {ip_address} unblocked in DB.")
    
    if ip_address in blocked_ips:
        del blocked_ips[ip_address]
        current_app.logger.info(f"ACTION: Manually unblocked IP {ip_address} from in-memory.")

# --- AI/ML Anomaly Detector ---

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = LogisticRegression(random_state=42)
        self.pipeline = Pipeline([
            ('scaler', self.scaler),
            ('classifier', self.model)
        ])
        current_app.logger.info("AnomalyDetector initialized. Preparing to train a basic ML model.")
        self._train_dummy_model()

    def _generate_dummy_data(self):
        """
        Generates a small, simulated dataset for training the anomaly detector.
        Features correspond to the ones extracted in _extract_features.
        Labels: 0 for Benign, 1 for Malicious.
        """
        X = [] # Features
        y = [] # Labels (0: Benign, 1: Malicious)

        # Benign examples
        X.append([192, 50, 20, 0, 0, 0, 0, 0, 0]) # Normal GET
        X.append([10, 70, 30, 0, 10, 0, 0, 0, 1]) # Normal POST
        X.append([172, 60, 25, 0, 5, 0, 0, 0, 0]) # Another normal GET
        y.extend([0, 0, 0])

        # Malicious examples
        X.append([5, 30, 40, 1, 100, 1, 0, 0, 15]) # SQLi attempt
        X.append([100, 20, 60, 0, 80, 0, 1, 0, 10]) # XSS attempt
        X.append([200, 40, 50, 1, 120, 0, 0, 1, 20]) # Union-based attack
        X.append([150, 10, 15, 0, 5, 0, 0, 0, 0]) # Suspicious IP, benign request (still label as benign for this simple model)
        y.extend([1, 1, 1, 0]) # Last one is 'suspicious' but let's label it benign for simplicity for this model

        X.append([8, 10, 10, 0, 0, 0, 0, 0, 0]) # Very basic, benign
        y.append(0)

        return np.array(X), np.array(y)

    def _train_dummy_model(self):
        """
        Trains the ML model on a dummy dataset.
        """
        X_dummy, y_dummy = self._generate_dummy_data()
        try:
            self.pipeline.fit(X_dummy, y_dummy)
            current_app.logger.info("Anomaly Detector model trained on dummy data.")
        except Exception as e:
            current_app.logger.error(f"Error training dummy Anomaly Detector model: {e}")

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

        try:
            ip_octet_1 = int(ip_address.split('.')[0]) if '.' in ip_address else 0
        except ValueError:
            ip_octet_1 = 0

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
        return np.array([feature_vector])

    def detect(self, request_data):
        """
        Uses the trained ML model to predict if a request is an anomaly.
        """
        current_app.logger.info(f"Anomaly detection for request: {request_data.get('path')} from {request_data.get('ip_address')}")
        features_array = self._extract_features(request_data)
        prediction = self.pipeline.predict(features_array)[0]
        prediction_proba = self.pipeline.predict_proba(features_array)[0]

        current_app.logger.info(f"ML Model Raw Prediction: {prediction}, Probabilities: {prediction_proba}")

        if prediction == 1: # Our dummy model predicts 1 for malicious
            if prediction_proba[1] > 0.8:
                return "Malicious"
            else:
                return "Suspicious"
        else:
            if prediction_proba[0] > 0.95:
                return "Benign"
            else:
                return "Suspicious"

# --- RL Agent for Deception ---

class HoneypotRLAgent:
    def __init__(self, logger):
        self.logger = logger
        self.logger.info("HoneypotRLAgent initialized. (Rule-based Deception Logic)")

    def determine_action(self, state: dict) -> str:
        """
        Determines an action based on the AI prediction and IP reputation.
        This mimics adaptive behavior without full RL training.
        """
        self.logger.info(f"RL Agent determining action for state: {state}")

        ai_prediction = state.get('ai_prediction', 'Benign')
        ip_reputation_is_malicious = state.get('ip_reputation_is_malicious', False)

        if ai_prediction == "Malicious":
            if ip_reputation_is_malicious:
                self.logger.info("ACTION RULE: Malicious prediction + Malicious IP reputation -> Block IP (High Confidence Threat)")
                return "block"
            else:
                self.logger.info("ACTION RULE: Malicious prediction + Clean IP -> Redirect to fake page (Test Deception)")
                return "redirect_to_fake_page"
        elif ai_prediction == "Suspicious":
            if ip_reputation_is_malicious:
                self.logger.info("ACTION RULE: Suspicious prediction + Malicious IP -> Serve fake error (Frustrate/Delay)")
                return "serve_fake_error"
            else:
                self.logger.info("ACTION RULE: Suspicious prediction + Clean IP -> Log and observe (Gather more info)")
                return "log"
        else: # Benign
            self.logger.info("ACTION RULE: Benign prediction -> Log only.")
            return "log"

# --- Main Honeypot Logic ---

# Instantiate your AI models (these will be initialized when the app context is available)
# These will be initialized within create_app
anomaly_detector = None
honeypot_rl_agent = None

def init_honeypot_models(app_logger):
    """Initializes anomaly detector and RL agent once the app is ready."""
    global anomaly_detector, honeypot_rl_agent
    anomaly_detector = AnomalyDetector()
    app_logger.info("Anomaly Detector model loaded successfully.")
    honeypot_rl_agent = HoneypotRLAgent(app_logger)
    app_logger.info("RL Agent model loaded successfully.")


def detect_and_log_attack(request_data, user_ip, ip_reputation, geolocation_info=None):
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

    if isinstance(payload, bytes):
        try:
            payload = payload.decode('utf-8')
        except UnicodeDecodeError:
            payload = str(payload)

    logged_geolocation_data = geolocation_info if geolocation_info is not None else {'city': 'N/A', 'country': 'N/A'}
    logged_ip_reputation_data = ip_reputation if ip_reputation is not None else {'is_malicious': False, 'reason': 'N/A'}

    ip_reputation_is_malicious = logged_ip_reputation_data.get('is_malicious', False)

    # 1. Anomaly Detection
    ai_prediction = "Detection_Error"
    if anomaly_detector: # Ensure the model is initialized
        try:
            ai_prediction = anomaly_detector.detect(request_data)
        except Exception as e:
            current_app.logger.error(f"Error during anomaly detection: {e}")
    else:
        current_app.logger.warning("AnomalyDetector not initialized. Skipping AI prediction.")


    # 2. RL Agent determines action
    rl_action = "log" # Default action
    if honeypot_rl_agent: # Ensure the RL agent is initialized
        rl_state = {
            "ip_address": ip_address,
            "ai_prediction": ai_prediction,
            "ip_reputation_is_malicious": ip_reputation_is_malicious
        }
        rl_action = honeypot_rl_agent.determine_action(rl_state)
    else:
        current_app.logger.warning("HoneypotRLAgent not initialized. Skipping RL action determination.")


    # Apply RL Action (e.g., block if the action is 'block')
    if rl_action == "block":
        block_ip(ip_address, duration_minutes=60, reason=f"RL Agent Block: AI={ai_prediction}")
        current_app.logger.info(f"IP {ip_address} blocked by RL agent. Reason: {rl_action}")

    # Determine attack_type
    attack_type = "Generic"
    if ai_prediction == "Malicious":
        attack_type = "AI_Malicious"
    elif "SQL" in str(payload).upper() or "OR '1'='1" in str(payload):
        attack_type = "SQL_Injection_Attempt"
    elif "<SCRIPT" in str(payload).upper() or "ALERT(" in str(payload).upper():
        attack_type = "XSS_Attempt"
    elif any(keyword in path.lower() for keyword in ["admin", "login", "phpmyadmin", "wp-login"]):
        attack_type = "Auth_Bypass_Attempt"

    # 3. Log the attack to the database
    with current_app.app_context():
        attack_log = Attack(
            ip_address=ip_address,
            timestamp=datetime.utcnow(),
            path=path,
            method=method,
            payload=payload,
            user_agent=user_agent,
            referer=referer,
            attack_type=attack_type,
            ai_prediction=ai_prediction,
            rl_action_taken=rl_action,
            headers=json.dumps(request_data.get('headers', {})),
            geolocation_data=logged_geolocation_data,
            ip_reputation_data=logged_ip_reputation_data
        )
        db.session.add(attack_log)
        db.session.commit()
        current_app.logger.info(f"Attack logged: IP={ip_address}, Path={path}, AI={ai_prediction}, RL={rl_action}")

    return ai_prediction, rl_action

def honeypot_trap(f):
    """
    Decorator for honeypot routes to trigger detection and response logic.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        with current_app.app_context():
            user_ip = request.remote_addr
            current_app.logger.info(f"Honeypot trap triggered for IP: {user_ip}")

            if is_ip_blocked(user_ip):
                current_app.logger.warning(f"Blocked IP {user_ip} attempted access.")
                flash('Your IP address has been temporarily blocked due to suspicious activity.', 'danger')
                return redirect(url_for('blocked_page')) # Redirect to a generic blocked page

            ipinfo_api_key = current_app.config.get('IPINFO_API_KEY')
            geolocation_info = get_geolocation_data(user_ip, current_app.logger, ipinfo_api_key)
            ip_reputation = check_ip_reputation(user_ip, current_app.logger)

            request_data = {
                'ip_address': user_ip, # Ensure IP is in request_data for feature extraction
                'path': request.path,
                'method': request.method,
                'headers': dict(request.headers),
                'payload': request.get_data(as_text=True),
                'user_agent': request.headers.get('User-Agent'),
                'referer': request.headers.get('Referer')
            }

            ai_prediction, rl_action = detect_and_log_attack(
                request_data, user_ip, ip_reputation, geolocation_info
            )

            if rl_action == "block":
                flash('Your IP address has been temporarily blocked due to suspicious activity.', 'danger')
                return redirect(url_for('blocked_page'))
            elif rl_action == "redirect_to_fake_page":
                current_app.logger.info(f"RL action: Redirecting {user_ip} to a fake page.")
                return redirect(url_for('fake_page'))
            elif rl_action == "serve_fake_error":
                current_app.logger.info(f"RL action: Serving fake error to {user_ip}.")
                return "Internal Server Error (Fake)", 500
            
            return f(*args, **kwargs)
    return decorated_function