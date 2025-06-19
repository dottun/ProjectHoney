# app.py

# --- Imports at the top of the file ---
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user, UserMixin
import requests # For IP info lookups

# --- Import your initialized extensions from extensions.py ---
from extensions import db, bcrypt, login_manager, migrate, mail

# --- Import your models from models.py ---
# This will now work because models.py imports 'db' from extensions.py, not app.py
from models import User, BlockedIP, Attack

# --- User Loader (CRUCIAL for Flask-Login) ---
@login_manager.user_loader
def load_user(user_id):
    # This function must return a User object or None
    # Using db.session.get for Flask-SQLAlchemy 3.x
    return db.session.get(User, int(user_id))

# --- Application Factory Function ---
def create_app(config_class=None):
    app = Flask(__name__)
    if config_class:
        app.config.from_object(config_class)
    else: # Fallback to a default Config if none is provided (e.g., for local testing)
        class DefaultConfig:
            SECRET_KEY = 'your_super_secret_key_for_dev_CHANGE_THIS'
            SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
            SQLALCHEMY_TRACK_MODIFICATIONS = False
            IPINFO_API_KEY = 'YOUR_IPINFO_API_KEY' # Get one from ipinfo.io
        app.config.from_object(DefaultConfig)

    # Initialize extensions with the app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # Set up Flask-Login
    login_manager.login_view = 'login' # type: ignore
    login_manager.login_message_category = 'info' # type: ignore

    # Basic logging setup
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Helper function to get IP details using ipinfo.io
    def get_ip_details(ip_address):
        if not app.config.get('IPINFO_API_KEY'):
            app.logger.warning("IPINFO_API_KEY not set in config. IP details will be unavailable.")
            return {'country': 'N/A', 'city': 'N/A', 'latitude': None, 'longitude': None}

        if ip_address in ['127.0.0.1', 'localhost']: # Handle local IPs
            return {'country': 'Local', 'city': 'Local', 'latitude': None, 'longitude': None}

        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json?token={app.config['IPINFO_API_KEY']}")
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            loc = data.get('loc', '0,0').split(',')
            return {
                'country': data.get('country', 'N/A'),
                'city': data.get('city', 'N/A'),
                'latitude': float(loc[0]) if loc[0] else None,
                'longitude': float(loc[1]) if loc[1] else None
            }
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error fetching IP details for {ip_address}: {e}")
            return {'country': 'N/A', 'city': 'N/A', 'latitude': None, 'longitude': None}
        except ValueError: # For float conversion errors
            app.logger.error(f"Could not parse latitude/longitude for {ip_address}")
            return {'country': 'N/A', 'city': 'N/A', 'latitude': None, 'longitude': None}

    # --- Routes ---

    @app.route("/")
    @app.route("/welcome")
    def welcome():
        return render_template('welcome.html', title='Welcome')

    @app.route("/register", methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('admin_dashboard'))
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

            if not username or not email or not password:
                flash('Please fill in all fields.', 'danger')
                return render_template('register.html', title='Register')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password_hash=hashed_password)

            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Your account has been created! You can now log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash(f'Registration failed: {e}', 'danger')
        return render_template('register.html', title='Register')

    @app.route("/login", methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('admin_dashboard'))
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password_hash, password):
                from flask_login import login_user
                login_user(user)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin_dashboard'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        return render_template('login.html', title='Login')

    @app.route("/logout")
    @login_required
    def logout():
        from flask_login import logout_user
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('welcome'))

    @app.route("/admin_dashboard")
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('Access denied. You must be an administrator to view this page.', 'danger')
            return redirect(url_for('welcome'))

        time_24_hours_ago = datetime.utcnow() - timedelta(hours=24)
        recent_attacks = db.session.execute(db.select(Attack).filter(Attack.timestamp >= time_24_hours_ago)).scalars().all()

        attack_counts_hourly = {}
        top_ips = {}
        geographic_distribution = {}
        ai_predictions = {'Malicious': 0, 'Benign': 0, 'Unknown': 0}
        rl_actions = {'block': 0, 'monitor': 0, 'allow': 0}

        for attack in recent_attacks:
            hour_key = attack.timestamp.replace(minute=0, second=0, microsecond=0)
            attack_counts_hourly[hour_key] = attack_counts_hourly.get(hour_key, 0) + 1

            top_ips[attack.ip_address] = top_ips.get(attack.ip_address, 0) + 1

            if attack.latitude is not None and attack.longitude is not None and attack.country != 'Local':
                country_key = attack.country
                if country_key not in geographic_distribution:
                    geographic_distribution[country_key] = {
                        'count': 0,
                        'latitude': attack.latitude,
                        'longitude': attack.longitude
                    }
                geographic_distribution[country_key]['count'] += 1

            ai_predictions[attack.ai_prediction] = ai_predictions.get(attack.ai_prediction, 0) + 1
            rl_actions[attack.rl_action_taken] = rl_actions.get(attack.rl_action_taken, 0) + 1

        sorted_hours = sorted(attack_counts_hourly.keys())
        attack_chart_labels = [hour.strftime('%Y-%m-%d %H:00') for hour in sorted_hours]
        attack_chart_data = [attack_counts_hourly[hour] for hour in sorted_hours]

        sorted_top_ips = sorted(top_ips.items(), key=lambda item: item[1], reverse=True)[:5]
        top_ip_labels = [ip for ip, count in sorted_top_ips]
        top_ip_counts = [count for ip, count in sorted_top_ips]
        

        
        geographic_distribution_data = []
        total_geo_attacks = sum(data['count'] for data in geographic_distribution.values())

        if total_geo_attacks > 0:
            sorted_geographic_countries = sorted(geographic_distribution.items(), key=lambda item: item[1]['count'], reverse=True)
            for country, data in sorted_geographic_countries:
                count = data['count']
                percentage = (count / total_geo_attacks) * 100
                width_style = f"{percentage:.2f}%"
                geographic_distribution_data.append({
                    'country': country,
                    'count': count,
                    'percentage': f"{percentage:.2f}%",
                    'width': width_style,
                    'latitude': data['latitude'],
                    'longitude': data['longitude']
            })

        ai_insights = [
            {'category': 'AI Predictions', 'data': ai_predictions},
            {'category': 'RL Actions', 'data': rl_actions}
        ]

        ai_alert_notes = [
            "Anomaly detected in login attempts from new regions.",
            "Spike in '/admin' path access attempts from blocked IPs."
        ]

        return render_template('admin_dashboard.html',
            title='Admin Dashboard',
            attack_chart_labels=json.dumps(attack_chart_labels),
            attack_chart_data=json.dumps(attack_chart_data),
            top_ip_labels=json.dumps(top_ip_labels),
            top_ip_counts=json.dumps(top_ip_counts),
            geographic_distribution_data=(geographic_distribution_data),
            ai_insights=ai_insights,
            ai_alert_notes=ai_alert_notes
        )

    # app.py (inside your create_app function)

    @app.route('/log_attack', methods=['POST'])
    def log_attack():
        """
        Logs a simulated or detected attack into the database.
        Requires JSON data with 'ip_address', 'path', and 'method'.
        Other fields like 'attack_type', 'payload', 'user_agent' are optional.
        """
        data = request.json
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        ip_address = data.get('ip_address')
        path = data.get('path')
        method = data.get('method')

        # Get optional fields. Provide default None if not present.
        attack_type = data.get('attack_type')
        payload = data.get('payload')
        user_agent = data.get('user_agent')
        referer = data.get('referer')
        ai_prediction = data.get('ai_prediction')
        rl_action_taken = data.get('rl_action_taken')
        headers = data.get('headers')
        geolocation_data = data.get('geolocation_data')
        ip_reputation_data = data.get('ip_reputation_data')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        country = data.get('country')
        city = data.get('city')
        attack_vector = data.get('attack_vector') # Make sure to get this if you plan to use it

        # Ensure all REQUIRED fields are present
        if not all([ip_address, path, method]): # <-- ONLY the NOT NULL fields are critical here
            return jsonify({'message': 'Missing required fields (ip_address, path, method)'}), 400

        try:
            attack_log = Attack(
                ip_address=ip_address,
                path=path,
                method=method,
                # Optional fields (set to None if not provided)
                attack_type=attack_type, # This maps to Attack.attack_type in your model
                payload=payload,
                user_agent=user_agent,
                referer=referer,
                ai_prediction=ai_prediction,
                rl_action_taken=rl_action_taken,
                headers=headers,
                geolocation_data=geolocation_data,
                ip_reputation_data=ip_reputation_data,
                latitude=latitude,
                longitude=longitude,
                country=country,
                city=city,
                attack_vector=attack_vector # This maps to Attack.attack_vector in your model
            )
            db.session.add(attack_log)
            db.session.commit()
            return jsonify({'message': 'Attack logged successfully', 'attack_id': attack_log.id}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error logging attack: {e}")
            return jsonify({'message': f'Internal server error: {e}'}), 500



    @app.route("/attack_logs")
    @login_required
    def attack_logs():
        attacks = db.session.execute(db.select(Attack).order_by(Attack.timestamp.desc())).scalars().all()
        return render_template('attack_logs.html', title='Attack Logs', attacks=attacks)

    @app.route("/blocked_ips")
    @login_required
    def blocked_ips():
        blocked_ips = db.session.execute(db.select(BlockedIP).order_by(BlockedIP.blocked_at.desc())).scalars().all()
        return render_template('blocked_ips.html', title='Blocked IPs', blocked_ips=blocked_ips)

    @app.route("/block_ip/<ip_address>", methods=['POST'])
    @login_required
    def block_ip(ip_address):
        existing_block = db.session.execute(db.select(BlockedIP).filter_by(ip_address=ip_address)).scalars().first()
        if not existing_block:
            new_block = BlockedIP(ip_address=ip_address, reason="Manually blocked by admin")
            db.session.add(new_block)
            db.session.commit()
            flash(f'IP {ip_address} has been blocked.', 'success')
        else:
            flash(f'IP {ip_address} is already blocked.', 'info')
        return redirect(url_for('attack_logs'))

    @app.route("/unblock_ip/<ip_address>", methods=['POST'])
    @login_required
    def unblock_ip(ip_address):
        blocked_ip_entry = db.session.execute(db.select(BlockedIP).filter_by(ip_address=ip_address)).scalars().first()
        if blocked_ip_entry:
            db.session.delete(blocked_ip_entry)
            db.session.commit()
            flash(f'IP {ip_address} has been unblocked.', 'success')
        else:
            flash(f'IP {ip_address} was not found in the blocked list.', 'danger')
        return redirect(url_for('blocked_ips'))

    @app.route('/live_attacks_dashboard')
    @login_required
    def live_attacks_dashboard():
        return render_template('live_attacks_dashboard.html', title='Live Attacks Dashboard')

    @app.route('/api/attacks')
    @login_required # Assuming this route is also login_required
    def api_attacks():
        # Adjust timedelta as needed, e.g., to fetch recent attacks for "live" view
        time_frame = datetime.utcnow() - timedelta(minutes=5) # Example: last 5 minutes for live data
        attacks = db.session.execute(
            db.select(Attack)
            .filter(Attack.timestamp >= time_frame) # Filter for recent attacks
            .order_by(Attack.timestamp.desc())
        ).scalars().all()

        attack_data = []
        for attack in attacks:
            attack_data.append({
                'id': attack.id,
                'timestamp': attack.timestamp.isoformat(),
                'ip_address': attack.ip_address,
                'attack_type': attack.attack_type, # Include relevant nullable fields
                'payload': attack.payload,
                'user_agent': attack.user_agent,
                'referer': attack.referer,
                'path': attack.path,
                'method': attack.method,
                'ai_prediction': attack.ai_prediction,
                'rl_action_taken': attack.rl_action_taken,
                'headers': attack.headers, # JsonEncodedDict fields might need special handling if empty
                'geolocation_data': attack.geolocation_data,
                'ip_reputation_data': attack.ip_reputation_data,
                'latitude': attack.latitude,
                'longitude': attack.longitude,
                'country': attack.country,
                'city': attack.city,
                'attack_vector': attack.attack_vector # Include this too if relevant
                # REMOVE OR COMMENT OUT THIS LINE IF Attack model doesn't have 'port':
                # 'port': attack.port,
            })
        return jsonify(attack_data)

    @app.route('/lookup_ip/<ip_address>')
    @login_required
    def lookup_ip(ip_address):
        details = get_ip_details(ip_address)
        return jsonify(details)

    return app

# --- How to run your app ---
if __name__ == '__main__':
    class Config:
        SECRET_KEY = 'your_super_secret_key_for_dev_CHANGE_THIS'
        SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        IPINFO_API_KEY = 'YOUR_IPINFO_API_KEY' # Get one from ipinfo.io - IMPORTANT!

    app_instance = create_app(Config)
    with app_instance.app_context():
        db.create_all()
        if not db.session.execute(db.select(User).filter_by(username='admin')).scalars().first():
            hashed_password = bcrypt.generate_password_hash('admin_password').decode('utf-8')
            admin_user = User(username='admin', email='admin@example.com', password_hash=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user 'admin' created with password 'admin_password'")
    app_instance.run(debug=True)