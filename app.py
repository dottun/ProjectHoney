# app.py
import json
import logging
import os
import threading # For non-blocking emails
from datetime import datetime, timedelta
# from jinja2 import Environment, FileSystemLoader # This import is not strictly needed for Flask apps

from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message # Import Message from Flask-Mail
from flask_limiter.errors import RateLimitExceeded # Import RateLimitExceeded error

# Import extensions and configurations
from extensions import db, bcrypt, login_manager, limiter, migrate, mail
from config import Config # Import Config from config.py

# Import honeypot-related functions and classes from honeypot.py
# Make sure honeypot.py is in the same directory as app.py
from honeypot import (
    honeypot_trap, check_ip_reputation, get_geolocation_data,
    block_ip, detect_and_log_attack, is_ip_blocked, unblock_ip,
    init_honeypot_models
)

# Import database models
# Make sure models.py is in the same directory as app.py
from models import User, Attack, BlockedIP

# --- Application Factory Function ---
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class) # Load configuration from Config class

    # Initialize extensions with the app instance
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'

    # --- Logging Configuration ---
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                        handlers=[
                            logging.FileHandler("app.log"), # Log to file
                            logging.StreamHandler()        # Log to console
                        ])
    app.logger.setLevel(logging.INFO)
    app.logger.info("Application starting up...")

    # --- Flask-Login User Loader ---
    @login_manager.user_loader
    def load_user(user_id):
        # This function loads a user from the database given their ID.
        # Required by Flask-Login.
        return User.query.get(int(user_id))

    # Context processor to make current_user available in all templates
    @app.context_processor
    def inject_user():
        return dict(current_user=current_user)

    # Set up application-wide Jinja2 globals
    with app.app_context():
        app.jinja_env.globals['my_app_name'] = "AI Honeypot System"
        app.jinja_env.globals['current_year'] = datetime.now().year
        # If you want to expose a function:
        # app.jinja_env.globals['get_env_var'] = os.getenv

    # --- Email Alert Functions ---
    def send_async_email(app_context, msg):
        """Helper to send email in a separate thread."""
        with app_context:
            try:
                mail.send(msg)
                app.logger.info(f"Email sent to {msg.recipients}")
            except Exception as e:
                app.logger.error(f"Failed to send email: {e}")

    def send_alert_email(subject, body, recipient_email=None):
        """Sends an email alert to the admin or specified recipient."""
        if not app.config.get('MAIL_SERVER') or not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
            app.logger.warning("Email server credentials not fully configured. Skipping email alert.")
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


    # --- Before Request Hook for IP Blocking ---
    @app.before_request
    def check_global_ip_block():
        """Checks if the incoming IP is globally blocked before processing the request."""
        user_ip = request.remote_addr
        if is_ip_blocked(user_ip):
            app.logger.warning(f"Globally blocked IP {user_ip} attempted access before request.")
            flash('Your IP address has been temporarily blocked due to suspicious activity.', 'danger')
            return render_template('blocked.html'), 403

    # --- Error Handlers ---
    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Handles rate limit exceeded errors (HTTP 429)."""
        user_ip = request.remote_addr
        app.logger.warning(f"Rate limit exceeded for IP: {user_ip}. Limit: {e.description}")
        flash('You have made too many requests. Please try again later.', 'danger')
        return render_template('blocked.html', message="You have made too many requests. Please try again later."), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        """Handles internal server errors (HTTP 500)."""
        app.logger.error(f"500 Internal Server Error: {e}", exc_info=True)
        db.session.rollback() # Rollback session in case of a database error
        return render_template('500.html'), 500

    @app.errorhandler(404)
    def page_not_found(e):
        """Handles 404 Not Found errors, logs them as potential probes."""
        user_ip = request.remote_addr
        ip_reputation = check_ip_reputation(user_ip, app.logger)
        request_data = {
            'ip_address': user_ip,
            'user_agent': request.headers.get('User-Agent', ''),
            'path': request.path,
            'method': request.method,
            'payload': '',
            'referer': request.headers.get('Referer', '')
        }
        app.logger.warning(f"404 Not Found triggered for path: {request.path} from {user_ip}")
        # Fetch geolocation data before calling detect_and_log_attack
        geolocation = get_geolocation_data(user_ip, app.logger, app.config.get('IPINFO_API_KEY'))
        ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation, geolocation) 

        if rl_action_taken == "block": # Note: honeypot.py returns "block" not "block_ip"
            block_ip(user_ip, duration_minutes=30)
            return render_template('blocked.html'), 403
        elif rl_action_taken == "redirect_to_fake_page":
            return redirect(url_for('fake_page')) # Using 'fake_page' as a generic redirect
        elif rl_action_taken == "serve_fake_error":
            return render_template('fake_error.html'), 500
        
        return render_template('404.html'), 404

    # --- Application Routes (All existing routes moved here before the return statement) ---

    # Your root route
    @app.route('/')
    def index(): # Renamed from my_route to be more generic for the root
        # No need to pass 'globals' here, my_app_name and current_year are already available globally
        return render_template('index.html') # Assuming 'index.html' is your main landing page

    # Your home route (as previously defined, but now correctly structured)
    @app.route("/home")
    def home():
        """Home page, redirects authenticated users to dashboard."""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        # my_app_name and current_year are automatically available in home.html
        return render_template('home.html', title='Home')

    @app.route("/login", methods=['GET', 'POST'])
    @limiter.limit("5 per minute") # Rate limit login attempts
    def login():
        """Handles user login attempts."""
        if current_user.is_authenticated:
            app.logger.info(f"Authenticated user {current_user.username} tried to access /login, redirecting to dashboard.")
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            remember_me = request.form.get('remember_me') == 'on' # Check if 'remember me' checkbox was ticked

            user = User.query.filter_by(username=username).first()

            if user and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user, remember=remember_me)
                app.logger.info(f"Successful login for user: {username} from IP: {request.remote_addr}")
                flash('Logged in successfully!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid username or password. Please try again.', 'danger')
                ip_address = request.remote_addr
                user_agent = request.headers.get('User-Agent')
                payload = f"Failed login attempt for username: {username}"
                request_data = {
                    'ip_address': ip_address,
                    'path': request.path,
                    'method': request.method,
                    'headers': dict(request.headers),
                    'payload': payload,
                    'user_agent': user_agent,
                    'referer': request.headers.get('Referer')
                }
                # Call detect_and_log_attack directly here for failed login attempts
                with app.app_context():
                    # Fetch geolocation data before calling detect_and_log_attack
                    geolocation = get_geolocation_data(ip_address, app.logger, app.config.get('IPINFO_API_KEY'))
                    detect_and_log_attack(request_data, ip_address, check_ip_reputation(ip_address, app.logger), geolocation)
        return render_template('login.html', title='Login')

    @app.route("/register", methods=['GET', 'POST'])
    def register():
        """Handles user registration."""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html')

            existing_user = User.query.filter_by(username=username).first()
            existing_email = User.query.filter_by(email=email).first()

            if existing_user:
                flash('Username already exists. Please choose a different one.', 'danger')
            elif existing_email:
                flash('Email already registered. Please use a different email.', 'danger')
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(username=username, email=email, password_hash=hashed_password, is_admin=False)
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
        return render_template('register.html', title='Register')

    @app.route("/logout")
    @login_required
    def logout():
        """Logs out the current user."""
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('home'))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """User dashboard, showing basic info."""
        # Get the IP address of the current user
        user_ip = request.remote_addr
        # Fetch geolocation data for the current user's IP
        geolocation = get_geolocation_data(user_ip, app.logger, app.config.get('IPINFO_API_KEY'))
        # Fetch IP reputation data for the current user's IP
        ip_reputation = check_ip_reputation(user_ip, app.logger) # Pass app.logger as per honeypot.py signature
        return render_template('dashboard.html', title='Dashboard', geolocation=geolocation, ip_reputation=ip_reputation)

    @app.route('/attack_logs')
    @login_required
    def attack_logs():
        """Displays a list of attack logs (admin only)."""
        if not current_user.is_admin:
            flash('You do not have permission to view this page.', 'danger')
            return redirect(url_for('dashboard'))

        all_attacks = Attack.query.order_by(Attack.timestamp.desc()).all()
        return render_template('attack_logs.html', title='Attack Logs', all_attacks=all_attacks)


    @app.route('/admin_dashboard', methods=['GET', 'POST'])
    @login_required
    def admin_dashboard():
        """Admin dashboard, showing analytics and management tools."""
        if not current_user.is_admin:
            flash('You do not have permission to view the admin dashboard.', 'danger')
            return redirect(url_for('dashboard'))

        # Placeholder for POST request handling (e.g., manual_block_ip)
        if request.method == 'POST':
            ip_to_block = request.form.get('ip_address')
            block_reason = request.form.get('reason', 'Manual Admin Block')
            if ip_to_block:
                block_ip(ip_to_block, duration_minutes=1440, reason=block_reason) # Block for 24 hours
                flash(f'IP {ip_to_block} has been manually blocked.', 'success')
            else:
                flash('No IP address provided for manual blocking.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Fetch dashboard data
        users = User.query.all()
        active_blocked_ips_db = BlockedIP.query.filter(BlockedIP.blocked_until > datetime.utcnow()).all()

        total_interactions = Attack.query.count()
        # Ensure `distinct` is imported if used (already covered in my global suggestion, but good to double check)
        from sqlalchemy import distinct # Added here if not globally imported
        unique_ips = db.session.query(Attack.ip_address).distinct().count() # Corrected usage if `distinct` is needed.
        total_alerts = db.session.query(Attack).filter(
            (Attack.ai_prediction == 'Malicious') | (Attack.rl_action_taken == 'block')
        ).count()

        now = datetime.utcnow()
        one_day_ago = now - timedelta(days=1)

        # Ensure `func` is imported from `sqlalchemy` if you use it for strftime
        from sqlalchemy import func # <-- Added this for clarity if missing.
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

        all_attack_ips = db.session.query(Attack.ip_address).filter(Attack.timestamp >= one_day_ago).all()

        country_counts = {}
        for ip_row in all_attack_ips:
            # Need to call get_geolocation_data for each IP to get country
            geo_data = get_geolocation_data(ip_row.ip_address, app.logger, app.config.get('IPINFO_API_KEY'))
            country = geo_data.get('country', 'Unknown')
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
        geographic_distribution_data = geographic_distribution_data[:5] # Limit to top 5 for display


        # Data for AI Functions/Insights
        ai_prediction_counts = db.session.query(
            Attack.ai_prediction,
            func.count(Attack.id)
        ).filter(Attack.timestamp >= one_day_ago).group_by(
            Attack.ai_prediction
        ).all()

        rl_action_counts = db.session.query(
            Attack.rl_action_taken,
            func.count(Attack.id)
        ).filter(Attack.timestamp >= one_day_ago).group_by(
            Attack.rl_action_taken
        ).all()

        ai_insights = {}
        for pred, count in ai_prediction_counts:
            ai_insights[f"Predicted {pred.capitalize()} Attacks"] = count

        for action, count in rl_action_counts:
            if action == 'block': # Your RL agent returns "block", not "block_ip"
                ai_insights[f"RL Blocked {count} IPs"] = count
            elif action == 'log':
                ai_insights[f"RL Logged {count} Attacks"] = count
            # Add other actions like redirect_to_fake_page, serve_fake_error here too

        recent_ai_alerts = db.session.query(Attack).filter(
            (Attack.ai_prediction == 'Malicious') | (Attack.rl_action_taken == 'block')
        ).order_by(Attack.timestamp.desc()).limit(3).all()

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
            ai_insights=ai_insights,
            ai_alert_notes=ai_alert_notes
        )


    @app.route("/admin/unblock_ip", methods=['POST'])
    @login_required
    def admin_unblock_ip():
        """Admin function to manually unblock an IP."""
        if not current_user.is_admin:
            flash('Access Denied. Admins only.', 'danger')
            return redirect(url_for('dashboard'))

        ip_to_unblock = request.form.get('ip_address')
        if ip_to_unblock:
            unblock_ip(ip_to_unblock) # Call the function from honeypot.py
            flash(f'IP {ip_to_unblock} has been unblocked.', 'success')
            app.logger.info(f"Admin {current_user.username} unblocked IP: {ip_to_unblock}")
        else:
            flash('No IP address provided for unblocking.', 'danger')

        return redirect(url_for('admin_dashboard'))


    # --- Honeypot Trap Routes (Lures) ---
    # These routes are intentionally vulnerable or designed to attract attackers
    
    @app.route("/wp-login.php")
    @honeypot_trap # Apply the honeypot decorator
    def wordpress_login_honeypot():
        """Simulates a WordPress login page."""
        return render_template('honeypot_pages/wordpress_login.html', title='WordPress Login')

    @app.route("/phpmyadmin")
    @honeypot_trap
    def phpmyadmin_honeypot():
        """Simulates a phpMyAdmin login page."""
        return render_template('honeypot_pages/phpmyadmin.html', title='phpMyAdmin')

    @app.route("/admin.php")
    @honeypot_trap
    def admin_panel_honeypot():
        """Simulates a generic admin panel."""
        return render_template('honeypot_pages/admin_panel.html', title='Admin Panel')

    @app.route("/.env")
    @honeypot_trap
    def env_file_honeypot():
        """Simulates an accessible .env file to log attempts."""
        app.logger.warning(f"Honeypot Lure Hit: .env file probe from {request.remote_addr}")
        return "DB_HOST=localhost\nDB_USER=root\nDB_PASS=password123\n", 200

    @app.route("/search", methods=['GET', 'POST'])
    @honeypot_trap
    def search_honeypot():
        """Simulates a search endpoint that might be vulnerable to SQLi/XSS."""
        query = request.args.get('q') or request.form.get('q')
        if query:
            app.logger.warning(f"Honeypot Lure Hit: Search probe with query '{query}' from {request.remote_addr}")
            return f"Search results for: {query}", 200
        return render_template('honeypot_pages/search.html', title='Search')

    @app.route("/api/v1/user", methods=['GET', 'POST', 'PUT', 'DELETE'])
    @app.route("/api/v1/user/<username>", methods=['GET', 'POST', 'PUT', 'DELETE'])
    @honeypot_trap
    def api_user_honeypot(username=None):
        """Simulates a REST API user endpoint."""
        app.logger.warning(f"Honeypot Lure Hit: API probe for user {username} from {request.remote_addr} with method {request.method}")
        return jsonify({"user": username, "status": "active", "message": "API endpoint for user info."}), 200

    @app.route("/report_attack", methods=['POST'])
    def report_attack():
        """Endpoint to receive attack reports from other honeypot instances."""
        if not request.is_json:
            return jsonify({"message": "Request must be JSON"}), 400

        data = request.get_json()
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

        geolocation = get_geolocation_data(ip_address, app.logger, app.config['IPINFO_API_KEY'])
        ip_reputation = check_ip_reputation(ip_address, app.logger)

        attack_data_for_ai = {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'path': path,
            'method': method,
            'payload': payload
        }
        ai_prediction, rl_action_taken = detect_and_log_attack(attack_data_for_ai, ip_address, ip_reputation, geolocation)

        app.logger.info(f"Received and logged attack from {ip_address} ({attack_vector}). AI: {ai_prediction}, RL Action: {rl_action_taken}")

        return jsonify({"message": "Attack reported successfully", "ai_prediction": ai_prediction, "rl_action": rl_action_taken}), 200

    @app.route("/forgot_password")
    def forgot_password():
        """Placeholder for forgot password page."""
        return render_template('forgot_password.html', title='Forgot Password')

    # --- Deception/Blocked Pages ---
    @app.route("/fake_page")
    def fake_page():
        """A generic deceptive page for redirects."""
        return render_template('honeypot_pages/fake_page.html', title='Fake Page')

    @app.route("/fake_login_page", methods=['GET', 'POST'])
    def fake_login_page():
        """Renders a deceptive login page to capture attacker credentials."""
        if request.method == 'POST':
            user_ip = request.remote_addr
            username_attempt = request.form.get('username', 'N/A')
            password_attempt = request.form.get('password', 'N/A')

            app.logger.warning(f"Fake Login Page Interaction: IP={user_ip}, User: {username_attempt}, Pass: {password_attempt}")

            ip_reputation = check_ip_reputation(user_ip, app.logger)
            geolocation = get_geolocation_data(user_ip, app.logger, app.config['IPINFO_API_KEY'])

            request_data = {
                'ip_address': user_ip,
                'user_agent': request.headers.get('User-Agent', ''),
                'path': request.path,
                'method': request.method,
                'payload': json.dumps({'username': username_attempt, 'password': password_attempt}),
                'referer': request.headers.get('Referer', '')
            }

            ai_prediction, rl_action_taken = detect_and_log_attack(request_data, user_ip, ip_reputation, geolocation)
            
            flash("Login failed. Please try again.", 'danger')
            return render_template('fake_error.html', title='Error') # Redirect to fake error or similar

        response = make_response(render_template('honeypot_pages/fake_login_page.html', title='System Login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    @app.route("/fake_error")
    def fake_error():
        """A generic deceptive error page."""
        flash('An internal error occurred (simulated honeypot response).', 'danger')
        return render_template('fake_error.html', title='Simulated Error')

    @app.route("/blocked")
    def blocked():
        """Displays a page indicating that the user's IP has been blocked."""
        return render_template('blocked.html', title='Access Blocked')

    # Return the app instance at the very end of the function
    return app


# --- GLOBAL APP INSTANCE (outside the function) ---
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
    # Database and Model Initialization (MOVED HERE - after app is created)
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            admin_password_hash = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
            default_admin = User(username='admin', email='admin@example.com', password_hash=admin_password_hash, is_admin=True)
            db.session.add(default_admin)
            db.session.commit()
            app.logger.info("Default admin user created.")
        else:
            app.logger.info("Existing users found. Skipping default admin creation.")

        init_honeypot_models(app.logger)
        app.logger.info("Honeypot AI/RL models initialized.")