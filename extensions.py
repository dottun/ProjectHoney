# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_migrate import Migrate
from flask_mail import Mail
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address) # FIX: Add key_func here
migrate = Migrate()
mail = Mail()