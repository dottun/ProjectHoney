# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Optional, NumberRange

class SettingsForm(FlaskForm):
    ipinfo_api_key = StringField('IPinfo API Key', validators=[Optional()])
    rl_detection_threshold = IntegerField('RL Detection Threshold (e.g., 70 for 70%)',
                                            validators=[Optional(), NumberRange(min=0, max=100, message="Threshold must be between 0 and 100")])
    # Add more fields here as you define more settings
    submit = SubmitField('Save Settings')