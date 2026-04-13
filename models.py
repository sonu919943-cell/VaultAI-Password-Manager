from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# User table - stores account info
class User(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(80), unique=True, nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password    = db.Column(db.String(255), nullable=False)  # bcrypt hashed
    salt        = db.Column(db.LargeBinary(32), nullable=False)  # for encryption key

    # OTP fields — for two-factor authentication on login
    otp_code    = db.Column(db.String(6),   nullable=True)
    otp_expires = db.Column(db.DateTime,    nullable=True)

    # Password reset fields — for forgot password flow
    reset_code    = db.Column(db.String(6), nullable=True)   # 6-digit reset OTP
    reset_expires = db.Column(db.DateTime,  nullable=True)   # when reset code expires

# Note table - stores encrypted user notes
class Note(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title      = db.Column(db.String(200), nullable=False)       # plain title
    content    = db.Column(db.Text, nullable=False)              # encrypted content
    color      = db.Column(db.String(20), default='yellow')      # card color
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Password table - stores saved passwords
class Password(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site_name    = db.Column(db.String(100), nullable=False)
    site_url     = db.Column(db.String(200))
    username     = db.Column(db.Text, nullable=False)   # encrypted
    password     = db.Column(db.Text, nullable=False)   # encrypted
    category     = db.Column(db.String(50), default='General')
    strength     = db.Column(db.Integer, default=0)     # 0 to 4
    is_favorite  = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)