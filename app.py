from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
from models import db, User, Password, Note
import os, base64, secrets, string, re
from datetime import datetime, timedelta
from functools import wraps

load_dotenv()

# ── App setup ──────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# ── Flask-Mail setup (Gmail) ───────────────────────
app.config['MAIL_SERVER']        = 'smtp.gmail.com'
app.config['MAIL_PORT']          = 587
app.config['MAIL_USE_TLS']       = True
app.config['MAIL_USE_SSL']       = False
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_EMAIL')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_EMAIL')     # your gmail
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # your app password

db.init_app(app)
bcrypt = Bcrypt(app)
mail   = Mail(app)

# Common weak passwords (breach list)
WEAK_PASSWORDS = {
    'password', '123456', 'password123', 'admin', 'letmein',
    'qwerty', 'abc123', 'monkey', 'master', 'dragon',
    '111111', 'iloveyou', 'sunshine', 'welcome', 'login'
}

# ── Encryption helpers ─────────────────────────────
def make_key(master_password, salt):
    """Turn master password into an encryption key using PBKDF2"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def get_cipher():
    """Get encryption object from session key"""
    key = session.get('enc_key')
    if not key:
        raise ValueError('No encryption key in session')
    return Fernet(key.encode())

def encrypt(text):
    return get_cipher().encrypt(text.encode()).decode()

def decrypt(token):
    return get_cipher().decrypt(token.encode()).decode()

# ── OTP helpers ────────────────────────────────────
def generate_otp():
    """Generate a random 6-digit OTP code"""
    return str(secrets.randbelow(900000) + 100000)  # always 6 digits: 100000–999999

def send_otp_email(to_email, otp_code, username):
    """Send the OTP code to the user's email"""
    msg = Message(
        subject = 'VaultAI — Your Login Code',
        sender  = os.getenv('MAIL_EMAIL'),
        recipients = [to_email]
    )
    msg.html = f"""
    <div style="font-family:sans-serif;max-width:420px;margin:auto;padding:32px;
                background:#181510;color:#f0e8d8;border-radius:12px;border:1px solid rgba(255,220,120,0.15)">

      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-flex;align-items:center;gap:10px">
          <span style="font-size:22px">🔐</span>
          <span style="font-size:20px;font-weight:700;color:#e8a820">VaultAI</span>
        </div>
      </div>

      <h2 style="font-size:18px;margin-bottom:8px;color:#f0e8d8">Hi {username},</h2>
      <p style="color:#b8a890;font-size:14px;margin-bottom:24px;line-height:1.6">
        Someone (hopefully you!) is trying to log in to your VaultAI account.
        Use the code below to complete your login.
      </p>

      <div style="text-align:center;margin:28px 0">
        <div style="display:inline-block;background:#0a0906;border:2px solid #e8a820;
                    border-radius:10px;padding:16px 40px">
          <span style="font-size:36px;font-weight:700;letter-spacing:12px;
                        color:#e8a820;font-family:monospace">{otp_code}</span>
        </div>
      </div>

      <p style="color:#b8a890;font-size:13px;text-align:center;margin-bottom:8px">
        ⏰ This code expires in <strong style="color:#f0e8d8">10 minutes</strong>
      </p>
      <p style="color:#6e6050;font-size:12px;text-align:center">
        If you did not request this, please ignore this email.
        Your account is safe.
      </p>

    </div>
    """
    mail.send(msg)

def send_reset_email(to_email, reset_code, username):
    """Send the password reset code to the user's email"""
    msg = Message(
        subject    = 'VaultAI — Reset Your Master Password',
        sender     = os.getenv('MAIL_EMAIL'),
        recipients = [to_email]
    )
    msg.html = f"""
    <div style="font-family:sans-serif;max-width:420px;margin:auto;padding:32px;
                background:#181510;color:#f0e8d8;border-radius:12px;border:1px solid rgba(255,220,120,0.15)">

      <div style="text-align:center;margin-bottom:24px">
        <span style="font-size:20px;font-weight:700;color:#e8a820">🔐 VaultAI</span>
      </div>

      <h2 style="font-size:18px;margin-bottom:8px;color:#f0e8d8">Password Reset Request</h2>
      <p style="color:#b8a890;font-size:14px;margin-bottom:16px;line-height:1.6">
        Hi <strong style="color:#f0e8d8">{username}</strong>, we received a request to reset
        your VaultAI master password. Use the code below.
      </p>

      <div style="background:#2a2200;border:1px solid rgba(212,105,90,0.3);border-radius:8px;
                  padding:12px 16px;margin-bottom:20px">
        <p style="color:#d4695a;font-size:13px;margin:0;line-height:1.5">
          ⚠️ <strong>Important:</strong> Resetting your master password will
          <strong>permanently delete all your saved passwords and notes</strong>
          because they were encrypted with your old password. This cannot be undone.
        </p>
      </div>

      <div style="text-align:center;margin:28px 0">
        <div style="display:inline-block;background:#0a0906;border:2px solid #d4695a;
                    border-radius:10px;padding:16px 40px">
          <span style="font-size:36px;font-weight:700;letter-spacing:12px;
                        color:#d4695a;font-family:monospace">{reset_code}</span>
        </div>
      </div>

      <p style="color:#b8a890;font-size:13px;text-align:center;margin-bottom:8px">
        ⏰ This code expires in <strong style="color:#f0e8d8">15 minutes</strong>
      </p>
      <p style="color:#6e6050;font-size:12px;text-align:center">
        If you did not request this, please ignore this email. Your account is safe.
      </p>
    </div>
    """
    mail.send(msg)


# ── Password strength checker ──────────────────────
def check_strength(password):
    """Check how strong a password is. Returns score 0-4 and feedback."""
    if not password:
        return {'score': 0, 'label': 'Empty', 'color': '#d4695a', 'feedback': 'Enter a password'}

    if password.lower() in WEAK_PASSWORDS:
        return {'score': 0, 'label': 'Breached', 'color': '#d4695a',
                'feedback': 'This password was found in data breaches!', 'breached': True}

    score = 0
    tips  = []

    if len(password) >= 8:  score += 1
    else: tips.append('Use at least 8 characters')

    if len(password) >= 12: score += 1
    else: tips.append('12+ characters is better')

    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        tips.append('Mix uppercase and lowercase')

    if re.search(r'\d', password):
        score += 1
    else:
        tips.append('Add some numbers')

    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
    else:
        tips.append('Add symbols like !@#$')

    score  = min(score, 4)
    labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Excellent']
    colors = ['#d4695a', '#d49a3a', '#d49a3a', '#6db98c', '#e8a820']

    return {
        'score':    score,
        'label':    labels[score],
        'color':    colors[score],
        'feedback': ' | '.join(tips) if tips else 'Great password!',
        'breached': False
    }

# ── Password generator ─────────────────────────────
def generate_password(length=16):
    """Generate a random secure password"""
    chars    = string.ascii_letters + string.digits + '!@#$%^&*()'
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice('!@#$%^&*()')
    ]
    for _ in range(length - 4):
        password.append(secrets.choice(chars))
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

# ── Login required decorator ───────────────────────
def login_required(f):
    @wraps(f)
    def check(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return check

# ══════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ── Register ───────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email    = request.form['email'].strip()
        password = request.form['password']
        confirm  = request.form['confirm']

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        if check_strength(password)['score'] < 2:
            flash('Password is too weak. Make it stronger.', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')

        salt   = os.urandom(32)
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user   = User(username=username, email=email, password=hashed, salt=salt)
        db.session.add(user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ── Step 1: Login — check password ────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip()
        password   = request.form['password']

        # Find user by username or email
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        # Check if password is correct
        if not user or not bcrypt.check_password_hash(user.password, password):
            flash('Wrong username or password.', 'error')
            return render_template('login.html')

        # Password is correct — now generate and send OTP
        otp = generate_otp()

        # Save OTP to database with 10-minute expiry
        user.otp_code    = otp
        user.otp_expires = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

        # Store info in session temporarily (not logged in yet!)
        session['otp_user_id']  = user.id
        session['otp_password'] = password  # needed to make encryption key after OTP

        # Send OTP email
        try:
            send_otp_email(user.email, otp, user.username)
        except Exception as e:
            flash(f'Could not send OTP email. Check your .env file. Error: {str(e)}', 'error')
            return render_template('login.html')

        # Go to OTP verification page
        return redirect(url_for('verify_otp'))

    return render_template('login.html')


# ── Step 2: Verify OTP ─────────────────────────────
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Make sure the user came from login step
    if 'otp_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        user        = User.query.get(session['otp_user_id'])

        if not user:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))

        # Check if OTP has expired
        if datetime.utcnow() > user.otp_expires:
            flash('OTP has expired. Please log in again.', 'error')
            session.pop('otp_user_id', None)
            session.pop('otp_password', None)
            return redirect(url_for('login'))

        # Check if OTP matches
        if entered_otp != user.otp_code:
            flash('Wrong OTP code. Try again.', 'error')
            return render_template('verify_otp.html', email=user.email)

        # OTP is correct! Now fully log the user in
        password = session.pop('otp_password')
        enc_key  = make_key(password, user.salt)

        # Clear OTP from database so it can't be reused
        user.otp_code    = None
        user.otp_expires = None
        db.session.commit()

        # Clear temp session, set real session
        session.pop('otp_user_id', None)
        session.permanent  = True
        session['user_id']  = user.id
        session['username'] = user.username
        session['enc_key']  = enc_key.decode()

        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))

    # GET request — show OTP form
    user = User.query.get(session['otp_user_id'])
    return render_template('verify_otp.html', email=user.email)


# ── Resend OTP ─────────────────────────────────────
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'otp_user_id' not in session:
        return jsonify({'ok': False, 'msg': 'Session expired'})

    user = User.query.get(session['otp_user_id'])
    if not user:
        return jsonify({'ok': False, 'msg': 'User not found'})

    # Generate a new OTP
    otp              = generate_otp()
    user.otp_code    = otp
    user.otp_expires = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()

    try:
        send_otp_email(user.email, otp, user.username)
        return jsonify({'ok': True, 'msg': 'New OTP sent to your email!'})
    except Exception as e:
        return jsonify({'ok': False, 'msg': f'Failed to send: {str(e)}'})



# ══════════════════════════════════════════════════
# FORGOT PASSWORD — 3 step flow
# Step 1: Enter email  →  /forgot-password
# Step 2: Enter OTP    →  /forgot-verify
# Step 3: Set new pass →  /forgot-reset
# NOTE: Old vault data is cleared because it was
#       encrypted with the old master password key
# ══════════════════════════════════════════════════

# ── Step 1: Enter email ────────────────────────────
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()

        # Find the user by email
        user = User.query.filter_by(email=email).first()

        # Always show the same message (security: don't reveal if email exists)
        if not user:
            flash('If that email is registered, a reset code has been sent.', 'success')
            return render_template('forgot_password.html')

        # Generate a 6-digit reset code
        reset_code = generate_otp()

        # Save reset code with 15 minute expiry
        user.reset_code    = reset_code
        user.reset_expires = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

        # Send reset email
        try:
            send_reset_email(user.email, reset_code, user.username)
        except Exception as e:
            flash(f'Could not send email. Check your .env settings. Error: {str(e)}', 'error')
            return render_template('forgot_password.html')

        # Store email in session for next step
        session['reset_email'] = user.email
        flash('Reset code sent! Check your email.', 'success')
        return redirect(url_for('forgot_verify'))

    return render_template('forgot_password.html')


# ── Step 2: Verify reset OTP ───────────────────────
@app.route('/forgot-verify', methods=['GET', 'POST'])
def forgot_verify():
    # Must come from step 1
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered = request.form['otp'].strip()
        email   = session.get('reset_email')
        user    = User.query.filter_by(email=email).first()

        if not user:
            flash('Session expired. Please try again.', 'error')
            return redirect(url_for('forgot_password'))

        # Check if code expired
        if not user.reset_expires or datetime.utcnow() > user.reset_expires:
            flash('Reset code has expired. Please request a new one.', 'error')
            session.pop('reset_email', None)
            return redirect(url_for('forgot_password'))

        # Check if code matches
        if entered != user.reset_code:
            flash('Wrong code. Please try again.', 'error')
            return render_template('forgot_verify.html', email=email)

        # Code is correct — let them set new password
        session['reset_verified_email'] = email
        session.pop('reset_email', None)
        return redirect(url_for('forgot_reset'))

    email = session.get('reset_email', '')
    return render_template('forgot_verify.html', email=email)


# ── Resend reset code ──────────────────────────────
@app.route('/resend-reset', methods=['POST'])
def resend_reset():
    email = session.get('reset_email')
    if not email:
        return jsonify({'ok': False, 'msg': 'Session expired'})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'ok': False, 'msg': 'User not found'})

    # Generate fresh code
    reset_code         = generate_otp()
    user.reset_code    = reset_code
    user.reset_expires = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    try:
        send_reset_email(user.email, reset_code, user.username)
        return jsonify({'ok': True, 'msg': 'New reset code sent!'})
    except Exception as e:
        return jsonify({'ok': False, 'msg': f'Failed to send: {str(e)}'})


# ── Step 3: Set new master password ───────────────
@app.route('/forgot-reset', methods=['GET', 'POST'])
def forgot_reset():
    # Must come from step 2
    if 'reset_verified_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm      = request.form['confirm']
        email        = session.get('reset_verified_email')

        # Validate new password
        if new_password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('forgot_reset.html')

        if check_strength(new_password)['score'] < 2:
            flash('Password is too weak. Please make it stronger.', 'error')
            return render_template('forgot_reset.html')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Something went wrong. Please try again.', 'error')
            return redirect(url_for('forgot_password'))

        # ── IMPORTANT: Clear all old encrypted data ──
        # The old passwords and notes were encrypted with
        # a key derived from the OLD master password.
        # With a new master password → new key → old data
        # is permanently unreadable → so we delete it cleanly.
        Password.query.filter_by(user_id=user.id).delete()
        Note.query.filter_by(user_id=user.id).delete()

        # Set new master password and new salt
        new_salt = os.urandom(32)
        user.password      = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.salt          = new_salt
        user.reset_code    = None
        user.reset_expires = None
        db.session.commit()

        # Clean session
        session.pop('reset_verified_email', None)

        flash('Password reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_reset.html')


# ── Logout ─────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


# ── Dashboard ──────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    user    = User.query.get(session['user_id'])
    entries = Password.query.filter_by(user_id=user.id).order_by(
        Password.is_favorite.desc(), Password.created_at.desc()
    ).all()

    passwords = []
    for e in entries:
        try:
            passwords.append({
                'id':          e.id,
                'site_name':   e.site_name,
                'site_url':    e.site_url or '',
                'username':    decrypt(e.username),
                'password':    decrypt(e.password),
                'category':    e.category,
                'strength':    e.strength,
                'is_favorite': e.is_favorite,
                'created_at':  e.created_at.strftime('%b %d, %Y')
            })
        except:
            continue

    stats = {
        'total':     len(passwords),
        'strong':    sum(1 for p in passwords if p['strength'] >= 3),
        'weak':      sum(1 for p in passwords if p['strength'] <= 1),
        'favorites': sum(1 for p in passwords if p['is_favorite']),
    }

    categories = sorted(set(p['category'] for p in passwords))

    return render_template('dashboard.html',
                           user=user,
                           passwords=passwords,
                           stats=stats,
                           categories=categories)


# ── Add password ───────────────────────────────────
@app.route('/add', methods=['POST'])
@login_required
def add_password():
    data      = request.get_json()
    site_name = data.get('site_name', '').strip()
    username  = data.get('username', '').strip()
    password  = data.get('password', '')

    if not site_name or not username or not password:
        return jsonify({'ok': False, 'msg': 'All fields are required'})

    entry = Password(
        user_id   = session['user_id'],
        site_name = site_name,
        site_url  = data.get('site_url', '').strip(),
        username  = encrypt(username),
        password  = encrypt(password),
        category  = data.get('category', 'General'),
        strength  = check_strength(password)['score']
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Password saved!'})


# ── Edit password ──────────────────────────────────
@app.route('/edit/<int:pid>', methods=['PUT'])
@login_required
def edit_password(pid):
    entry = Password.query.filter_by(id=pid, user_id=session['user_id']).first()
    if not entry:
        return jsonify({'ok': False, 'msg': 'Not found'})

    data = request.get_json()
    if 'site_name' in data: entry.site_name = data['site_name']
    if 'site_url'  in data: entry.site_url  = data['site_url']
    if 'category'  in data: entry.category  = data['category']
    if 'username'  in data: entry.username  = encrypt(data['username'])
    if 'password'  in data:
        entry.password = encrypt(data['password'])
        entry.strength = check_strength(data['password'])['score']

    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Updated!'})


# ── Delete password ────────────────────────────────
@app.route('/delete/<int:pid>', methods=['DELETE'])
@login_required
def delete_password(pid):
    entry = Password.query.filter_by(id=pid, user_id=session['user_id']).first()
    if not entry:
        return jsonify({'ok': False, 'msg': 'Not found'})

    db.session.delete(entry)
    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Deleted!'})


# ── Toggle favorite ────────────────────────────────
@app.route('/favorite/<int:pid>', methods=['POST'])
@login_required
def toggle_favorite(pid):
    entry = Password.query.filter_by(id=pid, user_id=session['user_id']).first()
    if not entry:
        return jsonify({'ok': False})

    entry.is_favorite = not entry.is_favorite
    db.session.commit()
    return jsonify({'ok': True, 'is_favorite': entry.is_favorite})


# ── Check password strength (API) ─────────────────
@app.route('/check-strength', methods=['POST'])
@login_required
def check_strength_api():
    password = request.get_json().get('password', '')
    return jsonify(check_strength(password))


# ── Generate password (API) ────────────────────────
@app.route('/generate', methods=['POST'])
@login_required
def generate():
    data   = request.get_json()
    length = int(data.get('length', 16))
    pwd    = generate_password(length)
    return jsonify({'password': pwd, 'strength': check_strength(pwd)})


# ── Notes page ─────────────────────────────────────
@app.route('/notes')
@login_required
def notes():
    """Show all notes for this user"""
    user       = User.query.get(session['user_id'])
    all_notes  = Note.query.filter_by(user_id=user.id).order_by(Note.updated_at.desc()).all()

    # Decrypt each note's content
    notes_list = []
    for n in all_notes:
        try:
            notes_list.append({
                'id':         n.id,
                'title':      n.title,
                'content':    decrypt(n.content),
                'color':      n.color,
                'created_at': n.created_at.strftime('%b %d, %Y'),
                'updated_at': n.updated_at.strftime('%b %d, %Y  %I:%M %p'),
            })
        except:
            continue

    return render_template('notes.html', user=user, notes=notes_list)


# ── Add note ────────────────────────────────────────
@app.route('/notes/add', methods=['POST'])
@login_required
def add_note():
    data    = request.get_json()
    title   = data.get('title', '').strip()
    content = data.get('content', '').strip()
    color   = data.get('color', 'yellow')

    if not title:
        return jsonify({'ok': False, 'msg': 'Title is required'})

    note = Note(
        user_id = session['user_id'],
        title   = title,
        content = encrypt(content) if content else encrypt(''),
        color   = color
    )
    db.session.add(note)
    db.session.commit()

    return jsonify({'ok': True, 'msg': 'Note saved!', 'id': note.id})


# ── Edit note ───────────────────────────────────────
@app.route('/notes/edit/<int:nid>', methods=['PUT'])
@login_required
def edit_note(nid):
    note = Note.query.filter_by(id=nid, user_id=session['user_id']).first()
    if not note:
        return jsonify({'ok': False, 'msg': 'Note not found'})

    data = request.get_json()
    if 'title'   in data: note.title   = data['title'].strip()
    if 'content' in data: note.content = encrypt(data['content'])
    if 'color'   in data: note.color   = data['color']

    note.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Note updated!'})


# ── Delete note ─────────────────────────────────────
@app.route('/notes/delete/<int:nid>', methods=['DELETE'])
@login_required
def delete_note(nid):
    note = Note.query.filter_by(id=nid, user_id=session['user_id']).first()
    if not note:
        return jsonify({'ok': False, 'msg': 'Note not found'})

    db.session.delete(note)
    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Note deleted!'})


# ── Database Viewer (show to teacher) ─────────────
@app.route('/db-viewer')
def db_viewer():
    """Shows all database tables in a nice visual table"""

    # Get all users
    users = User.query.all()
    user_rows = []
    for u in users:
        user_rows.append({
            'id':       u.id,
            'username': u.username,
            'email':    u.email,
            'password': u.password[:35] + '...',
            'salt':     '[32 random bytes]',
            'otp_code': u.otp_code or 'None',
        })

    # Get all passwords
    passwords = Password.query.all()
    pw_rows = []
    for p in passwords:
        pw_rows.append({
            'id':          p.id,
            'user_id':     p.user_id,
            'site_name':   p.site_name,
            'site_url':    p.site_url or '',
            'username':    p.username[:35] + '...',
            'password':    p.password[:35] + '...',
            'category':    p.category,
            'strength':    p.strength,
            'is_favorite': p.is_favorite,
            'created_at':  p.created_at.strftime('%Y-%m-%d %H:%M'),
        })

    # Get all notes
    notes = Note.query.all()
    note_rows = []
    for n in notes:
        note_rows.append({
            'id':         n.id,
            'user_id':    n.user_id,
            'title':      n.title,
            'content':    n.content[:35] + '...',   # encrypted content
            'color':      n.color,
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M'),
            'updated_at': n.updated_at.strftime('%Y-%m-%d %H:%M'),
        })

    return render_template('db_viewer.html',
                           users=user_rows,
                           passwords=pw_rows,
                           notes=note_rows)


# Creates DB tables when Render starts the app
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
