# ============================================================
#   SECURE LOGIN SYSTEM - app.py
#   Features: bcrypt hashing, input validation, sessions, 2FA
# ============================================================

from flask import (Flask, render_template, request,
                   redirect, url_for, session, flash)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode
import io
import base64
import re
import sqlite3
from database import init_db, get_db
from datetime import datetime

app = Flask(__name__)

# ── Secret key for session encryption ────────────────────────
app.secret_key = "CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION"

# ── Flask-Bcrypt for password hashing ────────────────────────
bcrypt = Bcrypt(app)

# ── Rate limiter — prevent brute-force attacks ────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ── Initialize DB on startup ──────────────────────────────────
init_db()

# ============================================================
#   INPUT VALIDATION HELPERS
# ============================================================

def validate_username(username):
    """
    Only allow letters, numbers, underscores (3-20 chars).
    This prevents SQL injection and XSS via username field.
    """
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_email(email):
    """Basic email format validation."""
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,}$', email))

def validate_password(password):
    """
    Password must be:
    - At least 8 characters
    - Has uppercase, lowercase, number, and symbol
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain an uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain a lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain a number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain a symbol (!@#$...)"
    return True, "OK"

# ============================================================
#   ROUTES
# ============================================================

# ── Home ──────────────────────────────────────────────────────
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ── Register ──────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        enable_2fa = request.form.get('enable_2fa') == 'on'

        # ── Input Validation ──────────────────────────────
        if not validate_username(username):
            flash("Username: 3-20 chars, letters/numbers/underscore only.", "error")
            return render_template('register.html')

        if not validate_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template('register.html')

        pw_ok, pw_msg = validate_password(password)
        if not pw_ok:
            flash(pw_msg, "error")
            return render_template('register.html')

        # ── Hash password with bcrypt ─────────────────────
        # bcrypt automatically adds a salt — safe against rainbow table attacks
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # ── 2FA Setup ─────────────────────────────────────
        totp_secret = None
        qr_code_b64 = None
        if enable_2fa:
            totp_secret = pyotp.random_base32()   # Generate TOTP secret
            totp = pyotp.TOTP(totp_secret)
            uri  = totp.provisioning_uri(
                name=email,
                issuer_name="SecureLoginApp"
            )
            # Generate QR code as base64 image
            img = qrcode.make(uri)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qr_code_b64 = base64.b64encode(buf.getvalue()).decode()

        # ── Save to DB using parameterized query ──────────
        # Parameterized queries prevent SQL injection completely
        try:
            conn = get_db()
            conn.execute(
                """INSERT INTO users (username, email, password, totp_secret, is_2fa_enabled)
                   VALUES (?, ?, ?, ?, ?)""",
                (username, email, hashed_pw, totp_secret, 1 if enable_2fa else 0)
            )
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")
            return render_template('register.html')

        if enable_2fa:
            flash("Account created! Scan the QR code with Google Authenticator.", "success")
            return render_template('register.html', qr_code=qr_code_b64, show_qr=True)

        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# ── Login ─────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")   # Brute-force protection
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Basic validation
        if not username or not password:
            flash("Please fill in all fields.", "error")
            return render_template('login.html')

        # ── Fetch user with parameterized query ───────────
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # ── Verify password with bcrypt ───────────────────
        if not user or not bcrypt.check_password_hash(user['password'], password):
            flash("Invalid username or password.", "error")
            return render_template('login.html')

        # ── 2FA check ─────────────────────────────────────
        if user['is_2fa_enabled']:
            # Store temp session — full login only after 2FA
            session['pre_2fa_user_id'] = user['id']
            session['pre_2fa_username'] = user['username']
            return redirect(url_for('verify_2fa'))

        # ── Create session ────────────────────────────────
        session.permanent = True
        session['user_id']  = user['id']
        session['username'] = user['username']

        # Update last login timestamp
        conn = get_db()
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user['id'])
        )
        conn.commit()
        conn.close()

        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# ── 2FA Verification ──────────────────────────────────────────
@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        user_id  = session['pre_2fa_user_id']

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()

        # Verify TOTP code
        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(otp_code, valid_window=1):
            flash("Invalid or expired OTP code. Try again.", "error")
            return render_template('verify_2fa.html')

        # 2FA passed — create full session
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_username', None)
        session.permanent = True
        session['user_id']  = user['id']
        session['username'] = user['username']

        conn = get_db()
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user['id'])
        )
        conn.commit()
        conn.close()

        flash("2FA verified! Welcome back.", "success")
        return redirect(url_for('dashboard'))

    return render_template('verify_2fa.html')

# ── Dashboard (protected route) ───────────────────────────────
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please login to continue.", "error")
        return redirect(url_for('login'))

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session['user_id'],)
    ).fetchone()
    conn.close()

    return render_template('dashboard.html', user=user)

# ── Logout ────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    username = session.get('username', '')
    session.clear()   # Destroy entire session
    flash(f"Goodbye, {username}! You have been logged out.", "success")
    return redirect(url_for('login'))

# ============================================================
if __name__ == '__main__':
    app.run(debug=True)