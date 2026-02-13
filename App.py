from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize token serializer for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create user model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('login.html') # currently moving to login instead index

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('profile'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('login'))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('login'))

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('login'))

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! You can now log in.')
        return redirect(url_for('login'))

    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a secure token
            token = serializer.dumps(user.email, salt='password-reset-salt')

            # In a real application, you would send an email with the reset link
            # For this example, we'll just flash the token (not secure for production)
            reset_url = url_for('reset_password', token=token, _external=True)
            flash(f'Password reset link has been sent to your email. For demo purposes, here is the link: {reset_url}')
            return redirect(url_for('login'))
        else:
            flash('Email not found in our records.')

    return render_template('reset_password.html', token=None)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    try:
        # Verify the token (expires after 1 hour)
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Invalid or expired token.')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if password != confirm_password:
                flash('Passwords do not match.')
                return redirect(url_for('reset_password', token=token))

            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated! You can now log in with your new password.')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)

    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))

# Create database tables
def create_tables():
    if not os.path.exists('instance'):
        os.makedirs('instance')
    db.create_all()

# Run the application
if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=True)
