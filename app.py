from flask import Flask, request, send_file, render_template_string, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import zipfile
import json
import io
import csv
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'mygeosync-secret-2024')

# Database configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    company_name = db.Column(db.String(100))
    full_name = db.Column(db.String(100))
    subscription_type = db.Column(db.String(20), default='trial')
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_expiry = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=7))
    is_active = db.Column(db.Boolean, default=True)

class ConversionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200))
    points_converted = db.Column(db.Integer)
    conversion_date = db.Column(db.DateTime, default=datetime.utcnow)

# ✅ HEALTH CHECK - MUST BE FIRST ROUTE!
@app.route('/health')
def health_check():
    return 'OK', 200

with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@mygeosync.com').first():
        admin = User(
            email='admin@mygeosync.com',
            password_hash=generate_password_hash('admin123'),
            company_name='MYGeoSync',
            full_name='Administrator',
            subscription_type='enterprise',
            subscription_expiry=datetime.utcnow() + timedelta(days=3650),
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def mrso_to_wgs84(x, y):
    lat = 5.0 + (y - 500000) / 110000
    lon = 101.0 + (x - 300000) / 111000
    return round(lat, 6), round(lon, 6)

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync</a>
                <div class="navbar-nav">
                    <a class="nav-link" href="/converter">Converter</a>
                    <a class="nav-link" href="/logout">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container mt-4">
            <h1>Welcome to MYGeoSync!</h1>
            <p>Your professional coordinate conversion platform is ready.</p>
            <a href="/converter" class="btn btn-success btn-lg">Start Converting Coordinates</a>
        </div>
    </body>
    </html>
    '''

# [REST OF YOUR ROUTES - login, register, converter, convert, logout]
# Copy all your other routes exactly as you have them

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password) and user.is_active:
            login_user(user)
            flash(f'Welcome to MYGeoSync, {user.full_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body style="background: #f8f9fa; padding: 50px;">
        <div class="card" style="max-width: 400px; margin: 0 auto;">
            <div class="card-header bg-primary text-white">
                <h4>MYGeoSync Login</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
                <div class="text-center mt-3">
                    <a href="/register">Create Account</a>
                </div>
                <div class="text-center mt-2">
                    <small class="text-muted">Demo: admin@mygeosync.com / admin123</small>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

# [Include all your other routes: register, converter, convert, logout]

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)