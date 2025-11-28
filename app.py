import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import zipfile
import json
import io
import csv
import tempfile
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)

# Configuration for Render
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'mygeosync-pro-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///mygeosync.db').replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'noreply@mygeosync.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@mygeosync.com')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Try to import pyproj for better coordinate conversion
try:
    from pyproj import Transformer
    PYPROJ_AVAILABLE = True
    print("✅ pyproj is available - using exact coordinate transformation")
except ImportError:
    PYPROJ_AVAILABLE = False
    print("🔧 Using fast approximate conversion optimized for Malaysia")

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    company_name = db.Column(db.String(100), default='MYGeoSync')
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    company_reg_no = db.Column(db.String(50))
    subscription_type = db.Column(db.String(20), default='trial')
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_expiry = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Relationships
    conversions = db.relationship('ConversionRecord', backref='user', lazy=True, cascade='all, delete-orphan')
    projects = db.relationship('Project', backref='user', lazy=True)
    support_tickets = db.relationship('SupportTicket', backref='user', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(200))
    coordinates = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ConversionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200))
    points_converted = db.Column(db.Integer)
    conversion_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))

class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    admin_notes = db.Column(db.Text)

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.String(255))

# Initialize database
with app.app_context():
    db.create_all()
    # Create admin user if not exists
    if not User.query.filter_by(email='admin@mygeosync.com').first():
        admin = User(
            email='admin@mygeosync.com',
            company_name='MYGeoSync',
            full_name='Administrator',
            phone='+60123456789',
            subscription_type='enterprise',
            subscription_expiry=datetime.utcnow() + timedelta(days=3650),
            is_admin=True,
            is_verified=True
        )
        admin.password_hash = bcrypt.generate_password_hash('admin123').decode('utf-8')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin@mygeosync.com / admin123")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Conversion functions
def mrso_to_wgs84(x, y):
    """Convert MRSO to WGS84 coordinates - uses exact transformation if pyproj available"""
    if PYPROJ_AVAILABLE:
        transformer = Transformer.from_crs("ESRI:102062", "EPSG:4326", always_xy=True)
        lon, lat = transformer.transform(x, y)
        return round(lat, 6), round(lon, 6)
    else:
        # Optimized approximation for Malaysia
        lat = 5.0 + (y - 500000) / 110000
        lon = 101.0 + (x - 300000) / 111000
        return round(lat, 6), round(lon, 6)

def create_polygon_from_points(points_data):
    """Create closed polygon from points"""
    if len(points_data) < 3:
        return None
    sorted_points = sorted(points_data, key=lambda x: x['ID'])
    polygon_coords = [(p['Longitude'], p['Latitude']) for p in sorted_points]
    polygon_coords.append(polygon_coords[0])
    return polygon_coords

def create_kml_content(points_data, polygon_coords, base_name, line_color="ff0000ff", show_points=False, show_labels=False):
    """Generate KML content for Google Earth"""
    points_kml = ""
    if show_points or show_labels:
        for point in points_data:
            label = f"<name>{point['Station']}</name>" if show_labels else ""
            
            if show_points:
                points_kml += f"""    <Placemark>
      {label}
      <Style>
        <IconStyle>
          <color>ff0000ff</color>
          <scale>1.0</scale>
          <Icon>
            <href>http://maps.google.com/mapfiles/kml/paddle/red-circle.png</href>
          </Icon>
        </IconStyle>
        <LabelStyle>
          <scale>{1.0 if show_labels else 0}</scale>
        </LabelStyle>
      </Style>
      <Point>
        <coordinates>{point['Longitude']},{point['Latitude']},0</coordinates>
      </Point>
    </Placemark>
"""
            elif show_labels:
                points_kml += f"""    <Placemark>
      <name>{point['Station']}</name>
      <Style>
        <IconStyle>
          <scale>0</scale>
        </IconStyle>
        <LabelStyle>
          <scale>1.0</scale>
        </LabelStyle>
      </Style>
      <Point>
        <coordinates>{point['Longitude']},{point['Latitude']},0</coordinates>
      </Point>
    </Placemark>
"""
    
    polygon_kml = ""
    if polygon_coords:
        coords_str = " ".join([f"{lon},{lat},0" for lon, lat in polygon_coords])
        polygon_kml = f"""    <Placemark>
      <name>{base_name}</name>
      <Style>
        <LineStyle>
          <color>{line_color}</color>
          <width>2</width>
        </LineStyle>
        <PolyStyle>
          <color>40000000</color>
          <fill>1</fill>
        </PolyStyle>
      </Style>
      <Polygon>
        <outerBoundaryIs>
          <LinearRing>
            <coordinates>{coords_str}</coordinates>
          </LinearRing>
        </outerBoundaryIs>
      </Polygon>
    </Placemark>
"""
    
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <name>{base_name}</name>
{polygon_kml}
{points_kml}
</Document>
</kml>"""

def create_geojson_content(points_data, polygon_coords):
    """Create GeoJSON content"""
    features = []
    
    if polygon_coords:
        features.append({
            "type": "Feature",
            "properties": {"name": "Boundary", "type": "polygon"},
            "geometry": {"type": "Polygon", "coordinates": [polygon_coords]}
        })
    
    for point in points_data:
        features.append({
            "type": "Feature",
            "properties": {
                "ID": point['ID'],
                "Station": point['Station'],
                "Xcoord": point['Xcoord'],
                "Ycoord": point['Ycoord'],
                "type": "point"
            },
            "geometry": {
                "type": "Point",
                "coordinates": [point['Longitude'], point['Latitude']]
            }
        })
    
    return {"type": "FeatureCollection", "features": features}

# Enhanced Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        company_name = request.form.get('company_name', 'MYGeoSync')
        full_name = request.form.get('full_name')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        user = User(
            email=email,
            company_name=company_name,
            full_name=full_name,
            subscription_type='trial',
            subscription_expiry=datetime.utcnow() + timedelta(days=30)
        )
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! 30-day free trial started.', 'success')
        return redirect(url_for('login'))
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
            .card { border: none; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-primary text-white text-center py-4">
                            <h3><i class="fas fa-user-plus me-2"></i>Create MYGeoSync Account</h3>
                            <p class="mb-0">Professional Coordinate Conversion Platform</p>
                        </div>
                        <div class="card-body p-4">
                            {% with messages = get_flashed_messages(with_categories=true) %}
                                {% if messages %}
                                    {% for category, message in messages %}
                                        <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }}">{{ message }}</div>
                                    {% endfor %}
                                {% endif %}
                            {% endwith %}
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Full Name</label>
                                    <input type="text" class="form-control" name="full_name" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Company Name</label>
                                    <input type="text" class="form-control" name="company_name" value="MYGeoSync" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" name="email" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" name="password" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Confirm Password</label>
                                    <input type="password" class="form-control" name="confirm_password" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100 py-2">Start Free Trial</button>
                            </form>
                            <div class="text-center mt-3">
                                <a href="{{ url_for('login') }}">Already have an account? Login</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Account is deactivated. Please contact support.', 'error')
                return redirect(url_for('login'))
            
            login_user(user)
            flash(f'Welcome to MYGeoSync, {user.full_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
            .card { border: none; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-5">
                    <div class="card">
                        <div class="card-header bg-primary text-white text-center py-4">
                            <h3><i class="fas fa-sign-in-alt me-2"></i>MYGeoSync Login</h3>
                            <p class="mb-0">Professional Coordinate Conversion Platform</p>
                        </div>
                        <div class="card-body p-4">
                            {% with messages = get_flashed_messages(with_categories=true) %}
                                {% if messages %}
                                    {% for category, message in messages %}
                                        <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }}">{{ message }}</div>
                                    {% endfor %}
                                {% endif %}
                            {% endwith %}
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" name="email" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" name="password" required>
                                </div>
                                <div class="mb-3 form-check">
                                    <input type="checkbox" class="form-check-input" id="remember">
                                    <label class="form-check-label" for="remember">Remember me</label>
                                </div>
                                <button type="submit" class="btn btn-primary w-100 py-2">Login</button>
                            </form>
                            <div class="text-center mt-3">
                                <a href="{{ url_for('forgot_password') }}">Forgot your password?</a>
                            </div>
                            <div class="text-center mt-2">
                                <a href="{{ url_for('register') }}">Don't have an account? Start Free Trial</a>
                            </div>
                            <div class="text-center mt-3">
                                <small class="text-muted">Admin: admin@mygeosync.com / admin123</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/forgot-password')
def forgot_password():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Forgot Password - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
            .card { border: none; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-warning text-dark text-center py-4">
                            <h3><i class="fas fa-key me-2"></i>Reset Password</h3>
                        </div>
                        <div class="card-body p-4 text-center">
                            <div class="alert alert-info">
                                <strong>Password reset feature coming soon!</strong><br>
                                Please contact support at support@mygeosync.com to reset your password.
                            </div>
                            <a href="{{ url_for('login') }}" class="btn btn-primary w-100">Back to Login</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# Enhanced Main Application Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Check subscription status
    if current_user.subscription_expiry < datetime.utcnow():
        current_user.is_active = False
        db.session.commit()
        flash('Your subscription has expired. Please renew to continue using the service.', 'error')
        return redirect(url_for('account'))
    
    # Get user's conversion history
    recent_conversions = ConversionRecord.query.filter_by(user_id=current_user.id)\
        .order_by(ConversionRecord.conversion_date.desc())\
        .limit(10).all()
    
    # Calculate days remaining
    days_remaining = (current_user.subscription_expiry - datetime.utcnow()).days
    days_remaining = max(0, days_remaining)
    
    # Total conversions
    total_conversions = ConversionRecord.query.filter_by(user_id=current_user.id).count()
    total_points = db.session.query(db.func.sum(ConversionRecord.points_converted))\
        .filter(ConversionRecord.user_id == current_user.id).scalar() or 0
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            body { background: #f8f9fa; }
            .navbar { margin-bottom: 20px; }
            .stat-card { border-left: 4px solid #007cba; }
            .external-links {
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                border-radius: 8px;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">
                    <i class="fas fa-globe-asia me-2"></i>MYGeoSync Pro
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {{ current_user.full_name }}</span>
                    <a class="nav-link" href="{{ url_for('converter') }}">Converter</a>
                    <a class="nav-link" href="{{ url_for('projects') }}">Projects</a>
                    <a class="nav-link" href="{{ url_for('account') }}">Account</a>
                    {% if current_user.is_admin %}
                    <a class="nav-link" href="{{ url_for('admin_dashboard') }}">Admin</a>
                    {% endif %}
                    <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                </div>
            </div>
        </nav>
        
        <div class="container mt-4">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="row">
                <div class="col-md-8">
                    <div class="card shadow-sm mb-4">
                        <div class="card-header bg-white">
                            <h5 class="mb-0"><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-3">
                                    <div class="card stat-card mb-3">
                                        <div class="card-body text-center">
                                            <h6 class="text-muted">Subscription</h6>
                                            <h4 class="text-success">Active</h4>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="card stat-card mb-3">
                                        <div class="card-body text-center">
                                            <h6 class="text-muted">Days Remaining</h6>
                                            <h4>{{ days_remaining }}</h4>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="card stat-card mb-3">
                                        <div class="card-body text-center">
                                            <h6 class="text-muted">Total Conversions</h6>
                                            <h4>{{ total_conversions }}</h4>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="card stat-card mb-3">
                                        <div class="card-body text-center">
                                            <h6 class="text-muted">Points Converted</h6>
                                            <h4>{{ total_points }}</h4>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 mt-4">
                                <a href="{{ url_for('converter') }}" class="btn btn-success btn-lg">
                                    <i class="fas fa-rocket me-2"></i>Convert Coordinates
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    {% if recent_conversions %}
                    <div class="card shadow-sm">
                        <div class="card-header bg-white">
                            <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Conversions</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>Filename</th>
                                            <th>Points</th>
                                            <th>Date</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for conv in recent_conversions %}
                                        <tr>
                                            <td>{{ conv.filename }}</td>
                                            <td>{{ conv.points_converted }}</td>
                                            <td>{{ conv.conversion_date.strftime('%Y-%m-%d %H:%M') }}</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    {% endif %}
                </div>
                
                <div class="col-md-4">
                    <div class="card shadow-sm">
                        <div class="card-header bg-white">
                            <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i>Account Info</h5>
                        </div>
                        <div class="card-body">
                            <p><strong>Email:</strong> {{ current_user.email }}</p>
                            <p><strong>Company:</strong> {{ current_user.company_name }}</p>
                            <p><strong>Member Since:</strong> {{ current_user.registration_date.strftime('%Y-%m-%d') }}</p>
                            <p><strong>Subscription Expires:</strong> {{ current_user.subscription_expiry.strftime('%Y-%m-%d') }}</p>
                            <div class="alert alert-info mt-3">
                                <small>For support, contact: support@mygeosync.com</small>
                            </div>
                        </div>
                    </div>

                    <!-- External Resources -->
                    <div class="external-links mt-4">
                        <h6><i class="fas fa-external-link-alt me-2"></i>Useful Resources</h6>
                        <ul class="list-unstyled mb-0 small">
                            <li class="mb-2">
                                <a href="https://www.mybis.gov.my/one/discover.php" target="_blank">
                                    <i class="fas fa-external-link-alt me-1"></i> MyBIS Portal
                                </a>
                            </li>
                            <li class="mb-2">
                                <a href="https://browser.dataspace.copernicus.eu/" target="_blank">
                                    <i class="fas fa-satellite me-1"></i> Copernicus Browser
                                </a>
                            </li>
                            <li class="mb-2">
                                <a href="https://pefc.org/find-certified" target="_blank">
                                    <i class="fas fa-certificate me-1"></i> PEFC Find Certified
                                </a>
                            </li>
                            <li>
                                <a href="https://search.fsc.org/en/" target="_blank">
                                    <i class="fas fa-tree me-1"></i> FSC Find Certified
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''', recent_conversions=recent_conversions, days_remaining=days_remaining, 
         total_conversions=total_conversions, total_points=total_points)

# Enhanced Converter with better UI and multiple file support
@app.route('/converter')
@login_required
def converter():
    # Check subscription
    if current_user.subscription_expiry < datetime.utcnow():
        current_user.is_active = False
        db.session.commit()
        flash('Your subscription has expired. Please renew to continue using the service.', 'error')
        return redirect(url_for('account'))
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Converter - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            body { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container { 
                max-width: 1200px; 
                background: white; 
                padding: 30px; 
                border-radius: 15px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                margin-top: 20px;
            }
            .upload-area {
                border: 3px dashed #007cba;
                border-radius: 10px;
                padding: 40px;
                text-align: center;
                background: #f8f9fa;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .upload-area:hover {
                background: #e3f2fd;
                border-color: #0056b3;
            }
            .feature-card {
                border-left: 4px solid #28a745;
                padding: 15px;
                margin-bottom: 15px;
                background: #f8f9fa;
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Header -->
            <div class="header mb-4" style="background: linear-gradient(135deg, #007cba 0%, #0056b3 100%); color: white; padding: 25px; border-radius: 10px; text-align: center;">
                <h1><i class="fas fa-globe-asia me-3"></i>MYGeoSync Coordinate Converter</h1>
                <p class="lead mb-0">Convert MRSO coordinates to multiple formats</p>
                <small>Core Outputs: CSV + KML + GeoJSON</small>
            </div>

            <!-- Navigation -->
            <div class="d-flex justify-content-between mb-4">
                <a href="{{ url_for('dashboard') }}" class="btn btn-outline-primary">
                    <i class="fas fa-arrow-left me-2"></i>Back to Dashboard
                </a>
                <div>
                    <span class="me-3">Logged in as: {{ current_user.email }}</span>
                    <a href="{{ url_for('account') }}" class="btn btn-outline-secondary btn-sm me-2">Account</a>
                    {% if current_user.is_admin %}
                    <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline-warning btn-sm me-2">Admin</a>
                    {% endif %}
                    <a href="{{ url_for('logout') }}" class="btn btn-outline-secondary btn-sm">Logout</a>
                </div>
            </div>

            <!-- Flash Messages -->
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            <div class="row">
                <!-- Left Column - Upload & Conversion -->
                <div class="col-lg-7">
                    <div class="card shadow-sm mb-4">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0"><i class="fas fa-sync-alt me-2"></i>Coordinate Conversion</h5>
                        </div>
                        <div class="card-body">
                            <form method="POST" action="{{ url_for('convert') }}" enctype="multipart/form-data" id="uploadForm">
                                <!-- File Upload -->
                                <div class="mb-4">
                                    <label class="form-label fw-bold"><i class="fas fa-file me-2"></i>Select MRSO Coordinate Files:</label>
                                    <input type="file" class="form-control" name="file" accept=".csv" required multiple id="fileInput">
                                    <div class="form-text">
                                        <i class="fas fa-info-circle me-1"></i>
                                        <strong>Required CSV format:</strong> ID,Station,X,Y
                                    </div>
                                    <div class="multi-file-indicator">
                                        <i class="fas fa-check-circle text-success me-2"></i>
                                        <small><strong>Multiple files supported:</strong> Select multiple files for batch processing</small>
                                    </div>
                                </div>

                                <!-- Visual Upload Area -->
                                <div class="upload-area mb-4" id="uploadArea">
                                    <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                                    <h5>Drag & Drop or Click to Browse</h5>
                                    <p class="text-muted mb-0">Upload your MRSO coordinates files (multiple files supported)</p>
                                </div>

                                <!-- KML Display Options -->
                                <div class="mb-4">
                                    <label class="form-label fw-bold"><i class="fas fa-map me-2"></i>KML Display Options (Google Earth):</label>
                                    <div class="row">
                                        <div class="col-6">
                                            <div class="form-check mb-2">
                                                <input class="form-check-input" type="checkbox" name="show_points" value="true" id="showPoints">
                                                <label class="form-check-label" for="showPoints">
                                                    <i class="fas fa-map-marker-alt me-1"></i> Show Points/Markers
                                                </label>
                                            </div>
                                        </div>
                                        <div class="col-6">
                                            <div class="form-check mb-2">
                                                <input class="form-check-input" type="checkbox" name="show_labels" value="true" id="showLabels">
                                                <label class="form-check-label" for="showLabels">
                                                    <i class="fas fa-tag me-1"></i> Show Labels
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                    <small class="text-muted">"Show Points" displays markers, "Show Labels" displays station names (works independently)</small>
                                </div>

                                <!-- KML Styling Options -->
                                <div class="mb-4">
                                    <label class="form-label fw-bold"><i class="fas fa-palette me-2"></i>KML Styling:</label>
                                    <div class="row">
                                        <div class="col-12">
                                            <label class="form-label">Boundary Color:</label>
                                            <select class="form-select" name="line_color">
                                                <option value="ff0000ff">🔴 Red</option>
                                                <option value="ff00ff00">🟢 Green</option>
                                                <option value="ffff0000">🔵 Blue</option>
                                                <option value="ffffff00">🟡 Yellow</option>
                                                <option value="ffff00ff">🟣 Purple</option>
                                            </select>
                                        </div>
                                    </div>
                                    <small class="text-muted">Line thickness is set to thin by default for better visibility</small>
                                </div>

                                <button type="submit" class="btn btn-success btn-lg w-100 py-3">
                                    <i class="fas fa-rocket me-2"></i> Convert Coordinates
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Right Column - Features & Outputs -->
                <div class="col-lg-5">
                    <!-- Core Outputs -->
                    <div class="card shadow-sm mb-4">
                        <div class="card-header bg-success text-white">
                            <h5 class="mb-0"><i class="fas fa-download me-2"></i>Core Output Files</h5>
                        </div>
                        <div class="card-body">
                            <div class="feature-card">
                                <h6><i class="fas fa-file-csv text-primary me-2"></i>CSV File</h6>
                                <p class="mb-2 small">Converted coordinates in tabular format with Latitude and Longitude columns</p>
                                <span class="badge bg-primary output-badge">Spreadsheet Ready</span>
                            </div>
                            
                            <div class="feature-card">
                                <h6><i class="fas fa-globe-americas text-warning me-2"></i>KML File</h6>
                                <p class="mb-2 small">Google Earth compatible file with customizable display options</p>
                                <span class="badge bg-warning output-badge">Google Earth</span>
                            </div>

                            <div class="feature-card">
                                <h6><i class="fas fa-code text-info me-2"></i>GeoJSON File</h6>
                                <p class="mb-2 small">Web mapping format for GIS applications and online maps</p>
                                <span class="badge bg-info output-badge">Web Maps</span>
                            </div>
                        </div>
                    </div>

                    <!-- Status Info -->
                    <div class="card shadow-sm mt-4">
                        <div class="card-header bg-secondary text-white">
                            <h6 class="mb-0"><i class="fas fa-info-circle me-2"></i>Status</h6>
                        </div>
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center">
                                <span>Conversion:</span>
                                <span class="badge {% if pyproj_available %}bg-success{% else %}bg-warning{% endif %}">
                                    {% if pyproj_available %}High Precision{% else %}Optimized{% endif %}
                                </span>
                            </div>
                        </div>
                    </div>

                    <!-- External Links -->
                    <div class="external-links mt-4">
                        <h6><i class="fas fa-external-link-alt me-2"></i>Useful Resources</h6>
                        <ul class="list-unstyled mb-0 small">
                            <li class="mb-2">
                                <a href="https://www.mybis.gov.my/one/discover.php" target="_blank">
                                    <i class="fas fa-external-link-alt me-1"></i> MyBIS Portal
                                </a>
                            </li>
                            <li class="mb-2">
                                <a href="https://browser.dataspace.copernicus.eu/" target="_blank">
                                    <i class="fas fa-satellite me-1"></i> Copernicus Browser
                                </a>
                            </li>
                            <li class="mb-2">
                                <a href="https://pefc.org/find-certified" target="_blank">
                                    <i class="fas fa-certificate me-1"></i> PEFC Find Certified
                                </a>
                            </li>
                            <li>
                                <a href="https://search.fsc.org/en/" target="_blank">
                                    <i class="fas fa-tree me-1"></i> FSC Find Certified
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- JavaScript -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function clearFile() {
                document.getElementById('fileInput').value = '';
                document.getElementById('uploadArea').innerHTML = `
                    <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                    <h5>Drag & Drop or Click to Browse</h5>
                    <p class="text-muted mb-0">Upload your MRSO coordinates files (multiple files supported)</p>
                `;
            }

            function showSample() {
                alert('Sample file format (CSV):\\n\\nID,Station,X,Y\\n1,Point A,345678,456789\\n2,Point B,345679,456790\\n3,Point C,345680,456791\\n4,Point D,345681,456792');
            }

            // File input change handler
            document.getElementById('fileInput').addEventListener('change', function(e) {
                if (this.files.length > 0) {
                    const fileCount = this.files.length;
                    const fileSize = (Array.from(this.files).reduce((acc, file) => acc + file.size, 0) / 1024 / 1024).toFixed(2);
                    
                    if (fileCount === 1) {
                        document.getElementById('uploadArea').innerHTML = `
                            <i class="fas fa-file-check fa-3x text-success mb-3"></i>
                            <h5>File Selected</h5>
                            <p class="text-success">${this.files[0].name}</p>
                            <small class="text-muted">${fileSize} MB - Click to change</small>
                        `;
                    } else {
                        document.getElementById('uploadArea').innerHTML = `
                            <i class="fas fa-files fa-3x text-success mb-3"></i>
                            <h5>${fileCount} Files Selected</h5>
                            <p class="text-success">Multiple files ready for batch processing</p>
                            <small class="text-muted">${fileCount} files, ${fileSize} MB total - Click to change</small>
                        `;
                    }
                }
            });

            // Drag and drop functionality
            const uploadArea = document.getElementById('uploadArea');
            const fileInput = document.getElementById('fileInput');

            ['dragover', 'dragenter'].forEach(event => {
                uploadArea.addEventListener(event, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    uploadArea.style.background = '#e3f2fd';
                    uploadArea.style.borderColor = '#0056b3';
                });
            });

            ['dragleave', 'dragend'].forEach(event => {
                uploadArea.addEventListener(event, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    uploadArea.style.background = '#f8f9fa';
                    uploadArea.style.borderColor = '#007cba';
                });
            });

            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                e.stopPropagation();
                uploadArea.style.background = '#f8f9fa';
                uploadArea.style.borderColor = '#007cba';
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    fileInput.files = files;
                    const event = new Event('change', { bubbles: true });
                    fileInput.dispatchEvent(event);
                }
            });

            uploadArea.addEventListener('click', () => {
                fileInput.click();
            });
        </script>
    </body>
    </html>
    ''', pyproj_available=PYPROJ_AVAILABLE)

@app.route('/convert', methods=['POST'])
@login_required
def convert():
    try:
        # Check subscription
        if current_user.subscription_expiry < datetime.utcnow():
            flash('Your subscription has expired.', 'error')
            return redirect(url_for('converter'))
        
        if 'file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('converter'))
        
        files = request.files.getlist('file')
        if not files or files[0].filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('converter'))

        show_points = request.form.get('show_points') == 'true'
        show_labels = request.form.get('show_labels') == 'true'
        line_color = request.form.get('line_color', 'ff0000ff')

        # Create output directory
        output_dir = tempfile.mkdtemp()
        files_to_zip = []
        
        total_files = 0
        total_points = 0
        base_names = []
        
        for file in files:
            if file.filename == '':
                continue
                
            total_files += 1
            
            # Read and process CSV file
            points_data = []
            content = file.read().decode('utf-8-sig').splitlines()
            csv_reader = csv.reader(content)
            headers = [h.strip().replace('\ufeff', '').replace(' ', '').upper() for h in next(csv_reader)]
            
            # Find columns
            col_mapping = {}
            required_cols = ['ID', 'STATION', 'X', 'Y']
            variations = {
                'ID': ['ID', 'POINTID', 'POINT', 'NUMBER'],
                'STATION': ['STATION', 'STATIONNAME', 'NAME', 'POINTNAME'],
                'X': ['X', 'XCOORD', 'EASTING', 'LONGITUDE'],
                'Y': ['Y', 'YCOORD', 'NORTHING', 'LATITUDE']
            }
            
            for req_col in required_cols:
                found = False
                for variation in variations[req_col]:
                    if variation in headers:
                        col_mapping[req_col] = headers.index(variation)
                        found = True
                        break
                if not found:
                    flash(f'Missing required column: {req_col} in {file.filename}', 'error')
                    continue
            
            # Process rows
            for row_num, row in enumerate(csv_reader, 2):
                if len(row) < max(col_mapping.values()) + 1:
                    continue
                    
                try:
                    point_id = int(row[col_mapping['ID']])
                    station = str(row[col_mapping['STATION']])
                    x_coord = float(row[col_mapping['X']])
                    y_coord = float(row[col_mapping['Y']])
                    
                    lat, lon = mrso_to_wgs84(x_coord, y_coord)
                    
                    points_data.append({
                        'ID': point_id,
                        'Station': station,
                        'Xcoord': x_coord,
                        'Ycoord': y_coord,
                        'Latitude': lat,
                        'Longitude': lon
                    })
                except (ValueError, IndexError) as e:
                    continue
            
            if not points_data:
                flash(f'No valid coordinates found in {file.filename}', 'error')
                continue

            total_points += len(points_data)

            # Create polygon
            polygon_coords = create_polygon_from_points(points_data)
            
            # Get base filename
            original_name = file.filename
            base_name = os.path.splitext(original_name)[0]
            base_names.append(base_name)
            
            # 1. CSV output (Core)
            csv_buffer = io.StringIO()
            csv_writer = csv.writer(csv_buffer)
            csv_writer.writerow(['ID', 'Station', 'Xcoord', 'Ycoord', 'Latitude', 'Longitude'])
            for point in points_data:
                csv_writer.writerow([point['ID'], point['Station'], point['Xcoord'], 
                                   point['Ycoord'], point['Latitude'], point['Longitude']])
            csv_output = os.path.join(output_dir, f'{base_name}_converted.csv')
            with open(csv_output, 'w', encoding='utf-8') as f:
                f.write(csv_buffer.getvalue())
            files_to_zip.append((f'{base_name}_converted.csv', csv_output))
            
            # 2. KML output (Core)
            kml_content = create_kml_content(points_data, polygon_coords, base_name, line_color, show_points, show_labels)
            kml_output = os.path.join(output_dir, f'{base_name}_boundary.kml')
            with open(kml_output, 'w', encoding='utf-8') as f:
                f.write(kml_content)
            files_to_zip.append((f'{base_name}_boundary.kml', kml_output))
            
            # 3. GeoJSON output (Core)
            geojson_content = create_geojson_content(points_data, polygon_coords)
            geojson_output = os.path.join(output_dir, f'{base_name}_boundary.geojson')
            with open(geojson_output, 'w', encoding='utf-8') as f:
                json.dump(geojson_content, f, indent=2)
            files_to_zip.append((f'{base_name}_boundary.geojson', geojson_output))

        if not files_to_zip:
            flash('No valid files to process', 'error')
            return redirect(url_for('converter'))
        
        # Record the conversion
        conversion_record = ConversionRecord(
            user_id=current_user.id,
            filename=', '.join([f.filename for f in files]),
            points_converted=total_points,
            file_size=sum([len(f.read()) for f in files])
        )
        db.session.add(conversion_record)
        db.session.commit()
        
        # Create ZIP file with all core outputs
        if total_files == 1:
            zip_filename = f'{base_names[0]}_converted.zip'
        else:
            # Format: firstfile_secondfile_ddmmyyyy_hhmm.zip
            first_two_names = '_'.join(base_names[:2])
            timestamp = datetime.now().strftime("%d%m%Y_%H%M")
            zip_filename = f'{first_two_names}_{timestamp}.zip'
            
        zip_output = os.path.join(output_dir, zip_filename)
        with zipfile.ZipFile(zip_output, 'w') as zipf:
            for display_name, file_path in files_to_zip:
                zipf.write(file_path, display_name)
        
        if total_files == 1:
            flash(f'Successfully converted {total_points} coordinates from 1 file! Downloading ZIP with CSV, KML, and GeoJSON files.', 'success')
        else:
            flash(f'Successfully converted {total_points} coordinates from {total_files} files! Downloading ZIP with all converted files.', 'success')
        
        return send_file(
            zip_output,
            as_attachment=True,
            download_name=zip_filename,
            mimetype='application/zip'
        )
    
    except Exception as e:
        flash(f'Error processing files: {str(e)}', 'error')
        return redirect(url_for('converter'))

# Projects Management
@app.route('/projects')
@login_required
def projects():
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Projects - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync</a>
                <div class="navbar-nav">
                    <a class="nav-link" href="/dashboard">Dashboard</a>
                    <a class="nav-link" href="/converter">Converter</a>
                    <a class="nav-link active" href="/projects">Projects</a>
                    <a class="nav-link" href="/account">Account</a>
                    <a class="nav-link" href="/logout">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container mt-4">
            <h2>My Projects</h2>
            <div class="row">
                {% for project in projects %}
                <div class="col-md-4 mb-3">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">{{ project.name }}</h5>
                            <p class="card-text">{{ project.description }}</p>
                            <small class="text-muted">Created: {{ project.created_at.strftime('%Y-%m-%d') }}</small>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </body>
    </html>
    ''', projects=user_projects)

# Enhanced Account Management
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name')
        current_user.company_name = request.form.get('company_name')
        current_user.email = request.form.get('email')
        current_user.phone = request.form.get('phone')
        
        new_password = request.form.get('new_password')
        if new_password:
            current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        db.session.commit()
        flash('Account updated successfully', 'success')
        return redirect(url_for('account'))
    
    days_remaining = (current_user.subscription_expiry - datetime.utcnow()).days
    days_remaining = max(0, days_remaining)
    
    # Get user's full conversion history
    all_conversions = ConversionRecord.query.filter_by(user_id=current_user.id)\
        .order_by(ConversionRecord.conversion_date.desc())\
        .all()
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Account - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync Pro</a>
                <div class="navbar-nav ms-auto">
                    <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a class="nav-link" href="{{ url_for('converter') }}">Converter</a>
                    <a class="nav-link active" href="{{ url_for('account') }}">Account</a>
                    {% if current_user.is_admin %}
                    <a class="nav-link" href="{{ url_for('admin_dashboard') }}">Admin</a>
                    {% endif %}
                    <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                </div>
            </div>
        </nav>
        
        <div class="container mt-4">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="row">
                <div class="col-md-6">
                    <div class="card shadow-sm">
                        <div class="card-header bg-white">
                            <h5 class="mb-0"><i class="fas fa-user-cog me-2"></i>Account Settings</h5>
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Full Name</label>
                                    <input type="text" class="form-control" name="full_name" value="{{ current_user.full_name }}" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Company Name</label>
                                    <input type="text" class="form-control" name="company_name" value="{{ current_user.company_name }}" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" name="email" value="{{ current_user.email }}" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Phone</label>
                                    <input type="text" class="form-control" name="phone" value="{{ current_user.phone or '' }}">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">New Password (leave blank to keep current)</label>
                                    <input type="password" class="form-control" name="new_password">
                                </div>
                                <button type="submit" class="btn btn-primary">Update Account</button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card shadow-sm">
                        <div class="card-header bg-white">
                            <h5 class="mb-0"><i class="fas fa-receipt me-2"></i>Subscription</h5>
                        </div>
                        <div class="card-body">
                            <p><strong>Email:</strong> {{ current_user.email }}</p>
                            <p><strong>Full Name:</strong> {{ current_user.full_name }}</p>
                            <p><strong>Company:</strong> {{ current_user.company_name }}</p>
                            <p><strong>Member Since:</strong> {{ current_user.registration_date.strftime('%Y-%m-%d') }}</p>
                            <p><strong>Subscription Type:</strong> {{ current_user.subscription_type|title }}</p>
                            <p><strong>Subscription Expires:</strong> {{ current_user.subscription_expiry.strftime('%Y-%m-%d') }}</p>
                            <p><strong>Days Remaining:</strong> 
                                <span class="badge bg-{{ 'success' if days_remaining > 7 else 'warning' if days_remaining > 0 else 'danger' }}">
                                    {{ days_remaining }} days
                                </span>
                            </p>
                            <div class="alert alert-info mt-3">
                                <small>For subscription renewal or support, please contact us at support@mygeosync.com</small>
                            </div>
                        </div>
                    </div>

                    <div class="card shadow-sm mt-4">
                        <div class="card-header bg-white">
                            <h5 class="mb-0"><i class="fas fa-history me-2"></i>Conversion History</h5>
                        </div>
                        <div class="card-body">
                            {% if all_conversions %}
                            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>File</th>
                                            <th>Points</th>
                                            <th>Date</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for conv in all_conversions %}
                                        <tr>
                                            <td><small>{{ conv.filename[:20] }}{% if conv.filename|length > 20 %}...{% endif %}</small></td>
                                            <td>{{ conv.points_converted }}</td>
                                            <td><small>{{ conv.conversion_date.strftime('%m/%d') }}</small></td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                            {% else %}
                            <p class="text-muted">No conversion history yet.</p>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''', days_remaining=days_remaining, all_conversions=all_conversions)

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    # Admin statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_conversions = ConversionRecord.query.count()
    total_points = db.session.query(db.func.sum(ConversionRecord.points_converted)).scalar() or 0
    
    # Recent conversions
    recent_conversions = ConversionRecord.query\
        .join(User)\
        .order_by(ConversionRecord.conversion_date.desc())\
        .limit(20).all()
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync Pro - Admin</a>
                <div class="navbar-nav ms-auto">
                    <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a class="nav-link" href="{{ url_for('admin_users') }}">Users</a>
                    <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                </div>
            </div>
        </nav>
        
        <div class="container mt-4">
            <h2>Admin Dashboard</h2>
            
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="card bg-primary text-white">
                        <div class="card-body text-center">
                            <h4>{{ total_users }}</h4>
                            <p>Total Users</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-success text-white">
                        <div class="card-body text-center">
                            <h4>{{ active_users }}</h4>
                            <p>Active Users</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-info text-white">
                        <div class="card-body text-center">
                            <h4>{{ total_conversions }}</h4>
                            <p>Total Conversions</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-warning text-white">
                        <div class="card-body text-center">
                            <h4>{{ total_points }}</h4>
                            <p>Points Converted</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Recent Conversions</h5>
                </div>
                <div class="card-body">
                    {% if recent_conversions %}
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>File</th>
                                    <th>Points</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for conv in recent_conversions %}
                                <tr>
                                    <td>{{ conv.user.email }}</td>
                                    <td>{{ conv.filename }}</td>
                                    <td>{{ conv.points_converted }}</td>
                                    <td>{{ conv.conversion_date.strftime('%Y-%m-%d %H:%M') }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <p class="text-muted">No conversions yet.</p>
                    {% endif %}
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', total_users=total_users, active_users=active_users, 
         total_conversions=total_conversions, total_points=total_points,
         recent_conversions=recent_conversions)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Management - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync Pro - Admin</a>
                <div class="navbar-nav ms-auto">
                    <a class="nav-link" href="{{ url_for('admin_dashboard') }}">Dashboard</a>
                    <a class="nav-link active" href="{{ url_for('admin_users') }}">Users</a>
                    <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                </div>
            </div>
        </nav>
        
        <div class="container mt-4">
            <h2>User Management</h2>
            
            <div class="card">
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Email</th>
                                    <th>Name</th>
                                    <th>Company</th>
                                    <th>Status</th>
                                    <th>Expiry</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for user in users %}
                                <tr>
                                    <td>{{ user.email }}</td>
                                    <td>{{ user.full_name }}</td>
                                    <td>{{ user.company_name }}</td>
                                    <td>
                                        <span class="badge bg-{{ 'success' if user.is_active else 'danger' }}">
                                            {{ 'Active' if user.is_active else 'Inactive' }}
                                        </span>
                                        {% if user.is_admin %}
                                        <span class="badge bg-warning">Admin</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ user.subscription_expiry.strftime('%Y-%m-%d') }}</td>
                                    <td>
                                        <form method="POST" action="{{ url_for('admin_toggle_user', user_id=user.id) }}" style="display: inline;">
                                            <button type="submit" class="btn btn-sm btn-{{ 'danger' if user.is_active else 'success' }}">
                                                {{ 'Deactivate' if user.is_active else 'Activate' }}
                                            </button>
                                        </form>
                                        <form method="POST" action="{{ url_for('admin_extend_subscription', user_id=user.id) }}" style="display: inline;">
                                            <button type="submit" class="btn btn-sm btn-info">Extend 30d</button>
                                        </form>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', users=users)

@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    flash(f'User {user.email} {"activated" if user.is_active else "deactivated"}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/extend_subscription/<int:user_id>', methods=['POST'])
@login_required
def admin_extend_subscription(user_id):
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.subscription_expiry = user.subscription_expiry + timedelta(days=30)
    db.session.commit()
    
    flash(f'Subscription extended for {user.email}', 'success')
    return redirect(url_for('admin_users'))

# Support Ticket System
@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    if request.method == 'POST':
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        ticket = SupportTicket(
            user_id=current_user.id,
            subject=subject,
            message=message
        )
        db.session.add(ticket)
        db.session.commit()
        
        flash('Support ticket submitted successfully! We will contact you at ' + current_user.email, 'success')
        return redirect(url_for('dashboard'))
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Support - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync</a>
            </div>
        </nav>
        <div class="container mt-4">
            <h2>Contact Support</h2>
            <p>For immediate assistance, email: support@mygeosync.com</p>
            <form method="POST">
                <div class="mb-3">
                    <label class="form-label">Subject</label>
                    <input type="text" class="form-control" name="subject" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Message</label>
                    <textarea class="form-control" name="message" rows="5" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Submit Ticket</button>
            </form>
        </div>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print("=" * 60)
    print("🌍 MYGeoSync Professional - ENHANCED VERSION")
    print("=" * 60)
    print(f"✅ Admin: admin@mygeosync.com / admin123")
    print(f"📍 Starting server at: http://localhost:{port}")
    print(f"🏢 Company: MYGeoSync")
    print(f"📧 Support: support@mygeosync.com")
    print("✨ Enhanced Features:")
    print("   • Multiple file upload with drag & drop")
    print("   • Advanced coordinate conversion")
    print("   • Project management system")
    print("   • Enhanced user dashboard")
    print("   • Support ticket system")
    print("   • Admin user management")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False)