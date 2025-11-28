import os
import secrets
from flask import Flask, render_template_string, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import zipfile
import json
import io
import csv
import tempfile

app = Flask(__name__)

# Fly.io configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'flyio-mygeosync-secret-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///mygeosync.db').replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 5,
    'max_overflow': 10,
}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models (same as Koyeb version)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    company_name = db.Column(db.String(100), default='MYGeoSync')
    full_name = db.Column(db.String(100))
    subscription_type = db.Column(db.String(20), default='trial')
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_expiry = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

class ConversionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200))
    points_converted = db.Column(db.Integer)
    conversion_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)

# Initialize database
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@mygeosync.com').first():
        admin = User(
            email='admin@mygeosync.com',
            company_name='MYGeoSync',
            full_name='Administrator',
            subscription_type='enterprise',
            subscription_expiry=datetime.utcnow() + timedelta(days=3650),
            is_admin=True
        )
        admin.password_hash = bcrypt.generate_password_hash('admin123').decode('utf-8')
        db.session.add(admin)
        db.session.commit()
        print("✅ Fly.io: Admin user created")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Conversion functions (same as Koyeb version)
def mrso_to_wgs84(x, y):
    lat = 5.0 + (y - 500000) / 110000
    lon = 101.0 + (x - 300000) / 111000
    return round(lat, 6), round(lon, 6)

def create_polygon_from_points(points_data):
    if len(points_data) < 3:
        return None
    sorted_points = sorted(points_data, key=lambda x: x['ID'])
    polygon_coords = [(p['Longitude'], p['Latitude']) for p in sorted_points]
    polygon_coords.append(polygon_coords[0])
    return polygon_coords

def create_kml_content(points_data, polygon_coords, base_name, line_color="ff0000ff", show_points=False, show_labels=False):
    points_kml = ""
    if show_points or show_labels:
        for point in points_data:
            label = f"<name>{point['Station']}</name>" if show_labels else ""
            if show_points:
                points_kml += f"""    <Placemark>
      {label}
      <Style><IconStyle><color>ff0000ff</color><scale>1.0</scale><Icon><href>http://maps.google.com/mapfiles/kml/paddle/red-circle.png</href></Icon></IconStyle><LabelStyle><scale>{1.0 if show_labels else 0}</scale></LabelStyle></Style>
      <Point><coordinates>{point['Longitude']},{point['Latitude']},0</coordinates></Point>
    </Placemark>
"""
            elif show_labels:
                points_kml += f"""    <Placemark>
      <name>{point['Station']}</name>
      <Style><IconStyle><scale>0</scale></IconStyle><LabelStyle><scale>1.0</scale></LabelStyle></Style>
      <Point><coordinates>{point['Longitude']},{point['Latitude']},0</coordinates></Point>
    </Placemark>
"""
    
    polygon_kml = ""
    if polygon_coords:
        coords_str = " ".join([f"{lon},{lat},0" for lon, lat in polygon_coords])
        polygon_kml = f"""    <Placemark>
      <name>{base_name}</name>
      <Style><LineStyle><color>{line_color}</color><width>2</width></LineStyle><PolyStyle><color>40000000</color><fill>1</fill></PolyStyle></Style>
      <Polygon><outerBoundaryIs><LinearRing><coordinates>{coords_str}</coordinates></LinearRing></outerBoundaryIs></Polygon>
    </Placemark>
"""
    
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document><name>{base_name}</name>{polygon_kml}{points_kml}</Document></kml>"""

def create_geojson_content(points_data, polygon_coords):
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

# Routes (same as Koyeb version - all routes identical)
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

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
                            <p class="mb-0">Fly.io Deployment</p>
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
                                <button type="submit" class="btn btn-primary w-100 py-2">Login</button>
                            </form>
                            <div class="text-center mt-3">
                                <a href="{{ url_for('register') }}">Don't have an account? Register</a>
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        company_name = request.form.get('company_name')
        full_name = request.form.get('full_name')
        
        # Basic validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
            
        # Create new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(
            email=email,
            password_hash=hashed_password,
            company_name=company_name,
            full_name=full_name,
            subscription_type='trial',
            subscription_expiry=datetime.utcnow() + timedelta(days=30)
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

# Add health check route
@app.route('/health')
def health_check():
    return 'OK', 200

# Make sure main block looks like this:
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    print("🚀 MYGeoSync - Fly.io Edition")
    print(f"📍 Port: {port}")
    print(f"🏢 Company: MYGeoSync")
    print(f"👤 Admin: admin@mygeosync.com / admin123")
    print(f"🌐 Platform: Fly.io")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
