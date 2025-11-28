from flask import Flask, request, send_file, render_template_string, flash, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import zipfile
import json
import io
import csv
import os
import tempfile
import secrets

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'mrso-converter-pro-secret-2024')

# Database configuration - Universal
database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Using fast approximate conversion optimized for Malaysia
PYPROJ_AVAILABLE = False
print("🔧 Using fast approximate conversion optimized for Malaysia")

# Enhanced Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    company_name = db.Column(db.String(100))
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    company_reg_no = db.Column(db.String(50))
    subscription_type = db.Column(db.String(20), default='trial')
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_expiry = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=7))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    
    conversions = db.relationship('ConversionRecord', backref='user', lazy=True, cascade='all, delete-orphan')
    invoices = db.relationship('Invoice', backref='user', lazy=True)

class ConversionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200))
    points_converted = db.Column(db.Integer)
    conversion_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invoice_number = db.Column(db.String(50), unique=True)
    amount = db.Column(db.Float)
    sst_amount = db.Column(db.Float)
    total_amount = db.Column(db.Float)
    status = db.Column(db.String(20), default='pending')
    invoice_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))

class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    admin_notes = db.Column(db.Text)

# Initialize database
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@geomalaya.com').first():
        admin = User(
            email='admin@geomalaya.com',
            password_hash=generate_password_hash('admin123'),
            company_name='MYGeoSync',
            full_name='Administrator',
            phone='+60123456789',
            subscription_type='enterprise',
            subscription_expiry=datetime.utcnow() + timedelta(days=3650),
            is_admin=True,
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin@geomalaya.com / admin123")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Conversion functions
def mrso_to_wgs84(x, y):
    """Convert MRSO to WGS84 coordinates - optimized for Malaysia"""
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

# Routes (simplified for deployment)
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
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Account is deactivated. Please contact support.', 'error')
                return redirect(url_for('login'))
            
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
        <style>
            body { background: #f8f9fa; padding: 50px; }
            .card { max-width: 400px; margin: 0 auto; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h4>MYGeoSync Login</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" class="form-control" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
                <div class="text-center mt-3">
                    <a href="/register">Create Account</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

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
            subscription_expiry=datetime.utcnow() + timedelta(days=7)
        )
        user.password_hash = generate_password_hash(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! 7-day free trial started.', 'success')
        return redirect(url_for('login'))
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body style="background: #f8f9fa; padding: 50px;">
        <div class="card" style="max-width: 500px; margin: 0 auto;">
            <div class="card-header bg-success text-white">
                <h4>Create MYGeoSync Account</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Full Name</label>
                        <input type="text" class="form-control" name="full_name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Company Name</label>
                        <input type="text" class="form-control" name="company_name" required>
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
                    <button type="submit" class="btn btn-success w-100">Start Free Trial</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    return f'''
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
                    <a class="nav-link" href="/logout">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container mt-4">
            <h1>Welcome to MYGeoSync!</h1>
            <p>Your professional coordinate conversion platform is ready.</p>
            <a href="/converter" class="btn btn-success">Start Converting Coordinates</a>
        </div>
    </body>
    </html>
    '''

@app.route('/converter')
@login_required
def converter():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Converter - MYGeoSync</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">MYGeoSync</a>
            </div>
        </nav>
        <div class="container mt-4">
            <h2>Coordinate Converter</h2>
            <p>Upload your CSV file to convert MRSO coordinates to WGS84.</p>
            <form method="POST" action="/convert" enctype="multipart/form-data">
                <div class="mb-3">
                    <label class="form-label">Select CSV File</label>
                    <input type="file" class="form-control" name="file" accept=".csv" required>
                </div>
                <button type="submit" class="btn btn-primary">Convert</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/convert', methods=['POST'])
@login_required
def convert():
    try:
        if 'file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('converter'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('converter'))

        # Process CSV file
        points_data = []
        content = file.read().decode('utf-8-sig').splitlines()
        csv_reader = csv.reader(content)
        headers = [h.strip().replace('\ufeff', '').replace(' ', '').upper() for h in next(csv_reader)]
        
        # Simple column mapping
        col_mapping = {}
        for i, header in enumerate(headers):
            if 'ID' in header:
                col_mapping['ID'] = i
            elif 'STATION' in header:
                col_mapping['STATION'] = i
            elif 'X' in header:
                col_mapping['X'] = i
            elif 'Y' in header:
                col_mapping['Y'] = i
        
        # Process data
        for row in csv_reader:
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
            except (ValueError, IndexError):
                continue

        if not points_data:
            flash('No valid coordinates found', 'error')
            return redirect(url_for('converter'))

        # Create output files
        zip_buffer = io.BytesIO()
        base_name = os.path.splitext(file.filename)[0]
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # CSV output
            csv_buffer = io.StringIO()
            csv_writer = csv.writer(csv_buffer)
            csv_writer.writerow(['ID', 'Station', 'Xcoord', 'Ycoord', 'Latitude', 'Longitude'])
            for point in points_data:
                csv_writer.writerow([point['ID'], point['Station'], point['Xcoord'], 
                                   point['Ycoord'], point['Latitude'], point['Longitude']])
            zip_file.writestr(f'{base_name}_converted.csv', csv_buffer.getvalue())
            
            # KML output
            polygon_coords = create_polygon_from_points(points_data)
            kml_content = create_kml_content(points_data, polygon_coords, base_name)
            zip_file.writestr(f'{base_name}_boundary.kml', kml_content)
            
            # GeoJSON output
            geojson_content = create_geojson_content(points_data, polygon_coords)
            zip_file.writestr(f'{base_name}_boundary.geojson', json.dumps(geojson_content, indent=2))

        # Record conversion
        conversion_record = ConversionRecord(
            user_id=current_user.id,
            filename=file.filename,
            points_converted=len(points_data),
            file_size=len(file.read())
        )
        db.session.add(conversion_record)
        db.session.commit()
        
        zip_buffer.seek(0)
        flash(f'Successfully converted {len(points_data)} coordinates!', 'success')
        
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f'{base_name}_converted.zip',
            mimetype='application/zip'
        )
    
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('converter'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9002))
    app.run(host='0.0.0.0', port=port, debug=False)