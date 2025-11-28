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

# Database - Fly.io provides DATABASE_URL
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

# ✅ ADD THIS MISSING DASHBOARD ROUTE!
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
            full_name=full_name
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
                        <label>Full Name</label>
                        <input type="text" class="form-control" name="full_name" required>
                    </div>
                    <div class="mb-3">
                        <label>Company Name</label>
                        <input type="text" class="form-control" name="company_name" required>
                    </div>
                    <div class="mb-3">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                    <div class="mb-3">
                        <label>Confirm Password</label>
                        <input type="password" class="form-control" name="confirm_password" required>
                    </div>
                    <button type="submit" class="btn btn-success w-100">Start Free Trial</button>
                </form>
            </div>
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
                <div class="navbar-nav">
                    <a class="nav-link" href="/dashboard">Dashboard</a>
                    <a class="nav-link" href="/logout">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container mt-4">
            <h2>Coordinate Converter</h2>
            <p>Upload your CSV file to convert MRSO coordinates to WGS84.</p>
            <form method="POST" action="/convert" enctype="multipart/form-data">
                <div class="mb-3">
                    <label class="form-label">Select CSV File</label>
                    <input type="file" class="form-control" name="file" accept=".csv" required>
                    <div class="form-text">Required format: ID, Station, X, Y</div>
                </div>
                <button type="submit" class="btn btn-primary btn-lg">Convert Coordinates</button>
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

        points_data = []
        content = file.read().decode('utf-8-sig').splitlines()
        csv_reader = csv.reader(content)
        headers = [h.strip().replace('\ufeff', '').replace(' ', '').upper() for h in next(csv_reader)]
        
        col_mapping = {}
        for i, header in enumerate(headers):
            if 'ID' in header: col_mapping['ID'] = i
            elif 'STATION' in header: col_mapping['STATION'] = i
            elif 'X' in header: col_mapping['X'] = i
            elif 'Y' in header: col_mapping['Y'] = i
        
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
                    'ID': point_id, 'Station': station, 'Xcoord': x_coord, 
                    'Ycoord': y_coord, 'Latitude': lat, 'Longitude': lon
                })
            except (ValueError, IndexError):
                continue

        if not points_data:
            flash('No valid coordinates found', 'error')
            return redirect(url_for('converter'))

        zip_buffer = io.BytesIO()
        base_name = os.path.splitext(file.filename)[0]
        
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            # CSV
            csv_buffer = io.StringIO()
            csv_writer = csv.writer(csv_buffer)
            csv_writer.writerow(['ID', 'Station', 'Xcoord', 'Ycoord', 'Latitude', 'Longitude'])
            for point in points_data:
                csv_writer.writerow([point['ID'], point['Station'], point['Xcoord'], 
                                   point['Ycoord'], point['Latitude'], point['Longitude']])
            zip_file.writestr(f'{base_name}_converted.csv', csv_buffer.getvalue())
            
            # Simple KML
            kml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document><name>{base_name}</name>'''
            for point in points_data:
                kml_content += f'''
<Placemark>
<name>{point["Station"]}</name>
<Point><coordinates>{point["Longitude"]},{point["Latitude"]},0</coordinates></Point>
</Placemark>'''
            kml_content += '</Document></kml>'
            zip_file.writestr(f'{base_name}.kml', kml_content)

        conversion_record = ConversionRecord(
            user_id=current_user.id,
            filename=file.filename,
            points_converted=len(points_data)
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
    app.run(host='0.0.0.0', port=8080, debug=False)