from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import json
import uuid
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass
from math import radians, sin, cos, sqrt, atan2
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ✅ SINGLE Flask app instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'safescape-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///safescape.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Database Models (keep your existing models here)
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    traveler_type = db.Column(db.String(50), default='solo_female')
    accessibility_needs = db.Column(db.JSON, default=list)
    safety_preferences = db.Column(db.JSON, default=list)
    emergency_contacts = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    hazard_reports = db.relationship('HazardReport', backref='reporter', lazy=True)
    safety_statuses = db.relationship('SafetyStatus', backref='user', lazy=True)
    locations = db.relationship('UserLocation', backref='user', lazy=True)

class HazardReport(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    issue_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accessibility_impacts = db.Column(db.JSON, default=list)
    ai_analysis = db.Column(db.JSON)
    verification_count = db.Column(db.Integer, default=0)
    verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SafetyStatus(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserLocation(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_shared = db.Column(db.Boolean, default=False)

class EmergencyService(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.Text)
    phone = db.Column(db.String(20))
    available_24x7 = db.Column(db.Boolean, default=True)
    city = db.Column(db.String(100))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SOSAlert(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')
    emergency_services_notified = db.Column(db.Boolean, default=False)
    contacts_notified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)

@dataclass
class SafetyScore:
    score: int
    level: str
    factors: Dict
    recommendations: List[str]

# Utility Functions (keep your existing utility functions)

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371
    lat1_rad = radians(lat1)
    lon1_rad = radians(lon1)
    lat2_rad = radians(lat2)
    lon2_rad = radians(lon2)
    
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    a = sin(dlat/2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c

def analyze_hazard_severity(description: str, issue_type: str) -> Dict:
    keywords = {
        'critical': ['attack', 'assault', 'weapon', 'fire', 'collapse', 'emergency', 'danger', 'violent'],
        'high': ['harassment', 'threat', 'unsafe', 'dangerous', 'avoid', 'warning', 'chase', 'follow'],
        'medium': ['broken', 'damaged', 'dark', 'no light', 'crowded', 'busy', 'congested'],
        'low': ['inconvenience', 'minor', 'annoying', 'bother', 'slight', 'small']
    }
    
    type_weights = {
        'harassment_zone': 8, 'broken_road': 3, 'no_streetlight': 4, 'poor_visibility': 5,
        'unsafe_crowd': 6, 'transport_issue': 3, 'accessibility': 2, 'other': 1
    }
    
    description_lower = description.lower()
    severity_score = 0
    
    for severity_level, words in keywords.items():
        for word in words:
            if word in description_lower:
                severity_score += {'critical': 10, 'high': 6, 'medium': 3, 'low': 1}[severity_level]
    
    length_factor = min(len(description) / 50, 2)
    severity_score += length_factor
    severity_score += type_weights.get(issue_type, 1)
    
    if severity_score >= 15: suggested_severity = 'critical'
    elif severity_score >= 10: suggested_severity = 'high'
    elif severity_score >= 5: suggested_severity = 'medium'
    else: suggested_severity = 'low'
    
    return {
        'severity': suggested_severity,
        'confidence': min(severity_score / 20 * 100, 100),
        'factors': {
            'keyword_score': severity_score,
            'description_length': len(description),
            'type_weight': type_weights.get(issue_type, 1)
        }
    }

def calculate_area_safety_score(latitude: float, longitude: float, radius_km: float = 0.5) -> SafetyScore:
    recent_hazards = HazardReport.query.filter(
        HazardReport.status == 'active',
        HazardReport.created_at >= datetime.utcnow() - timedelta(days=7)
    ).all()
    
    nearby_hazards = []
    for hazard in recent_hazards:
        distance = calculate_distance(latitude, longitude, hazard.latitude, hazard.longitude)
        if distance <= radius_km:
            nearby_hazards.append(hazard)
    
    score = 100
    severity_weights = {'low': 2, 'medium': 5, 'high': 10, 'critical': 20}
    
    for hazard in nearby_hazards:
        weight = severity_weights.get(hazard.severity, 1)
        if hazard.verified: weight *= 1.5
        score -= weight
    
    hour = datetime.utcnow().hour
    if hour < 6 or hour > 20: score -= 10
    
    score = max(0, min(100, score))
    
    if score >= 80:
        level = 'Very Safe'
        recommendations = ["Normal precautions recommended", "Stay aware of surroundings"]
    elif score >= 60:
        level = 'Safe'
        recommendations = ["Remain vigilant", "Stick to well-lit areas"]
    elif score >= 40:
        level = 'Moderate'
        recommendations = ["Travel with companions if possible", "Avoid isolated areas", "Share your location"]
    elif score >= 20:
        level = 'Caution'
        recommendations = ["Avoid this area if possible", "Travel with companions", "Share live location", "Use main roads only"]
    else:
        level = 'Unsafe'
        recommendations = ["Avoid this area entirely", "Use alternative routes", "Travel in groups only", "Keep emergency contacts ready"]
    
    return SafetyScore(
        score=round(score),
        level=level,
        factors={'nearby_hazards': len(nearby_hazards), 'recent_hazards': len([h for h in nearby_hazards if h.verified]), 'time_of_day': 'night' if hour < 6 or hour > 20 else 'day'},
        recommendations=recommendations
    )

# ✅ SINGLE Root Route
@app.route('/')
def home():
    return jsonify({
        "message": "SafeScape API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "auth": ["/auth/register", "/auth/login"],
            "user": ["/user/profile", "/user/location", "/user/status"],
            "safety": ["/safety/reports", "/safety/score", "/safety/emergency-services"],
            "emergency": ["/emergency/sos", "/emergency/contacts"]
        }
    })

# Health check
@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })

# Authentication Routes
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['email', 'password', 'name']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "User already exists"}), 409
        
        user = User(
            email=data['email'],
            password_hash=bcrypt.generate_password_hash(data['password']).decode('utf-8'),
            name=data['name'],
            phone=data.get('phone'),
            traveler_type=data.get('traveler_type', 'solo_female'),
            accessibility_needs=data.get('accessibility_needs', []),
            safety_preferences=data.get('safety_preferences', []),
            emergency_contacts=data.get('emergency_contacts', [])
        )
        
        db.session.add(user)
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            "message": "User created successfully",
            "user": {"id": user.id, "email": user.email, "name": user.name, "traveler_type": user.traveler_type},
            "access_token": access_token
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Add your other routes here (login, user profile, safety routes, etc.)
# Keep the rest of your route implementations...

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        if EmergencyService.query.count() == 0:
            sample_services = [
                EmergencyService(name="Delhi Police Station", type="police", latitude=28.6328, longitude=77.2197, phone="100", city="Delhi"),
                EmergencyService(name="AIIMS Hospital", type="hospital", latitude=28.5673, longitude=77.2101, phone="108", city="Delhi"),
            ]
            for service in sample_services:
                db.session.add(service)
            db.session.commit()
            logger.info("Sample emergency services added to database")

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)