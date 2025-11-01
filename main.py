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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
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

# Database Models
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
    
    # Relationships
    hazard_reports = db.relationship('HazardReport', backref='reporter', lazy=True)
    safety_statuses = db.relationship('SafetyStatus', backref='user', lazy=True)
    locations = db.relationship('UserLocation', backref='user', lazy=True)

class HazardReport(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    issue_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accessibility_impacts = db.Column(db.JSON, default=list)
    ai_analysis = db.Column(db.JSON)
    verification_count = db.Column(db.Integer, default=0)
    verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')  # active, resolved, false_report
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SafetyStatus(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # safe, concern, emergency
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
    type = db.Column(db.String(50), nullable=False)  # police, hospital, fire, support, shelter
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
    status = db.Column(db.String(20), default='active')  # active, responded, resolved
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

# Utility Functions
def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two points in kilometers using Haversine formula."""
    R = 6371  # Earth's radius in kilometers
    
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
    """AI-powered hazard severity analysis."""
    keywords = {
        'critical': ['attack', 'assault', 'weapon', 'fire', 'collapse', 'emergency', 'danger', 'violent'],
        'high': ['harassment', 'threat', 'unsafe', 'dangerous', 'avoid', 'warning', 'chase', 'follow'],
        'medium': ['broken', 'damaged', 'dark', 'no light', 'crowded', 'busy', 'congested'],
        'low': ['inconvenience', 'minor', 'annoying', 'bother', 'slight', 'small']
    }
    
    type_weights = {
        'harassment_zone': 8,
        'broken_road': 3,
        'no_streetlight': 4,
        'poor_visibility': 5,
        'unsafe_crowd': 6,
        'transport_issue': 3,
        'accessibility': 2,
        'other': 1
    }
    
    description_lower = description.lower()
    severity_score = 0
    
    # Keyword analysis
    for severity_level, words in keywords.items():
        for word in words:
            if word in description_lower:
                severity_score += {'critical': 10, 'high': 6, 'medium': 3, 'low': 1}[severity_level]
    
    # Length factor
    length_factor = min(len(description) / 50, 2)
    severity_score += length_factor
    
    # Type weight
    severity_score += type_weights.get(issue_type, 1)
    
    # Determine severity
    if severity_score >= 15:
        suggested_severity = 'critical'
    elif severity_score >= 10:
        suggested_severity = 'high'
    elif severity_score >= 5:
        suggested_severity = 'medium'
    else:
        suggested_severity = 'low'
    
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
    """Calculate safety score for an area based on nearby hazards."""
    # Get recent hazards in the area
    recent_hazards = HazardReport.query.filter(
        HazardReport.status == 'active',
        HazardReport.created_at >= datetime.utcnow() - timedelta(days=7)
    ).all()
    
    nearby_hazards = []
    for hazard in recent_hazards:
        distance = calculate_distance(latitude, longitude, hazard.latitude, hazard.longitude)
        if distance <= radius_km:
            nearby_hazards.append(hazard)
    
    # Calculate base score
    score = 100
    severity_weights = {'low': 2, 'medium': 5, 'high': 10, 'critical': 20}
    
    for hazard in nearby_hazards:
        weight = severity_weights.get(hazard.severity, 1)
        if hazard.verified:
            weight *= 1.5
        score -= weight
    
    # Time-based adjustment
    hour = datetime.utcnow().hour
    if hour < 6 or hour > 20:  # Night time
        score -= 10
    
    # Ensure score is within bounds
    score = max(0, min(100, score))
    
    # Determine safety level
    if score >= 80:
        level = 'Very Safe'
        recommendations = [
            "Normal precautions recommended",
            "Stay aware of surroundings"
        ]
    elif score >= 60:
        level = 'Safe'
        recommendations = [
            "Remain vigilant",
            "Stick to well-lit areas"
        ]
    elif score >= 40:
        level = 'Moderate'
        recommendations = [
            "Travel with companions if possible",
            "Avoid isolated areas",
            "Share your location"
        ]
    elif score >= 20:
        level = 'Caution'
        recommendations = [
            "Avoid this area if possible",
            "Travel with companions",
            "Share live location",
            "Use main roads only"
        ]
    else:
        level = 'Unsafe'
        recommendations = [
            "Avoid this area entirely",
            "Use alternative routes",
            "Travel in groups only",
            "Keep emergency contacts ready"
        ]
    
    return SafetyScore(
        score=round(score),
        level=level,
        factors={
            'nearby_hazards': len(nearby_hazards),
            'recent_hazards': len([h for h in nearby_hazards if h.verified]),
            'time_of_day': 'night' if hour < 6 or hour > 20 else 'day'
        },
        recommendations=recommendations
    )

# Routes
@app.route('/')
def home():
    return send_from_directory('templates', 'index_fixed.html')

@app.route('/original')
def original():
    return send_from_directory('templates', 'index.html')

@app.route('/api')
def api_info():
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
    try:
        # Test database connection
        db.session.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status,
        "version": "1.0.0"
    })

# Authentication Routes
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'name']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "User already exists"}), 409
        
        # Create new user
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
        
        # Create access token
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            "message": "User created successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "traveler_type": user.traveler_type
            },
            "access_token": access_token
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"error": "Email and password required"}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not bcrypt.check_password_hash(user.password_hash, data['password']):
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not user.is_active:
            return jsonify({"error": "Account deactivated"}), 403
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "traveler_type": user.traveler_type
            },
            "access_token": access_token
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@jwt.unauthorized_loader
def unauthorized_callback(error):
    return jsonify({"error": "Missing or invalid token"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"error": "Invalid token"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired"}), 401

# Initialize database and sample data
def init_db():
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Add sample emergency services if none exist
            if EmergencyService.query.count() == 0:
                sample_services = [
                    EmergencyService(
                        name="Delhi Police Station - Connaught Place",
                        type="police",
                        latitude=28.6328,
                        longitude=77.2197,
                        address="Connaught Place, New Delhi",
                        phone="100",
                        city="Delhi",
                        description="Main police station in central Delhi"
                    ),
                    EmergencyService(
                        name="AIIMS Hospital",
                        type="hospital",
                        latitude=28.5673,
                        longitude=77.2101,
                        address="Ansari Nagar, New Delhi",
                        phone="108",
                        city="Delhi",
                        description="Premier medical institute and hospital"
                    )
                ]
                
                for service in sample_services:
                    db.session.add(service)
                
                db.session.commit()
                logger.info("Sample emergency services added to database")
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)