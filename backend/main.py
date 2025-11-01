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
    return send_from_directory('templates', 'index.html')


@app.route('/api')
def api_info():
    return jsonify({
        "message": "SafeScape API",
        "version": "1.0.0",
        "endpoints": {
            "auth": ["/auth/register", "/auth/login"],
            "user": ["/user/profile", "/user/location", "/user/status"],
            "safety": ["/safety/reports", "/safety/score", "/safety/emergency-services"],
            "emergency": ["/emergency/sos", "/emergency/contacts"]
        }
    })

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('../static', filename)

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

# User Routes
@app.route('/user/profile', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if request.method == 'GET':
            return jsonify({
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "phone": user.phone,
                "traveler_type": user.traveler_type,
                "accessibility_needs": user.accessibility_needs,
                "safety_preferences": user.safety_preferences,
                "emergency_contacts": user.emergency_contacts,
                "created_at": user.created_at.isoformat()
            }), 200
        
        elif request.method == 'PUT':
            data = request.get_json()
            
            # Update user fields
            updatable_fields = ['name', 'phone', 'traveler_type', 'accessibility_needs', 
                              'safety_preferences', 'emergency_contacts']
            
            for field in updatable_fields:
                if field in data:
                    setattr(user, field, data[field])
            
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                "message": "Profile updated successfully",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "traveler_type": user.traveler_type
                }
            }), 200
            
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/user/location', methods=['POST'])
@jwt_required()
def update_location():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        required_fields = ['latitude', 'longitude']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        location = UserLocation(
            user_id=user_id,
            latitude=data['latitude'],
            longitude=data['longitude'],
            accuracy=data.get('accuracy'),
            is_shared=data.get('is_shared', False)
        )
        
        db.session.add(location)
        db.session.commit()
        
        return jsonify({
            "message": "Location updated successfully",
            "location": {
                "latitude": location.latitude,
                "longitude": location.longitude,
                "timestamp": location.timestamp.isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Location update error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/user/status', methods=['POST', 'GET'])
@jwt_required()
def safety_status():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if request.method == 'POST':
            data = request.get_json()
            
            if 'status' not in data:
                return jsonify({"error": "Status is required"}), 400
            
            status = SafetyStatus(
                user_id=user_id,
                status=data['status'],
                latitude=data.get('latitude'),
                longitude=data.get('longitude'),
                notes=data.get('notes')
            )
            
            db.session.add(status)
            db.session.commit()
            
            # If emergency status, trigger alerts
            if data['status'] == 'emergency':
                # In a real implementation, this would notify emergency contacts and services
                logger.info(f"EMERGENCY ALERT: User {user_id} triggered SOS at {data.get('latitude')}, {data.get('longitude')}")
            
            return jsonify({
                "message": "Safety status updated",
                "status": {
                    "status": status.status,
                    "timestamp": status.created_at.isoformat()
                }
            }), 200
        
        elif request.method == 'GET':
            # Get latest status
            latest_status = SafetyStatus.query.filter_by(user_id=user_id)\
                .order_by(SafetyStatus.created_at.desc())\
                .first()
            
            status_data = None
            if latest_status:
                status_data = {
                    "status": latest_status.status,
                    "latitude": latest_status.latitude,
                    "longitude": latest_status.longitude,
                    "notes": latest_status.notes,
                    "timestamp": latest_status.created_at.isoformat()
                }
            
            return jsonify({
                "current_status": status_data
            }), 200
            
    except Exception as e:
        logger.error(f"Safety status error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Safety Routes
@app.route('/safety/reports', methods=['GET', 'POST'])
@jwt_required()
def hazard_reports():
    try:
        user_id = get_jwt_identity()
        
        if request.method == 'POST':
            data = request.get_json()
            
            required_fields = ['issue_type', 'severity', 'description', 'latitude', 'longitude']
            for field in required_fields:
                if field not in data:
                    return jsonify({"error": f"Missing required field: {field}"}), 400
            
            # Validate description length
            if len(data['description'].strip()) < 10:
                return jsonify({"error": "Description must be at least 10 characters long"}), 400
            
            if len(data['description']) > 500:
                return jsonify({"error": "Description must be less than 500 characters"}), 400
            
            # AI analysis
            ai_analysis = analyze_hazard_severity(data['description'], data['issue_type'])
            
            # Use AI-suggested severity if it's higher than user-reported
            severity_weights = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            user_severity_weight = severity_weights.get(data['severity'], 1)
            ai_severity_weight = severity_weights.get(ai_analysis['severity'], 1)
            
            final_severity = data['severity']
            if ai_severity_weight > user_severity_weight:
                final_severity = ai_analysis['severity']
            
            report = HazardReport(
                user_id=user_id,
                issue_type=data['issue_type'],
                severity=final_severity,
                description=data['description'].strip(),
                latitude=data['latitude'],
                longitude=data['longitude'],
                accessibility_impacts=data.get('accessibility_impacts', []),
                ai_analysis={
                    **ai_analysis,
                    'reporter_name': data.get('reporter_name', 'Anonymous'),
                    'reporter_contact': data.get('reporter_contact'),
                    'location_address': data.get('location_address'),
                    'report_source': data.get('report_source', 'SafeScape API'),
                    'original_severity': data['severity']
                }
            )
            
            db.session.add(report)
            db.session.commit()
            
            return jsonify({
                "message": "Hazard report submitted successfully",
                "report": {
                    "id": report.id,
                    "issue_type": report.issue_type,
                    "severity": report.severity,
                    "description": report.description,
                    "latitude": report.latitude,
                    "longitude": report.longitude,
                    "accessibility_impacts": report.accessibility_impacts,
                    "ai_analysis": report.ai_analysis,
                    "verification_count": report.verification_count,
                    "verified": report.verified,
                    "created_at": report.created_at.isoformat()
                },
                "success": True
            }), 201
        
        elif request.method == 'GET':
            # Get query parameters
            latitude = request.args.get('lat', type=float)
            longitude = request.args.get('lng', type=float)
            radius = request.args.get('radius', 5, type=float)  # km
            issue_type = request.args.get('type')
            verified_only = request.args.get('verified', 'false').lower() == 'true'
            
            query = HazardReport.query.filter(HazardReport.status == 'active')
            
            # Filter by type if provided
            if issue_type:
                query = query.filter(HazardReport.issue_type == issue_type)
            
            # Filter by verified if requested
            if verified_only:
                query = query.filter(HazardReport.verified == True)
            
            reports = query.order_by(HazardReport.created_at.desc()).limit(100).all()
            
            # Filter by distance if coordinates provided
            if latitude and longitude:
                nearby_reports = []
                for report in reports:
                    distance = calculate_distance(latitude, longitude, report.latitude, report.longitude)
                    if distance <= radius:
                        report_data = {
                            "id": report.id,
                            "issue_type": report.issue_type,
                            "severity": report.severity,
                            "description": report.description,
                            "latitude": report.latitude,
                            "longitude": report.longitude,
                            "accessibility_impacts": report.accessibility_impacts,
                            "verified": report.verified,
                            "verification_count": report.verification_count,
                            "ai_analysis": report.ai_analysis,
                            "created_at": report.created_at.isoformat(),
                            "distance_km": round(distance, 2)
                        }
                        nearby_reports.append(report_data)
                
                return jsonify({"reports": nearby_reports}), 200
            
            # Return all reports without distance calculation
            reports_data = [{
                "id": report.id,
                "issue_type": report.issue_type,
                "severity": report.severity,
                "description": report.description,
                "latitude": report.latitude,
                "longitude": report.longitude,
                "accessibility_impacts": report.accessibility_impacts,
                "verified": report.verified,
                "verification_count": report.verification_count,
                "created_at": report.created_at.isoformat()
            } for report in reports]
            
            return jsonify({"reports": reports_data}), 200
            
    except Exception as e:
        logger.error(f"Hazard reports error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/safety/reports/<report_id>/verify', methods=['POST'])
@jwt_required()
def verify_report(report_id):
    try:
        user_id = get_jwt_identity()
        report = HazardReport.query.get(report_id)
        
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        # In a real implementation, you might want to track which users verified which reports
        report.verification_count += 1
        
        # Auto-verify if enough users have verified
        if report.verification_count >= 3:
            report.verified = True
        
        db.session.commit()
        
        return jsonify({
            "message": "Report verified successfully",
            "verification_count": report.verification_count,
            "verified": report.verified
        }), 200
        
    except Exception as e:
        logger.error(f"Verify report error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/safety/score', methods=['GET'])
@jwt_required()
def safety_score():
    try:
        latitude = request.args.get('lat', type=float)
        longitude = request.args.get('lng', type=float)
        radius = request.args.get('radius', 0.5, type=float)
        
        if not latitude or not longitude:
            return jsonify({"error": "Latitude and longitude parameters required"}), 400
        
        safety_score = calculate_area_safety_score(latitude, longitude, radius)
        
        return jsonify({
            "safety_score": safety_score.score,
            "safety_level": safety_score.level,
            "factors": safety_score.factors,
            "recommendations": safety_score.recommendations,
            "location": {
                "latitude": latitude,
                "longitude": longitude,
                "radius_km": radius
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Safety score error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/safety/emergency-services', methods=['GET'])
@jwt_required()
def emergency_services():
    try:
        latitude = request.args.get('lat', type=float)
        longitude = request.args.get('lng', type=float)
        radius = request.args.get('radius', 10, type=float)  # km
        service_type = request.args.get('type')
        
        query = EmergencyService.query
        
        # Filter by type if provided
        if service_type:
            query = query.filter(EmergencyService.type == service_type)
        
        services = query.all()
        
        # Calculate distances and filter
        nearby_services = []
        for service in services:
            if latitude and longitude:
                distance = calculate_distance(latitude, longitude, service.latitude, service.longitude)
                if distance <= radius:
                    service_data = {
                        "id": service.id,
                        "name": service.name,
                        "type": service.type,
                        "latitude": service.latitude,
                        "longitude": service.longitude,
                        "address": service.address,
                        "phone": service.phone,
                        "available_24x7": service.available_24x7,
                        "city": service.city,
                        "description": service.description,
                        "distance_km": round(distance, 2)
                    }
                    nearby_services.append(service_data)
            else:
                # Return all services without distance
                service_data = {
                    "id": service.id,
                    "name": service.name,
                    "type": service.type,
                    "latitude": service.latitude,
                    "longitude": service.longitude,
                    "address": service.address,
                    "phone": service.phone,
                    "available_24x7": service.available_24x7,
                    "city": service.city,
                    "description": service.description
                }
                nearby_services.append(service_data)
        
        # Sort by distance if coordinates provided
        if latitude and longitude:
            nearby_services.sort(key=lambda x: x['distance_km'])
        
        return jsonify({"services": nearby_services}), 200
        
    except Exception as e:
        logger.error(f"Emergency services error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Emergency Routes
@app.route('/emergency/sos', methods=['POST'])
@jwt_required()
def sos_alert():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        required_fields = ['latitude', 'longitude']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Create SOS alert
        sos = SOSAlert(
            user_id=user_id,
            latitude=data['latitude'],
            longitude=data['longitude'],
            message=data.get('message', 'Emergency assistance needed'),
            emergency_services_notified=True,  # In real implementation, actually notify services
            contacts_notified=True  # In real implementation, notify emergency contacts
        )
        
        db.session.add(sos)
        
        # Update user safety status to emergency
        status = SafetyStatus(
            user_id=user_id,
            status='emergency',
            latitude=data['latitude'],
            longitude=data['longitude'],
            notes=data.get('message', 'SOS activated')
        )
        db.session.add(status)
        
        db.session.commit()
        
        # In a real implementation, you would:
        # 1. Send SMS/email to emergency contacts
        # 2. Notify nearby emergency services
        # 3. Trigger push notifications to responders
        
        logger.info(f"SOS ALERT: User {user_id} at {data['latitude']}, {data['longitude']}")
        
        return jsonify({
            "message": "SOS alert activated. Help is on the way!",
            "alert_id": sos.id,
            "responders_notified": True,
            "contacts_notified": True
        }), 201
        
    except Exception as e:
        logger.error(f"SOS alert error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/emergency/contacts', methods=['GET'])
@jwt_required()
def emergency_contacts():
    try:
        city = request.args.get('city', 'delhi')
        
        # City-specific emergency contacts
        contacts_data = {
            'delhi': {
                'police': '100',
                'ambulance': '108',
                'women_helpline': '1091',
                'fire': '101',
                'disaster_management': '108'
            },
            'mumbai': {
                'police': '100',
                'ambulance': '108',
                'women_helpline': '103',
                'fire': '101',
                'disaster_management': '108'
            },
            'bangalore': {
                'police': '100',
                'ambulance': '108',
                'women_helpline': '1091',
                'fire': '101',
                'disaster_management': '108'
            },
            'jaipur': {
                'police': '100',
                'ambulance': '108',
                'women_helpline': '1090',
                'fire': '101',
                'disaster_management': '108'
            },
            'lucknow': {
                'police': '100',
                'ambulance': '108',
                'women_helpline': '1090',
                'fire': '101',
                'disaster_management': '108'
            },
            'gurugram': {
                'police': '100',
                'ambulance': '108',
                'women_helpline': '1091',
                'fire': '101',
                'disaster_management': '108'
            }
        }
        
        contacts = contacts_data.get(city.lower(), contacts_data['delhi'])
        
        return jsonify({
            "city": city,
            "contacts": contacts,
            "message": f"Emergency contacts for {city}"
        }), 200
        
    except Exception as e:
        logger.error(f"Emergency contacts error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Admin Routes (for data management)
@app.route('/admin/emergency-services', methods=['POST'])
def add_emergency_service():
    try:
        data = request.get_json()
        
        required_fields = ['name', 'type', 'latitude', 'longitude']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        service = EmergencyService(
            name=data['name'],
            type=data['type'],
            latitude=data['latitude'],
            longitude=data['longitude'],
            address=data.get('address'),
            phone=data.get('phone'),
            available_24x7=data.get('available_24x7', True),
            city=data.get('city'),
            description=data.get('description')
        )
        
        db.session.add(service)
        db.session.commit()
        
        return jsonify({
            "message": "Emergency service added successfully",
            "service": {
                "id": service.id,
                "name": service.name,
                "type": service.type,
                "location": {
                    "latitude": service.latitude,
                    "longitude": service.longitude
                }
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Add emergency service error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Health check
@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected" if db.session.execute("SELECT 1").first() else "disconnected"
    })

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
        db.create_all()
        
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
                ),
                EmergencyService(
                    name="Mumbai Police Headquarters",
                    type="police",
                    latitude=19.0760,
                    longitude=72.8777,
                    address="Crawford Market, Mumbai",
                    phone="100",
                    city="Mumbai",
                    description="Main police headquarters in Mumbai"
                )
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