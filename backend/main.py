"""
SafeScape - backend/main.py
Single-file deploy-ready Flask backend for Render.
Features:
 - Serves frontend index.html (templates/static)
 - User auth (register/login) with JWT
 - User profile, location, status
 - Hazard reports: submit, list, verify
 - SOS alerts
 - Emergency services lookup
 - Safety score calculation
 - Simple in-memory rate-limiter
 - Background worker to auto-flag suspicious reports
 - Twilio/SendGrid hooks (optional via env)
"""

import os
import uuid
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from math import radians, sin, cos, sqrt, atan2
from functools import wraps
from collections import defaultdict, deque

from flask import (
    Flask, request, jsonify, render_template, send_from_directory, abort
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

# Optional notification libs (used only if environment variables present)
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
except Exception:
    SendGridAPIClient = None

# ------------------------------
# Paths (Render expects static/templates in repo)
# ------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))           # backend/
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")             # backend/templates
STATIC_DIR = os.path.join(BASE_DIR, "static")                   # backend/static

# ------------------------------
# App and config
# ------------------------------
app = Flask(
    __name__,
    static_folder=STATIC_DIR,
    template_folder=TEMPLATES_DIR
)

# Basic configuration
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "safescape-secret-key-2024")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///safescape.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret-key-2024")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("safescape")

# ------------------------------
# Notification clients (optional)
# ------------------------------
TWILIO_SID = os.environ.get("TWILIO_SID")
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN")
TWILIO_FROM = os.environ.get("TWILIO_FROM")

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
NOTIFY_FROM_EMAIL = os.environ.get("NOTIFY_FROM_EMAIL")  # e.g. no-reply@safescape.app

twilio_client = None
if TWILIO_SID and TWILIO_TOKEN and TwilioClient:
    try:
        twilio_client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
        logger.info("Twilio client initialized")
    except Exception as e:
        logger.warning("Twilio init failed: %s", e)

sendgrid_client = None
if SENDGRID_API_KEY and SendGridAPIClient:
    try:
        sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
        logger.info("SendGrid client initialized")
    except Exception as e:
        logger.warning("SendGrid init failed: %s", e)

# ------------------------------
# Simple in-memory rate limiter
# (process-local; for prod use Redis + a real limiter)
# ------------------------------
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))  # requests per minute per IP
_rate_limit_store = defaultdict(lambda: deque())

def rate_limited(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        now = time.time()
        dq = _rate_limit_store[ip]
        # Pop old
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= RATE_LIMIT:
            return jsonify({"error": "Too many requests"}), 429
        dq.append(now)
        return func(*args, **kwargs)
    return wrapper

# ------------------------------
# Background worker: flag suspicious reports
# - Simple heuristic: too many reports from same IP or identical content
# ------------------------------
_suspicious_queue = deque()
_stop_worker = threading.Event()

def suspicious_worker():
    """Runs in background; inspects new reports and auto-flags suspicious ones."""
    seen_text = defaultdict(int)
    seen_ip = defaultdict(int)
    while not _stop_worker.is_set():
        try:
            while _suspicious_queue:
                item = _suspicious_queue.popleft()
                # item: dict with keys: report_id, ip, description, created_at
                desc = (item.get("description") or "").strip().lower()
                ip = item.get("ip")
                report_id = item.get("report_id")
                seen_text[desc] += 1
                seen_ip[ip] += 1
                # If same exact text reported > 3 times within process lifetime -> flag
                if seen_text[desc] >= 3 or seen_ip[ip] >= 10:
                    # mark report as false_report with a reason
                    try:
                        report = HazardReport.query.get(report_id)
                        if report and report.status == "active":
                            report.status = "false_report"
                            report.verified = False
                            db.session.commit()
                            logger.info("Auto-flagged report %s as suspicious", report_id)
                    except Exception as e:
                        logger.error("Worker flag error: %s", e)
        except Exception as e:
            logger.exception("Suspicious worker loop error: %s", e)
        time.sleep(2)

_worker_thread = threading.Thread(target=suspicious_worker, daemon=True)
_worker_thread.start()

# ------------------------------
# Models
# ------------------------------
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    traveler_type = db.Column(db.String(50), default="solo_female")
    accessibility_needs = db.Column(db.JSON, default=list)
    safety_preferences = db.Column(db.JSON, default=list)
    emergency_contacts = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    hazard_reports = db.relationship("HazardReport", backref="reporter", lazy=True)
    safety_statuses = db.relationship("SafetyStatus", backref="user", lazy=True)
    locations = db.relationship("UserLocation", backref="user", lazy=True)

class HazardReport(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    issue_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accessibility_impacts = db.Column(db.JSON, default=list)
    ai_analysis = db.Column(db.JSON)
    verification_count = db.Column(db.Integer, default=0)
    verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default="active")  # active, resolved, false_report
    reporter_ip = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SafetyStatus(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # safe, concern, emergency
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserLocation(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
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
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default="active")  # active, responded, resolved
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

# ------------------------------
# Utility helpers
# ------------------------------
def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in kilometers."""
    R = 6371
    lat1_rad, lon1_rad, lat2_rad, lon2_rad = map(radians, [lat1, lon1, lat2, lon2])
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    a = sin(dlat/2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

def analyze_hazard_severity(description: str, issue_type: str) -> Dict:
    """Lightweight keyword-based severity analysis (placeholder for ML)."""
    keywords = {
        'critical': ['attack', 'assault', 'weapon', 'fire', 'collapse', 'emergency', 'danger', 'violent'],
        'high': ['harassment', 'threat', 'unsafe', 'dangerous', 'avoid', 'warning', 'chase', 'follow'],
        'medium': ['broken', 'damaged', 'dark', 'no light', 'crowded', 'busy', 'congested'],
        'low': ['inconvenience', 'minor', 'annoying', 'bother', 'slight', 'small']
    }
    type_weights = {'harassment_zone': 8, 'broken_road': 3, 'no_streetlight': 4, 'poor_visibility': 5, 'unsafe_crowd': 6, 'transport_issue': 3, 'accessibility': 2, 'other': 1}
    description_lower = (description or "").lower()
    score = 0
    for severity_level, words in keywords.items():
        for w in words:
            if w in description_lower:
                score += {'critical': 10, 'high': 6, 'medium': 3, 'low': 1}[severity_level]
    score += min(len(description_lower) / 50, 2)
    score += type_weights.get(issue_type, 1)
    if score >= 15:
        sev = 'critical'
    elif score >= 10:
        sev = 'high'
    elif score >= 5:
        sev = 'medium'
    else:
        sev = 'low'
    return {'severity': sev, 'confidence': min(score / 20 * 100, 100), 'factors': {'score': score, 'len': len(description_lower), 'type_weight': type_weights.get(issue_type, 1)}}

def calculate_area_safety_score(latitude: float, longitude: float, radius_km: float = 0.5) -> SafetyScore:
    """Aggregate safety score for area using recent hazards."""
    recent_hazards = HazardReport.query.filter(HazardReport.status == 'active', HazardReport.created_at >= datetime.utcnow() - timedelta(days=7)).all()
    nearby = []
    for h in recent_hazards:
        d = calculate_distance(latitude, longitude, h.latitude, h.longitude)
        if d <= radius_km:
            nearby.append(h)
    score = 100
    severity_weights = {'low': 2, 'medium': 5, 'high': 10, 'critical': 20}
    for hazard in nearby:
        w = severity_weights.get(hazard.severity, 1)
        if hazard.verified:
            w *= 1.5
        score -= w
    hour = datetime.utcnow().hour
    if hour < 6 or hour > 20:
        score -= 10
    score = max(0, min(100, round(score)))
    if score >= 80:
        level = 'Very Safe'
        recs = ["Normal precautions", "Stay aware"]
    elif score >= 60:
        level = 'Safe'
        recs = ["Remain vigilant", "Prefer well-lit routes"]
    elif score >= 40:
        level = 'Moderate'
        recs = ["Avoid isolated areas", "Share live location"]
    elif score >= 20:
        level = 'Caution'
        recs = ["Travel with companions", "Use main roads"]
    else:
        level = 'Unsafe'
        recs = ["Avoid area", "Seek alternatives", "Notify contacts"]
    return SafetyScore(score=score, level=level, factors={'nearby_hazards': len(nearby)}, recommendations=recs)

def notify_contacts_by_sms(phone: str, message: str) -> bool:
    if not twilio_client or not TWILIO_FROM:
        logger.debug("Twilio not configured; skipping SMS to %s", phone)
        return False
    try:
        twilio_client.messages.create(body=message, from_=TWILIO_FROM, to=phone)
        return True
    except Exception as e:
        logger.error("Twilio send failed: %s", e)
        return False

def notify_by_email(to_email: str, subject: str, content: str) -> bool:
    if not sendgrid_client or not NOTIFY_FROM_EMAIL:
        logger.debug("SendGrid not configured; skipping email to %s", to_email)
        return False
    try:
        mail = Mail(from_email=NOTIFY_FROM_EMAIL, to_emails=to_email, subject=subject, plain_text_content=content)
        sendgrid_client.send(mail)
        return True
    except Exception as e:
        logger.error("SendGrid send failed: %s", e)
        return False

# ------------------------------
# Routes - Frontend serving
# ------------------------------
@app.route("/")
def root():
    # Render the main SPA index
    try:
        return render_template("index.html")
    except Exception as e:
        logger.error("Template render error: %s", e)
        # Try fallback to static index if templates misplaced
        idx_path = os.path.join(os.path.dirname(BASE_DIR), "templates", "index.html")
        if os.path.exists(idx_path):
            return send_from_directory(os.path.dirname(idx_path), "index.html")
        return jsonify({"error": "index.html not found on server"}), 500

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)

# ------------------------------
# Routes - API
# ------------------------------
@app.route("/api")
def api_info():
    return jsonify({"message": "SafeScape API", "version": "1.0.0"})

# --- Auth endpoints ---
@app.route("/auth/register", methods=["POST"])
@rate_limited
def register():
    data = request.get_json() or {}
    required = ["email", "password", "name"]
    for r in required:
        if r not in data or not data[r]:
            return jsonify({"error": f"Missing required field: {r}"}), 400
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "User already exists"}), 409
    pw_hash = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    user = User(
        email=data["email"],
        password_hash=pw_hash,
        name=data["name"],
        phone=data.get("phone"),
        traveler_type=data.get("traveler_type", "solo_female"),
        accessibility_needs=data.get("accessibility_needs", []),
        safety_preferences=data.get("safety_preferences", []),
        emergency_contacts=data.get("emergency_contacts", [])
    )
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        logger.exception("User create error: %s", e)
        db.session.rollback()
        return jsonify({"error": "Failed to create user"}), 500
    token = create_access_token(identity=user.id)
    return jsonify({"message": "User created", "user": {"id": user.id, "email": user.email, "name": user.name}, "access_token": token}), 201

@app.route("/auth/login", methods=["POST"])
@rate_limited
def login():
    data = request.get_json() or {}
    if "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=data["email"]).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"error": "Account deactivated"}), 403
    token = create_access_token(identity=user.id)
    return jsonify({"message": "Login successful", "user": {"id": user.id, "email": user.email, "name": user.name}, "access_token": token}), 200

# --- User endpoints ---
@app.route("/user/profile", methods=["GET", "PUT"])
@jwt_required()
def user_profile():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if request.method == "GET":
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
    data = request.get_json() or {}
    fields = ["name", "phone", "traveler_type", "accessibility_needs", "safety_preferences", "emergency_contacts"]
    for f in fields:
        if f in data:
            setattr(user, f, data[f])
    user.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Profile updated", "user": {"id": user.id, "email": user.email, "name": user.name}}), 200

@app.route("/user/location", methods=["POST"])
@jwt_required()
def update_location():
    uid = get_jwt_identity()
    data = request.get_json() or {}
    if "latitude" not in data or "longitude" not in data:
        return jsonify({"error": "latitude and longitude required"}), 400
    loc = UserLocation(user_id=uid, latitude=data["latitude"], longitude=data["longitude"], accuracy=data.get("accuracy"), is_shared=data.get("is_shared", False))
    db.session.add(loc)
    db.session.commit()
    return jsonify({"message": "Location saved", "location": {"latitude": loc.latitude, "longitude": loc.longitude, "timestamp": loc.timestamp.isoformat()}}), 200

@app.route("/user/status", methods=["POST", "GET"])
@jwt_required()
def user_status():
    uid = get_jwt_identity()
    if request.method == "POST":
        data = request.get_json() or {}
        if "status" not in data:
            return jsonify({"error": "status is required"}), 400
        s = SafetyStatus(user_id=uid, status=data["status"], latitude=data.get("latitude"), longitude=data.get("longitude"), notes=data.get("notes"))
        db.session.add(s)
        db.session.commit()
        if data.get("status") == "emergency":
            logger.info("EMERGENCY status from user %s at %s,%s", uid, data.get("latitude"), data.get("longitude"))
        return jsonify({"message": "Status saved", "timestamp": s.created_at.isoformat()}), 200
    else:
        latest = SafetyStatus.query.filter_by(user_id=uid).order_by(SafetyStatus.created_at.desc()).first()
        if not latest:
            return jsonify({"current_status": None}), 200
        return jsonify({"current_status": {"status": latest.status, "latitude": latest.latitude, "longitude": latest.longitude, "notes": latest.notes, "timestamp": latest.created_at.isoformat()}}), 200

# --- Safety / Hazard Reports ---
@app.route("/safety/reports", methods=["GET", "POST"])
@jwt_required()
def safety_reports():
    uid = get_jwt_identity()
    if request.method == "POST":
        data = request.get_json() or {}
        required = ["issue_type", "severity", "description", "latitude", "longitude"]
        for r in required:
            if r not in data:
                return jsonify({"error": f"Missing required field: {r}"}), 400
        desc = data["description"].strip()
        if len(desc) < 10:
            return jsonify({"error": "Description must be at least 10 characters"}), 400
        if len(desc) > 1000:
            return jsonify({"error": "Description too long"}), 400
        ai = analyze_hazard_severity(desc, data["issue_type"])
        # Use AI-suggested severity if more severe
        weights = {'low':1,'medium':2,'high':3,'critical':4}
        user_w = weights.get(data["severity"], 1)
        ai_w = weights.get(ai.get("severity"), 1)
        final_sev = data["severity"] if user_w >= ai_w else ai.get("severity")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        report = HazardReport(
            user_id=uid,
            issue_type=data["issue_type"],
            severity=final_sev,
            description=desc,
            latitude=data["latitude"],
            longitude=data["longitude"],
            accessibility_impacts=data.get("accessibility_impacts", []),
            ai_analysis={**ai, "original_severity": data["severity"]},
            reporter_ip=ip
        )
        try:
            db.session.add(report)
            db.session.commit()
            # push to suspicious worker queue
            _suspicious_queue.append({"report_id": report.id, "ip": ip, "description": desc, "created_at": str(report.created_at)})
        except Exception as e:
            logger.exception("Error saving report: %s", e)
            db.session.rollback()
            return jsonify({"error": "Unable to save report"}), 500
        return jsonify({"message": "Report submitted", "report": {"id": report.id, "severity": report.severity, "created_at": report.created_at.isoformat()}}), 201
    # GET
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    radius = request.args.get("radius", 5.0, type=float)
    issue_type = request.args.get("type")
    verified_only = request.args.get("verified", "false").lower() == "true"
    query = HazardReport.query.filter(HazardReport.status == "active")
    if issue_type:
        query = query.filter(HazardReport.issue_type == issue_type)
    if verified_only:
        query = query.filter(HazardReport.verified == True)
    reports = query.order_by(HazardReport.created_at.desc()).limit(200).all()
    if lat and lng:
        nearby = []
        for r in reports:
            d = calculate_distance(lat, lng, r.latitude, r.longitude)
            if d <= radius:
                nearby.append({
                    "id": r.id,
                    "issue_type": r.issue_type,
                    "severity": r.severity,
                    "description": r.description,
                    "latitude": r.latitude,
                    "longitude": r.longitude,
                    "verified": r.verified,
                    "verification_count": r.verification_count,
                    "ai_analysis": r.ai_analysis,
                    "created_at": r.created_at.isoformat(),
                    "distance_km": round(d,2)
                })
        return jsonify({"reports": nearby}), 200
    reports_data = [{
        "id": r.id,
        "issue_type": r.issue_type,
        "severity": r.severity,
        "description": r.description,
        "latitude": r.latitude,
        "longitude": r.longitude,
        "verified": r.verified,
        "verification_count": r.verification_count,
        "created_at": r.created_at.isoformat()
    } for r in reports]
    return jsonify({"reports": reports_data}), 200

@app.route("/safety/reports/<report_id>/verify", methods=["POST"])
@jwt_required()
def verify_report(report_id):
    uid = get_jwt_identity()
    report = HazardReport.query.get(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    report.verification_count += 1
    if report.verification_count >= 3:
        report.verified = True
    db.session.commit()
    return jsonify({"message": "Report verified", "verification_count": report.verification_count, "verified": report.verified}), 200

@app.route("/safety/score", methods=["GET"])
@jwt_required()
def safety_score():
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    radius = request.args.get("radius", 0.5, type=float)
    if lat is None or lng is None:
        return jsonify({"error": "lat and lng required"}), 400
    score = calculate_area_safety_score(lat, lng, radius)
    return jsonify({"safety_score": score.score, "safety_level": score.level, "factors": score.factors, "recommendations": score.recommendations}), 200

@app.route("/safety/emergency-services", methods=["GET"])
@jwt_required()
def get_emergency_services():
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    radius = request.args.get("radius", 10.0, type=float)
    service_type = request.args.get("type")
    query = EmergencyService.query
    if service_type:
        query = query.filter(EmergencyService.type == service_type)
    services = query.all()
    res = []
    for s in services:
        if lat and lng:
            d = calculate_distance(lat, lng, s.latitude, s.longitude)
            if d <= radius:
                res.append({"id": s.id, "name": s.name, "type": s.type, "latitude": s.latitude, "longitude": s.longitude, "address": s.address, "phone": s.phone, "available_24x7": s.available_24x7, "city": s.city, "description": s.description, "distance_km": round(d,2)})
        else:
            res.append({"id": s.id, "name": s.name, "type": s.type, "latitude": s.latitude, "longitude": s.longitude, "address": s.address, "phone": s.phone, "available_24x7": s.available_24x7, "city": s.city, "description": s.description})
    if lat and lng:
        res = sorted(res, key=lambda x: x.get("distance_km", 999))
    return jsonify({"services": res}), 200

# --- Emergency / SOS ---
@app.route("/emergency/sos", methods=["POST"])
@jwt_required()
def sos_alert():
    uid = get_jwt_identity()
    data = request.get_json() or {}
    if "latitude" not in data or "longitude" not in data:
        return jsonify({"error": "latitude and longitude required"}), 400
    sos = SOSAlert(user_id=uid, latitude=data["latitude"], longitude=data["longitude"], message=data.get("message", "SOS"), emergency_services_notified=False, contacts_notified=False)
    db.session.add(sos)
    # also create a SafetyStatus entry
    status = SafetyStatus(user_id=uid, status="emergency", latitude=data["latitude"], longitude=data["longitude"], notes=data.get("message"))
    db.session.add(status)
    db.session.commit()
    # Notify: emergency contacts and services (best-effort)
    user = User.query.get(uid)
    msg = f"SOS from {user.name if user else uid}: {sos.message} at {sos.latitude},{sos.longitude}"
    # Notify contacts
    for c in (user.emergency_contacts or []):
        phone = c.get("phone") if isinstance(c, dict) else None
        email = c.get("email") if isinstance(c, dict) else None
        if phone:
            notify_contacts_by_sms(phone, msg)
        if email:
            notify_by_email(email, "SafeScape SOS Alert", msg)
    # Mark notified flags
    sos.emergency_services_notified = True
    sos.contacts_notified = True
    db.session.commit()
    logger.info("SOS created %s by %s", sos.id, uid)
    return jsonify({"message": "SOS activated", "alert_id": sos.id}), 201

@app.route("/emergency/contacts", methods=["GET"])
def emergency_contacts():
    city = request.args.get("city", "delhi").lower()
    contacts_data = {
        'delhi': {'police': '100', 'ambulance': '108', 'women_helpline': '1091', 'fire': '101', 'disaster_management': '108'},
        'mumbai': {'police': '100', 'ambulance': '108', 'women_helpline': '103', 'fire': '101', 'disaster_management': '108'},
        'bangalore': {'police': '100', 'ambulance': '108', 'women_helpline': '1091', 'fire': '101', 'disaster_management': '108'}
    }
    return jsonify({"city": city, "contacts": contacts_data.get(city, contacts_data['delhi'])}), 200

# --- Admin utilities ---
@app.route("/admin/emergency-services", methods=["POST"])
def add_emergency_service():
    data = request.get_json() or {}
    for f in ("name","type","latitude","longitude"):
        if f not in data:
            return jsonify({"error": f"Missing {f}"}), 400
    s = EmergencyService(name=data["name"], type=data["type"], latitude=data["latitude"], longitude=data["longitude"], address=data.get("address"), phone=data.get("phone"), available_24x7=data.get("available_24x7", True), city=data.get("city"), description=data.get("description"))
    db.session.add(s); db.session.commit()
    return jsonify({"message": "Added", "id": s.id}), 201

# --- Health check ---
@app.route("/health")
def health_check():
    try:
        db.session.execute("SELECT 1")
        return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "database": "connected"}), 200
    except Exception as e:
        logger.exception("DB health check failed: %s", e)
        return jsonify({"status": "unhealthy", "timestamp": datetime.utcnow().isoformat(), "database": "disconnected"}), 500

# ------------------------------
# Error handlers for JWT
# ------------------------------
@jwt.unauthorized_loader
def unauthorized_callback(err):
    return jsonify({"error": "Missing or invalid token"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(err):
    return jsonify({"error": "Invalid token"}), 401

@jwt.expired_token_loader
def expired_token_callback(header, payload):
    return jsonify({"error": "Token expired"}), 401

# ------------------------------
# Initialization: create DB, sample emergency services
# ------------------------------
def init_db(load_sample=True):
    with app.app_context():
        db.create_all()
        if load_sample and EmergencyService.query.count() == 0:
            sample = [
                EmergencyService(name="Delhi Police Station - Connaught Place", type="police", latitude=28.6328, longitude=77.2197, address="Connaught Place, New Delhi", phone="100", city="Delhi", description="Main police station in central Delhi"),
                EmergencyService(name="AIIMS Hospital", type="hospital", latitude=28.5673, longitude=77.2101, address="Ansari Nagar, New Delhi", phone="108", city="Delhi", description="Premier medical institute and hospital"),
                EmergencyService(name="Mumbai Police Headquarters", type="police", latitude=19.0760, longitude=72.8777, address="Crawford Market, Mumbai", phone="100", city="Mumbai", description="Main police headquarters in Mumbai")
            ]
            db.session.add_all(sample); db.session.commit()
            logger.info("Sample emergency services added")

# ------------------------------
# Graceful shutdown to stop worker
# ------------------------------
import atexit
@atexit.register
def shutdown():
    try:
        _stop_worker.set()
        if _worker_thread.is_alive():
            _worker_thread.join(timeout=2)
    except Exception:
        pass

# ------------------------------
# Start point
# ------------------------------
if __name__ == "__main__":
    init_db(load_sample=True)
    port = int(os.environ.get("PORT", 5000))
    # For local dev, you can use flask's builtin server.
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_ENV") != "production")
