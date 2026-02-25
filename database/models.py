# database/models.py — SQLAlchemy ORM Models
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ─── USERS ────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(16),  default="user", nullable=False)  # admin / user
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    activity_logs  = db.relationship("UserActivity", backref="user",
                                     lazy="dynamic", cascade="all, delete-orphan")
    detection_logs = db.relationship("DetectionLog", backref="created_by_user",
                                     lazy="dynamic", foreign_keys="DetectionLog.user_id")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == "admin"

    def to_dict(self):
        return {
            "id":         self.id,
            "username":   self.username,
            "email":      self.email,
            "role":       self.role,
            "is_active":  self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<User {self.username}>"


# ─── DETECTION LOGS ───────────────────────────────────────────────────────────
class DetectionLog(db.Model):
    __tablename__  = "detection_logs"
    id             = db.Column(db.Integer, primary_key=True)
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip      = db.Column(db.String(45), nullable=False)
    dest_ip        = db.Column(db.String(45), nullable=False)
    source_port    = db.Column(db.Integer,    nullable=True)
    dest_port      = db.Column(db.Integer,    nullable=True)
    protocol       = db.Column(db.String(8),  nullable=True)
    attack_type    = db.Column(db.String(32), nullable=False, index=True)
    classification = db.Column(db.String(16), nullable=False)   # Normal/Suspicious/Attack
    risk_score     = db.Column(db.Integer, default=0)            # 0–100
    confidence     = db.Column(db.Float,   default=0.0)
    user_id        = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    alert_sent     = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id":             self.id,
            "timestamp":      self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "source_ip":      self.source_ip,
            "dest_ip":        self.dest_ip,
            "source_port":    self.source_port or "—",
            "dest_port":      self.dest_port   or "—",
            "protocol":       self.protocol    or "—",
            "attack_type":    self.attack_type,
            "classification": self.classification,
            "risk_score":     self.risk_score,
            "confidence":     round(self.confidence * 100, 1),
            "alert_sent":     self.alert_sent,
        }

    def __repr__(self):
        return f"<DetectionLog #{self.id} {self.attack_type}>"


# ─── USER ACTIVITY ────────────────────────────────────────────────────────────
class UserActivity(db.Model):
    __tablename__ = "user_activity"
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    login_time    = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time   = db.Column(db.DateTime, nullable=True)
    ip_address    = db.Column(db.String(45), nullable=True)
    user_agent    = db.Column(db.String(200), nullable=True)
    action        = db.Column(db.String(64), default="LOGIN")

    def to_dict(self):
        duration = None
        if self.login_time and self.logout_time:
            secs     = int((self.logout_time - self.login_time).total_seconds())
            duration = f"{secs // 60}m {secs % 60}s"
        return {
            "id":          self.id,
            "username":    self.user.username if self.user else "—",
            "login_time":  self.login_time.strftime("%Y-%m-%d %H:%M:%S") if self.login_time else "",
            "logout_time": self.logout_time.strftime("%Y-%m-%d %H:%M:%S") if self.logout_time else "Active",
            "ip_address":  self.ip_address or "—",
            "duration":    duration or "—",
            "action":      self.action,
        }
