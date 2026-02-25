# config.py — Application Configuration
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    # ── Flask ──────────────────────────────────────────────────────────────
    SECRET_KEY       = os.environ.get("SECRET_KEY", "ids-super-secret-key-2024")
    DEBUG            = False

    # ── Database ───────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI        = f"sqlite:///{os.path.join(BASE_DIR, 'database', 'ids.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Session ────────────────────────────────────────────────────────────
    PERMANENT_SESSION_LIFETIME     = 1800   # 30 minutes auto-logout
    SESSION_COOKIE_HTTPONLY        = True
    SESSION_COOKIE_SAMESITE        = "Lax"

    # ── Email Alerts ───────────────────────────────────────────────────────
    MAIL_SERVER   = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
    MAIL_PORT     = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS  = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")   # your email
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")   # your app password
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_USERNAME", "ids@system.local")
    ALERT_EMAIL   = os.environ.get("ALERT_EMAIL",   "admin@yourdomain.com")
    RISK_THRESHOLD = 75     # Send alert if risk_score >= this value

    # ── ML Model ───────────────────────────────────────────────────────────
    MODEL_PATH   = os.path.join(BASE_DIR, "models", "best_model.pkl")
    SCALER_PATH  = os.path.join(BASE_DIR, "models", "scaler.pkl")
    ENCODER_PATH = os.path.join(BASE_DIR, "models", "encoders.pkl")
    METRICS_PATH = os.path.join(BASE_DIR, "models", "metrics.json")

    # ── WTF ────────────────────────────────────────────────────────────────
    WTF_CSRF_ENABLED      = True
    WTF_CSRF_TIME_LIMIT   = 3600

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "default":     DevelopmentConfig,
}
