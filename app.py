"""
app.py — AI-Based Intrusion Detection System
Main Flask application with all routes.
"""

import os
import json
import random
import threading
import datetime
import subprocess
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, Response)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect

from config import config
from database.models import db, User, DetectionLog, UserActivity
from alert_system import mail, send_attack_alert
from utils.feature_extraction import simulate_packet, packet_to_features, ATTACK_POOL
from utils.risk_calculator import calculate_risk_score, classify, risk_label

# ─── App Factory ──────────────────────────────────────────────────────────────
def create_app(config_name="default"):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    mail.init_app(app)
    csrf    = CSRFProtect(app)
    login_manager = LoginManager(app)
    login_manager.login_view     = "login"
    login_manager.login_message  = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Context processor: make current year available in all templates ────
    @app.context_processor
    def inject_globals():
        return {"current_year": datetime.datetime.now().year,
                "app_version": "2.0"}

    return app, csrf

app, csrf = create_app()


# ─── Decorators ───────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ─── Background simulation engine ─────────────────────────────────────────────
_engine_running = False
_engine_thread  = None

def _detection_loop():
    """Background thread: simulate detection every 3-8 seconds."""
    import time
    while _engine_running:
        with app.app_context():
            try:
                pkt        = simulate_packet()
                attack     = random.choice(ATTACK_POOL)
                confidence = round(random.uniform(0.65, 0.99), 3)
                risk       = calculate_risk_score(attack.upper(), confidence)
                cls        = classify(attack.upper(), risk)

                log = DetectionLog(
                    source_ip      = pkt["source_ip"],
                    dest_ip        = pkt["dest_ip"],
                    source_port    = pkt["source_port"],
                    dest_port      = pkt["dest_port"],
                    protocol       = pkt["protocol"],
                    attack_type    = attack.upper(),
                    classification = cls,
                    risk_score     = risk,
                    confidence     = confidence,
                    alert_sent     = False,
                )
                db.session.add(log)
                db.session.commit()

                # Send email if risk is high enough
                if risk >= app.config.get("RISK_THRESHOLD", 75) and not log.alert_sent:
                    sent = send_attack_alert(app, log)
                    if sent:
                        log.alert_sent = True
                        db.session.commit()

            except Exception as e:
                print(f"[ENGINE ERROR] {e}")
                db.session.rollback()

        time.sleep(random.uniform(3, 8))


# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "user")

        # ── Validation ───────────────────────────────────────────────────
        errors = []
        if len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if "@" not in email:
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered.")
        if User.query.filter_by(username=username).first():
            errors.append("Username already taken.")
        if role not in ("admin", "user"):
            role = "user"

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html",
                                   username=username, email=email)

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "")
        user     = User.query.filter_by(email=email).first()

        if user and user.is_active and user.check_password(password):
            login_user(user, remember=False)
            session.permanent = True

            # Log activity
            activity = UserActivity(
                user_id    = user.id,
                ip_address = request.remote_addr,
                user_agent = request.headers.get("User-Agent", "")[:200],
                action     = "LOGIN",
            )
            db.session.add(activity)
            db.session.commit()

            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    # Update logout time for current session
    activity = (UserActivity.query
                .filter_by(user_id=current_user.id)
                .filter(UserActivity.logout_time == None)
                .order_by(UserActivity.id.desc())
                .first())
    if activity:
        activity.logout_time = datetime.datetime.utcnow()
        db.session.commit()

    logout_user()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    # Stats for cards
    total_logs    = DetectionLog.query.count()
    total_attacks = DetectionLog.query.filter(
        DetectionLog.classification == "Attack").count()
    high_risk     = DetectionLog.query.filter(
        DetectionLog.risk_score >= 70).count()
    normal_count  = DetectionLog.query.filter(
        DetectionLog.classification == "Normal").count()

    # Recent 10 logs for live table
    recent = (DetectionLog.query
              .order_by(DetectionLog.id.desc())
              .limit(10).all())

    # Attack type distribution for charts
    from sqlalchemy import func
    dist = (db.session.query(DetectionLog.attack_type, func.count(DetectionLog.id))
            .group_by(DetectionLog.attack_type)
            .order_by(func.count(DetectionLog.id).desc())
            .all())
    chart_labels = [r[0] for r in dist]
    chart_data   = [r[1] for r in dist]

    return render_template("dashboard.html",
        total_logs    = total_logs,
        total_attacks = total_attacks,
        high_risk     = high_risk,
        normal_count  = normal_count,
        recent        = [r.to_dict() for r in recent],
        chart_labels  = json.dumps(chart_labels),
        chart_data    = json.dumps(chart_data),
        engine_running= _engine_running,
    )


# ─── FEATURE 1: LIVE TRAFFIC ──────────────────────────────────────────────────

@app.route("/live")
@login_required
def live_traffic():
    return render_template("live_traffic.html", engine_running=_engine_running)


@app.route("/api/live-feed")
@login_required
def api_live_feed():
    """AJAX endpoint — returns latest 15 detection logs as JSON."""
    logs = (DetectionLog.query
            .order_by(DetectionLog.id.desc())
            .limit(15).all())
    return jsonify({"logs": [l.to_dict() for l in logs],
                    "engine": _engine_running})


@app.route("/api/engine/start", methods=["POST"])
@login_required
@admin_required
def engine_start():
    global _engine_running, _engine_thread
    if not _engine_running:
        _engine_running = True
        _engine_thread  = threading.Thread(target=_detection_loop, daemon=True)
        _engine_thread.start()
    return jsonify({"status": "started"})


@app.route("/api/engine/stop", methods=["POST"])
@login_required
@admin_required
def engine_stop():
    global _engine_running
    _engine_running = False
    return jsonify({"status": "stopped"})


# ─── FEATURE 2: DETECTION LOGS ────────────────────────────────────────────────

@app.route("/logs")
@login_required
def detection_logs():
    page        = request.args.get("page", 1, type=int)
    search      = request.args.get("search", "").strip()
    filter_type = request.args.get("type", "")
    per_page    = 15

    query = DetectionLog.query

    if search:
        query = query.filter(
            (DetectionLog.source_ip.contains(search)) |
            (DetectionLog.dest_ip.contains(search))   |
            (DetectionLog.attack_type.contains(search))
        )
    if filter_type:
        query = query.filter(DetectionLog.classification == filter_type)

    pagination = (query.order_by(DetectionLog.id.desc())
                       .paginate(page=page, per_page=per_page, error_out=False))

    return render_template("logs.html",
        logs       = pagination.items,
        pagination = pagination,
        search     = search,
        filter_type= filter_type,
    )


@app.route("/logs/download")
@login_required
def download_logs():
    """Download all detection logs as CSV."""
    logs = DetectionLog.query.order_by(DetectionLog.id.desc()).all()
    lines = ["ID,Timestamp,Source IP,Dest IP,Source Port,Dest Port,Protocol,"
             "Attack Type,Classification,Risk Score,Confidence"]
    for l in logs:
        lines.append(
            f"{l.id},{l.timestamp},{l.source_ip},{l.dest_ip},"
            f"{l.source_port or ''},{l.dest_port or ''},{l.protocol or ''},"
            f"{l.attack_type},{l.classification},{l.risk_score},"
            f"{round(l.confidence*100,1)}%"
        )
    csv_data = "\n".join(lines)
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=ids_detection_logs.csv"})


@app.route("/logs/clear", methods=["POST"])
@login_required
@admin_required
def clear_logs():
    DetectionLog.query.delete()
    db.session.commit()
    flash("All detection logs cleared.", "success")
    return redirect(url_for("detection_logs"))


# ─── FEATURE 3: ATTACK STATISTICS ────────────────────────────────────────────

@app.route("/statistics")
@login_required
def statistics():
    from sqlalchemy import func
    # By type
    by_type = (db.session.query(DetectionLog.attack_type, func.count(DetectionLog.id))
               .group_by(DetectionLog.attack_type).all())
    # By classification
    by_cls  = (db.session.query(DetectionLog.classification, func.count(DetectionLog.id))
               .group_by(DetectionLog.classification).all())
    # Last 24h hourly
    since   = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    hourly  = (db.session.query(
                   func.strftime("%H:00", DetectionLog.timestamp).label("hour"),
                   func.count(DetectionLog.id).label("cnt"))
               .filter(DetectionLog.timestamp >= since)
               .group_by("hour").order_by("hour").all())

    total   = DetectionLog.query.count()
    attacks = DetectionLog.query.filter(DetectionLog.classification == "Attack").count()

    return render_template("statistics.html",
        by_type      = json.dumps({r[0]: r[1] for r in by_type}),
        by_cls       = json.dumps({r[0]: r[1] for r in by_cls}),
        hourly_labels= json.dumps([r[0] for r in hourly]),
        hourly_data  = json.dumps([r[1] for r in hourly]),
        total        = total,
        attacks      = attacks,
        attack_rate  = round(attacks / total * 100, 1) if total else 0,
    )


# ─── FEATURE 6: USER ACTIVITY ─────────────────────────────────────────────────

@app.route("/activity")
@login_required
def user_activity():
    if current_user.is_admin():
        logs = (UserActivity.query
                .order_by(UserActivity.id.desc())
                .limit(100).all())
    else:
        logs = (UserActivity.query
                .filter_by(user_id=current_user.id)
                .order_by(UserActivity.id.desc())
                .limit(50).all())
    return render_template("user_activity.html", logs=[l.to_dict() for l in logs])


# ─── FEATURE 7: MODEL MANAGEMENT (Admin) ─────────────────────────────────────

@app.route("/model")
@login_required
@admin_required
def model_management():
    metrics_path = app.config.get("METRICS_PATH",
                                   os.path.join("models", "metrics.json"))
    metrics = None
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            metrics = json.load(f)

    model_exists = os.path.exists(
        app.config.get("MODEL_PATH", os.path.join("models", "best_model.pkl")))

    return render_template("model_management.html",
        metrics      = metrics,
        model_exists = model_exists,
    )


@app.route("/model/retrain", methods=["POST"])
@login_required
@admin_required
def retrain_model():
    """Trigger model retraining in background."""
    def _retrain():
        try:
            subprocess.run(["python", "model_training.py"], check=True,
                           capture_output=True, text=True)
            print("[RETRAIN] Completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[RETRAIN ERROR] {e.stderr}")

    t = threading.Thread(target=_retrain, daemon=True)
    t.start()
    flash("Model retraining started. This may take a few minutes.", "info")
    return redirect(url_for("model_management"))


# ─── USERS MANAGEMENT (Admin) ─────────────────────────────────────────────────

@app.route("/users")
@login_required
@admin_required
def users_list():
    users = User.query.order_by(User.id).all()
    return render_template("users.html", users=users)


@app.route("/users/<int:uid>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(uid):
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
    else:
        user.is_active = not user.is_active
        db.session.commit()
        state = "activated" if user.is_active else "deactivated"
        flash(f"User {user.username} {state}.", "success")
    return redirect(url_for("users_list"))


# ─── RISK API (for live meter) ────────────────────────────────────────────────

@app.route("/api/check-username")
def check_username():
    u = request.args.get("u", "").strip()
    available = len(u) >= 3 and not User.query.filter_by(username=u).first()
    return jsonify({"available": available})


@app.route("/api/risk-summary")
@login_required
def api_risk_summary():
    total  = DetectionLog.query.count() or 1
    high   = DetectionLog.query.filter(DetectionLog.risk_score >= 70).count()
    medium = DetectionLog.query.filter(
        DetectionLog.risk_score >= 40, DetectionLog.risk_score < 70).count()
    low    = DetectionLog.query.filter(DetectionLog.risk_score < 40).count()
    last   = DetectionLog.query.order_by(DetectionLog.id.desc()).first()
    return jsonify({
        "high":         high,
        "medium":       medium,
        "low":          low,
        "total":        total,
        "high_pct":     round(high   / total * 100),
        "medium_pct":   round(medium / total * 100),
        "low_pct":      round(low    / total * 100),
        "last_risk":    last.risk_score if last else 0,
        "last_type":    last.attack_type if last else "—",
    })


# ─── INIT & RUN ───────────────────────────────────────────────────────────────

def init_db():
    """Create all tables and seed default admin user."""
    with app.app_context():
        db.create_all()
        # Seed admin
        if not User.query.filter_by(email="admin@ids.local").first():
            admin = User(username="admin", email="admin@ids.local", role="admin")
            admin.set_password("Admin@1234")
            db.session.add(admin)
            db.session.commit()
            print("[INIT] Admin created  →  admin@ids.local / Admin@1234")
        # Seed 30 demo detection logs
        if DetectionLog.query.count() == 0:
            _seed_demo_logs()
            print("[INIT] Demo logs seeded.")


def _seed_demo_logs(n=40):
    attack_pool = (["NORMAL"]*20 + ["DOS"]*7 + ["PROBE"]*5 +
                   ["R2L"]*4 + ["U2R"]*2 + ["DDOS"]*4 + ["BRUTE_FORCE"]*3)
    ips  = [f"192.168.{random.randint(1,5)}.{random.randint(1,254)}" for _ in range(15)]
    now  = datetime.datetime.utcnow()
    for i in range(n):
        atk  = random.choice(attack_pool)
        conf = round(random.uniform(0.65, 0.99), 3)
        risk = calculate_risk_score(atk, conf)
        cls  = classify(atk, risk)
        log  = DetectionLog(
            timestamp   = now - datetime.timedelta(minutes=i * 4),
            source_ip   = random.choice(ips),
            dest_ip     = f"10.0.0.{random.randint(1,5)}",
            source_port = random.randint(1024, 65535),
            dest_port   = random.choice([80, 443, 22, 21, 3306]),
            protocol    = random.choice(["TCP","UDP","ICMP"]),
            attack_type = atk,
            classification = cls,
            risk_score  = risk,
            confidence  = conf,
        )
        db.session.add(log)
    db.session.commit()


if __name__ == "__main__":
    init_db()
    print("\n╔════════════════════════════════════════╗")
    print("   AI-IDS  →  http://localhost:5000")
    print("   Admin:   admin@ids.local / Admin@1234")
    print("╚════════════════════════════════════════╝\n")
    app.run(debug=True, use_reloader=False)
