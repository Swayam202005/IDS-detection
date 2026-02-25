# alert_system.py — Email Alert System
from flask_mail import Mail, Message
from flask import current_app

mail = Mail()


def send_attack_alert(app, log_entry):
    """
    Send email alert when a high-risk attack is detected.
    Requires MAIL_USERNAME and MAIL_PASSWORD in config.
    """
    if not app.config.get("MAIL_USERNAME"):
        print("[ALERT] Email not configured — skipping alert.")
        return False

    try:
        recipient = app.config.get("ALERT_EMAIL", app.config["MAIL_USERNAME"])
        subject   = f"[IDS ALERT] {log_entry.attack_type} Detected — Risk {log_entry.risk_score}%"

        body = f"""
==============================================
  AI-BASED INTRUSION DETECTION SYSTEM ALERT
==============================================

A high-risk network intrusion has been detected.

  Attack Type    : {log_entry.attack_type}
  Classification : {log_entry.classification}
  Risk Score     : {log_entry.risk_score}/100
  Confidence     : {round(log_entry.confidence * 100, 1)}%
  Source IP      : {log_entry.source_ip}
  Destination IP : {log_entry.dest_ip}
  Protocol       : {log_entry.protocol or 'Unknown'}
  Timestamp      : {log_entry.timestamp}

Immediate investigation recommended.

----------------------------------------------
AI-IDS Automated Alert System
"""
        with app.app_context():
            msg = Message(subject=subject, recipients=[recipient], body=body)
            mail.send(msg)
        print(f"[ALERT] Email sent to {recipient}")
        return True

    except Exception as e:
        print(f"[ALERT ERROR] Failed to send email: {e}")
        return False
