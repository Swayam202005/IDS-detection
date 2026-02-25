# AI-Based Intrusion Detection System (AI-IDS)
## Complete Setup Guide

---

## 📁 Project Structure

```
ids_project/
├── app.py                    ← Flask application (all routes)
├── config.py                 ← App configuration
├── model_training.py         ← Train ML models
├── alert_system.py           ← Email alert system
├── requirements.txt          ← Python dependencies
│
├── database/
│   └── ids.db                ← Auto-created SQLite database
│
├── models/
│   ├── best_model.pkl        ← Trained ML model (auto-generated)
│   ├── scaler.pkl            ← Feature scaler
│   ├── encoders.pkl          ← Label encoders
│   └── metrics.json          ← Model performance metrics
│
├── templates/
│   ├── base.html             ← Master layout (sidebar + topbar)
│   ├── login.html            ← Login page
│   ├── register.html         ← Registration page
│   ├── dashboard.html        ← Main dashboard
│   ├── live_traffic.html     ← Live traffic monitoring
│   ├── logs.html             ← Detection logs + search + CSV
│   ├── statistics.html       ← Charts & analytics
│   ├── user_activity.html    ← Login/logout history
│   ├── model_management.html ← ML model metrics & retrain
│   └── users.html            ← Admin user management
│
├── static/
│   ├── css/style.css         ← Full dark theme stylesheet
│   ├── js/dashboard.js       ← Live feed + risk meter
│   └── img/                  ← Generated chart images
│
└── utils/
    ├── feature_extraction.py ← Packet simulation & features
    └── risk_calculator.py    ← Risk score calculation
```

---

## ⚙️ Step-by-Step Setup

### Step 1: Install Python (3.9+)
Download from https://python.org/downloads

### Step 2: Create virtual environment
```bash
cd ids_project
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

### Step 3: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Train the ML model
```bash
python model_training.py
```
This generates:
- `models/best_model.pkl`
- `models/scaler.pkl`
- `models/encoders.pkl`
- `models/metrics.json`
- `static/img/confusion_matrix.png`
- `static/img/feature_importance.png`
- `static/img/model_comparison.png`

To use a real dataset (NSL-KDD):
```bash
python model_training.py --data data/KDDTrain+.txt
```

### Step 5: Run the application
```bash
python app.py
```

Open browser: **http://localhost:5000**

---

## 🔐 Default Login Credentials

| Field    | Value             |
|----------|-------------------|
| Email    | admin@ids.local   |
| Password | Admin@1234        |
| Role     | Administrator     |

---

## 📧 Email Alerts Setup (Optional)

Set environment variables before running:

**Windows:**
```cmd
set MAIL_USERNAME=your.email@gmail.com
set MAIL_PASSWORD=your_app_password
set ALERT_EMAIL=admin@yourdomain.com
```

**Linux/Mac:**
```bash
export MAIL_USERNAME=your.email@gmail.com
export MAIL_PASSWORD=your_app_password
export ALERT_EMAIL=admin@yourdomain.com
```

For Gmail: Use an **App Password** (not your Gmail password).
Enable 2FA → Google Account → Security → App Passwords

---

## 🎯 Dashboard Features

| Feature | Description |
|---------|-------------|
| Live Traffic | Real-time detection feed, auto-refresh every 3s |
| Detection Logs | Paginated table, search, CSV download |
| Attack Statistics | Pie chart, bar chart, 24h timeline |
| Email Alerts | Auto email when risk > 75% |
| Risk Indicator | SVG arc meter, color-coded bars |
| User Activity | Login/logout history per user |
| Model Management | Accuracy, F1, confusion matrix, retrain |

---

## 🤖 ML Models Trained

| Model | Notes |
|-------|-------|
| Random Forest | Best performer, saved as best_model.pkl |
| Decision Tree | Fast, interpretable |
| Logistic Regression | Baseline linear model |

**Attack Classes:**
- NORMAL — Benign traffic
- DOS — Denial of Service
- PROBE — Network scanning
- R2L — Remote to Local
- U2R — User to Root
- DDOS — Distributed DoS
- BRUTE_FORCE — Password attacks

---

## 🔒 Security Features

- Werkzeug password hashing (PBKDF2)
- Flask-WTF CSRF protection (all forms)
- Session timeout (30 min)
- Role-based access control (Admin / User)
- SQLAlchemy ORM (prevents SQL injection)
- Input validation on all forms

---

## 🛠 Troubleshooting

**"No module named flask"**
→ Make sure your virtual environment is activated and you ran `pip install -r requirements.txt`

**"No model found"**
→ Run `python model_training.py` first

**Charts not showing**
→ Run `python model_training.py` to generate the image files

**Email not sending**
→ Set MAIL_USERNAME and MAIL_PASSWORD environment variables. Use a Gmail App Password, not your regular password.

**Port 5000 already in use**
→ Change port in app.py: `app.run(port=5001)`

---

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/live-feed | GET | Latest 15 detection logs (JSON) |
| /api/risk-summary | GET | Risk distribution percentages |
| /api/engine/start | POST | Start simulation engine (admin) |
| /api/engine/stop | POST | Stop simulation engine (admin) |
| /api/check-username | GET | Check username availability |
| /logs/download | GET | Download all logs as CSV |
