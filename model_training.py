#!/usr/bin/env python3
"""
model_training.py — Train ML models for IDS
================================================
Usage:
    python model_training.py
    python model_training.py --data data/KDDTrain+.txt
"""

import os
import sys
import json
import argparse
import warnings

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

warnings.filterwarnings("ignore")

# ── Directory paths ──────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
STATIC_IMG_DIR = os.path.join(BASE_DIR, "static", "img")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(STATIC_IMG_DIR, exist_ok=True)

# ── NSL-KDD column names ─────────────────────────────────────────────────────
NSL_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_type", "difficulty",
]

# ── Attack type grouping ──────────────────────────────────────────────────────
ATTACK_MAP = {
    "normal": "NORMAL",
    # DoS
    "back": "DOS", "land": "DOS", "neptune": "DOS",
    "pod": "DOS", "smurf": "DOS", "teardrop": "DOS",
    "apache2": "DOS", "udpstorm": "DOS", "processtable": "DOS",
    # Probe
    "ipsweep": "PROBE", "nmap": "PROBE",
    "portsweep": "PROBE", "satan": "PROBE",
    "mscan": "PROBE", "saint": "PROBE",
    # R2L
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L",
    "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R",
    "perl": "U2R", "rootkit": "U2R",
    "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
}

# ── Model definitions ─────────────────────────────────────────────────────────
MODELS = {
    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=15,
        random_state=42,
    ),
    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        random_state=42,
        n_jobs=-1,
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def make_synthetic_data(n=3000):
    """
    Generate balanced synthetic training data.
    Guarantees every attack class appears in both train and test splits.
    """
    import random

    services = ["http", "ftp", "smtp", "ssh", "dns", "telnet"]
    protocols = ["tcp", "udp", "icmp"]
    flags = ["SF", "S0", "REJ", "RSTO"]

    # Fixed class list with guaranteed representation
    classes = ["NORMAL", "DOS", "PROBE", "R2L", "U2R"]
    # Each class gets at least 100 samples; distribute the rest randomly
    per_class = max(100, n // len(classes))

    rows = []
    for label in classes:
        for _ in range(per_class):
            row = {col: 0 for col in NSL_COLUMNS}
            row.update({
                "duration": random.randint(0, 1000),
                "protocol_type": random.choice(protocols),
                "service": random.choice(services),
                "flag": random.choice(flags),
                "src_bytes": random.randint(0, 100000),
                "dst_bytes": random.randint(0, 100000),
                "count": random.randint(0, 512),
                "srv_count": random.randint(0, 512),
                "serror_rate": round(random.random(), 2),
                "rerror_rate": round(random.random(), 2),
                "same_srv_rate": round(random.random(), 2),
                "dst_host_count": random.randint(0, 255),
                "dst_host_srv_count": random.randint(0, 255),
                "attack_type": label,
                "difficulty": 0,
            })
            rows.append(row)

    random.shuffle(rows)
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# PREPROCESSING
# ─────────────────────────────────────────────────────────────────────────────

def preprocess(df):
    """Encode categorical columns, scale features, encode labels."""
    df = df.copy()

    if "difficulty" in df.columns:
        df.drop("difficulty", axis=1, inplace=True)

    # Normalise labels — handle both raw NSL-KDD names and already-mapped names
    def map_label(x):
        x = str(x).strip().lower()
        # Already mapped to uppercase class (NORMAL, DOS, etc.)
        upper = x.upper()
        if upper in ("NORMAL", "DOS", "PROBE", "R2L", "U2R", "DDOS", "BRUTE_FORCE"):
            return upper
        # Raw NSL-KDD attack name
        return ATTACK_MAP.get(x, "NORMAL")

    df["attack_type"] = df["attack_type"].map(map_label)

    # Encode categorical features
    cat_cols = ["protocol_type", "service", "flag"]
    encoders = {}
    for col in cat_cols:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le

    y_raw = df["attack_type"].values
    X = df.drop("attack_type", axis=1).astype(float).values

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    le_label = LabelEncoder()
    y = le_label.fit_transform(y_raw)

    return X, y, scaler, encoders, le_label


# ─────────────────────────────────────────────────────────────────────────────
# PLOT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def save_confusion_matrix(model, X_test, y_test, label_encoder, model_name):
    """Save confusion matrix heatmap to static/img/."""
    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)

    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=label_encoder.classes_,
        yticklabels=label_encoder.classes_,
        ax=ax,
    )
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=13)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    plt.tight_layout()

    out = os.path.join(STATIC_IMG_DIR, "confusion_matrix.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [PLOT] Saved → {out}")


def save_feature_importance(model, feature_names, model_name):
    """Save top-15 feature importance chart (RF / DT only)."""
    if not hasattr(model, "feature_importances_"):
        return

    imp = model.feature_importances_
    names = feature_names[: len(imp)]
    top = np.argsort(imp)[-15:]

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(
        [names[i] for i in top],
        [imp[i] for i in top],
        color="#0d6efd",
    )
    ax.set_title(f"Feature Importance — {model_name}", fontsize=13)
    plt.tight_layout()

    out = os.path.join(STATIC_IMG_DIR, "feature_importance.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [PLOT] Saved → {out}")


def save_model_comparison(results):
    """Save accuracy vs F1 grouped bar chart for all models."""
    names = list(results.keys())
    accs = [results[n]["accuracy"] for n in names]
    f1s = [results[n]["f1_score"] for n in names]
    x = np.arange(len(names))

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - 0.2, accs, 0.4, label="Accuracy", color="#0d6efd", alpha=0.85)
    ax.bar(x + 0.2, f1s, 0.4, label="F1-Score", color="#20c997", alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(names)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Score (%)")
    ax.legend()
    ax.set_title("Model Comparison", fontsize=13)
    plt.tight_layout()

    out = os.path.join(STATIC_IMG_DIR, "model_comparison.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [PLOT] Saved → {out}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def train(data_path=None):
    """Train all models, pick the best, save artifacts and plots."""
    print("\n╔══════════════════════════════════════════╗")
    print("   IDS — Model Trainer v2.0")
    print("╚══════════════════════════════════════════╝\n")

    # ── Load data ─────────────────────────────────────────────────────────────
    if data_path and os.path.exists(data_path):
        print(f"[DATA] Loading dataset: {data_path}")
        df = pd.read_csv(data_path, header=None, names=NSL_COLUMNS)
    else:
        print("[DATA] No dataset — generating 2 000 synthetic samples.")
        print("[DATA] Tip: download NSL-KDD from https://www.unb.ca/cic/datasets/nsl.html")
        print("[DATA]      Run: python model_training.py --data data/KDDTrain+.txt\n")
        df = make_synthetic_data(n=2000)

    print(f"[DATA] Shape: {df.shape}")
    print(f"[DATA] Class distribution:\n{df['attack_type'].value_counts()}\n")

    # ── Preprocess ────────────────────────────────────────────────────────────
    X, y, scaler, encoders, le_label = preprocess(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    # ── Train each model ──────────────────────────────────────────────────────
    results = {}
    best_f1 = 0.0
    best_name = ""
    best_model = None

    for name, model in MODELS.items():
        print(f"[TRAIN] {name} ...")
        try:
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
        except Exception as exc:
            print(f"  [SKIP] {name} failed: {exc}")
            continue

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(
            y_test, y_pred, average="weighted", zero_division=0
        )
        rec = recall_score(
            y_test, y_pred, average="weighted", zero_division=0
        )
        f1 = f1_score(
            y_test, y_pred, average="weighted", zero_division=0
        )

        results[name] = {
            "accuracy":  round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall":    round(rec * 100, 2),
            "f1_score":  round(f1 * 100, 2),
        }
        print(
            f"  Acc={acc * 100:.1f}%  "
            f"Prec={prec * 100:.1f}%  "
            f"Rec={rec * 100:.1f}%  "
            f"F1={f1 * 100:.1f}%"
        )

        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model = model

    print(f"\n[BEST] {best_name}  (F1={best_f1 * 100:.1f}%)")

    # ── Save artifacts ────────────────────────────────────────────────────────
    joblib.dump(best_model, os.path.join(MODELS_DIR, "best_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    encoders["_label"] = le_label
    joblib.dump(encoders, os.path.join(MODELS_DIR, "encoders.pkl"))

    metrics = {
        "best_model": best_name,
        "results": results,
        "classes": list(le_label.classes_),
    }
    with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)

    print("[SAVE] best_model.pkl  scaler.pkl  encoders.pkl  metrics.json")

    # ── Generate plots ────────────────────────────────────────────────────────
    feature_names = np.array(
        [c for c in df.columns if c not in ("attack_type", "difficulty")]
    )
    save_confusion_matrix(best_model, X_test, y_test, le_label, best_name)
    save_feature_importance(best_model, feature_names, best_name)
    save_model_comparison(results)

    print("""
╔══════════════════════════════════════════╗
   TRAINING COMPLETE
   Artifacts : models/
   Charts    : static/img/
   Next step : python app.py
╚══════════════════════════════════════════╝
""")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train IDS ML models on NSL-KDD or synthetic data"
    )
    parser.add_argument(
        "--data",
        type=str,
        default=None,
        help="Path to NSL-KDD dataset file (e.g. data/KDDTrain+.txt)",
    )
    args = parser.parse_args()
    train(args.data)
