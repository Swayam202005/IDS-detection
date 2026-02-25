# utils/risk_calculator.py — Risk score & classification logic

ATTACK_WEIGHTS = {
    "U2R":         100,
    "R2L":         90,
    "DDOS":        88,
    "DOS":         80,
    "BRUTE_FORCE": 75,
    "PROBE":       55,
    "NORMAL":      0,
}


def calculate_risk_score(attack_type: str, confidence: float) -> int:
    """Return 0-100 risk score."""
    base   = ATTACK_WEIGHTS.get(attack_type.upper(), 60)
    score  = int(base * confidence)
    return min(score, 100)


def classify(attack_type: str, risk_score: int) -> str:
    """Return Normal / Suspicious / Attack label."""
    if attack_type.upper() == "NORMAL":
        return "Normal"
    if risk_score >= 70:
        return "Attack"
    return "Suspicious"


def risk_color(risk_score: int) -> str:
    """Bootstrap color class for risk level."""
    if risk_score >= 70:
        return "danger"
    if risk_score >= 40:
        return "warning"
    return "success"


def risk_label(risk_score: int) -> str:
    if risk_score >= 70:
        return "HIGH"
    if risk_score >= 40:
        return "MEDIUM"
    return "LOW"
