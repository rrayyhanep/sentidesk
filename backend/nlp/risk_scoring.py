"""Combine independent signals into an explainable 4-tier risk score."""


def calculate_risk(phishing: dict, social: dict, sentiment: dict | None = None) -> dict:
    score = min(100, phishing.get("risk_score", 0) * 0.65 + social.get("risk_score", 0) * 0.35)
    if sentiment and sentiment.get("label") == "negative":
        score = min(100, score + 10)
    score = round(score)
    
    if score >= 75:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": list(dict.fromkeys(phishing.get("indicators", []) + social.get("indicators", []))),
    }

