"""Combine independent signals into an explainable risk score."""


def calculate_risk(phishing: dict, social: dict, sentiment: dict | None = None) -> dict:
    score = min(100, phishing.get("risk_score", 0) * 0.65 + social.get("risk_score", 0) * 0.35)
    if sentiment and sentiment.get("label") == "negative":
        score = min(100, score + 5)
    score = round(score)
    return {"risk_score": score, "risk_level": "high" if score >= 60 else "medium" if score >= 25 else "low",
            "reasons": phishing.get("indicators", []) + social.get("indicators", [])}
