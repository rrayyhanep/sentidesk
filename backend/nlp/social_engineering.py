"""Detect coercion, impersonation and sensitive-data requests."""
import re


def detect_social_engineering(text: str) -> dict:
    lower = text.lower()
    indicators = []
    patterns = {
        "urgency": r"\b(urgent|immediately|right now|within \d+ hours|asap)\b",
        "authority_impersonation": r"\b(ceo|manager|director|bank|security team|support team)\b",
        "secret_request": r"\b(password|otp|verification code|secret|private key)\b",
        "financial_request": r"\b(gift card|wire|transfer|bitcoin|crypto|payment)\b",
        "threat": r"\b(suspended|terminated|legal action|police|penalty)\b",
    }
    for name, pattern in patterns.items():
        if re.search(pattern, lower):
            indicators.append(name)
    score = min(100, len(indicators) * 22)
    return {"detected": score >= 44, "risk_score": score, "indicators": indicators}
