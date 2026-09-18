"""Phishing indicators for customer messages (not a replacement for a gateway)."""
import re

URL_RE = re.compile(r"https?://[^\s<>]+", re.I)
SUSPICIOUS = ("verify", "suspended", "password", "click", "urgent", "gift card", "wire transfer", "otp", "one-time code", "crypto")


def detect_phishing(text: str) -> dict:
    lowered = text.lower()
    indicators = []
    urls = URL_RE.findall(text)
    if urls:
        indicators.append("contains_external_link")
    for term in SUSPICIOUS:
        if term in lowered:
            indicators.append("suspicious:" + term)
    if re.search(r"\b(password|otp|passcode|security code)\b", lowered) and re.search(r"\b(send|share|tell|provide|confirm)\b", lowered):
        indicators.append("credential_request")
    score = min(100, len(indicators) * 18 + (25 if len(urls) > 1 else 0))
    level = "high" if score >= 60 else "medium" if score >= 25 else "low"
    return {"is_phishing": score >= 50, "risk_score": score, "risk_level": level, "indicators": list(dict.fromkeys(indicators)), "urls": urls}
