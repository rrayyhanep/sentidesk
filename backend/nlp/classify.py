"""Complaint classification into 4 categories with keyphrase issue extraction."""
import re

COMPLAINT_CATEGORIES = {
    "Billing & Refunds": ("charge", "invoice", "bill", "refund", "payment", "subscription", "double", "card", "money", "overcharged", "receipt"),
    "Technical & Software Issues": ("error", "bug", "not working", "broken", "crash", "slow", "freeze", "fail", "failed", "glitch", "issue", "screen"),
    "Delivery & Order Shipping": ("delivery", "ship", "shipping", "arrive", "tracking", "order", "package", "transit", "delay", "delayed", "courier", "lost"),
    "Account & Security": ("password", "account", "sign in", "login", "locked", "access", "unauthorized", "hacked", "security", "verify", "otp", "reset"),
}


def classify_intent(text: str) -> dict:
    lowered = text.lower()
    scores = {}
    for cat_name, terms in COMPLAINT_CATEGORIES.items():
        score = sum(1 for term in terms if re.search(r"\b" + re.escape(term) + r"\b", lowered))
        scores[cat_name] = score

    best_category, max_score = max(scores.items(), key=lambda item: item[1])
    if max_score == 0:
        if any(w in lowered for w in ("ship", "pack", "track", "item")):
            best_category = "Delivery & Order Shipping"
        elif any(w in lowered for w in ("pay", "price", "cost", r"\$")):
            best_category = "Billing & Refunds"
        elif any(w in lowered for w in ("user", "mail", "auth", "pass")):
            best_category = "Account & Security"
        else:
            best_category = "Technical & Software Issues"

    confidence = round(min(0.99, 0.55 + max_score * 0.12), 2)
    return {
        "intent": best_category,
        "category": best_category,
        "confidence": confidence,
        "scores": scores,
    }


def extract_issue_keyphrase(text: str, category: str = "") -> str:
    lowered = text.lower()
    
    # Specific negative pattern matching
    if "late" in lowered or "delayed" in lowered or "not arrived" in lowered or "where is" in lowered:
        return "Delayed Shipment & Delivery Issue"
    if "refund" in lowered or "overcharged" in lowered or "double charge" in lowered or "cancel" in lowered:
        return "Billing Dispute & Refund Request"
    if "login" in lowered or "password" in lowered or "locked" in lowered or "cant access" in lowered:
        return "Account Lockout & Access Failure"
    if "crash" in lowered or "error" in lowered or "bug" in lowered or "not working" in lowered:
        return "Application Crash & Technical Glitch"
    if "phishing" in lowered or "suspicious" in lowered or "unauthorized" in lowered or "verify" in lowered:
        return "Security Warning & Suspicious Activity"
    if "damaged" in lowered or "broken" in lowered or "wrong item" in lowered:
        return "Defective Product & Damage Report"

    # Category fallbacks
    if category == "Delivery & Order Shipping":
        return "Order Delivery & Shipping Inquiry"
    if category == "Billing & Refunds":
        return "Invoice & Payment Transaction Issue"
    if category == "Account & Security":
        return "Account Access & Credential Assistance"
    if category == "Technical & Software Issues":
        return "System Functionality & Bug Report"

    return "Customer Support Inquiry"

