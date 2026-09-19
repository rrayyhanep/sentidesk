"""Sentiment analysis heuristics for dynamic email and review text evaluation."""
from __future__ import annotations

import re

POSITIVE = {
    "good", "great", "excellent", "thanks", "thank", "happy", "love", "helpful",
    "resolved", "perfect", "satisfied", "amazing", "wonderful", "fast", "fixed",
    "recommend", "solved", "fantastic", "glad", "awesome", "prompt", "smooth",
    "pleased", "impressed", "superb", "brilliant", "enjoyed", "appreciation"
}

NEGATIVE = {
    "bad", "angry", "hate", "worst", "terrible", "awful", "frustrated", "fraud",
    "scam", "broken", "error", "urgent", "disappointed", "unhappy", "fail", "failed",
    "crash", "bug", "delayed", "late", "overcharged", "refund", "horrible",
    "unacceptable", "useless", "waste", "stolen", "loss", "issue", "problem",
    "wrong", "damage", "damaged", "locked", "hacked", "suspended", "denied",
    "charge", "cancel", "canceled", "cancelling", "slow", "freeze", "glitch"
}


def analyze_sentiment(text: str) -> dict:
    words = re.findall(r"[a-z']+", text.lower())
    positive = sum(word in POSITIVE for word in words)
    negative = sum(word in NEGATIVE for word in words)
    
    total = positive + negative
    if total == 0:
        score = 0.0
        label = "neutral"
    else:
        score = (positive - negative) / max(len(words), 1)
        if positive > negative:
            label = "positive"
        elif negative > positive:
            label = "negative"
        else:
            label = "neutral"

    return {
        "label": label,
        "score": round(max(-1.0, min(1.0, score * 10)), 3),
        "positive_count": positive,
        "negative_count": negative,
    }

