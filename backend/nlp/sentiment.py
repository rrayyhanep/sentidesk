"""Sentiment analysis heuristics suitable for a demo/offline service."""
from __future__ import annotations

import re

POSITIVE = {"good", "great", "excellent", "thanks", "thank", "happy", "love", "helpful", "resolved", "perfect"}
NEGATIVE = {"bad", "angry", "hate", "worst", "terrible", "awful", "frustrated", "fraud", "scam", "broken", "error", "urgent"}


def analyze_sentiment(text: str) -> dict:
    words = re.findall(r"[a-z']+", text.lower())
    positive = sum(word in POSITIVE for word in words)
    negative = sum(word in NEGATIVE for word in words)
    score = (positive - negative) / max(len(words), 1)
    if score > 0.025:
        label = "positive"
    elif score < -0.025:
        label = "negative"
    else:
        label = "neutral"
    return {"label": label, "score": round(max(-1.0, min(1.0, score)), 3), "positive_count": positive, "negative_count": negative}
