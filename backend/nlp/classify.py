"""Intent classification with transparent keyword scoring."""
import re

INTENTS = {
    "billing": ("charge", "invoice", "bill", "refund", "payment", "subscription"),
    "technical_support": ("error", "bug", "not working", "broken", "login", "crash", "slow"),
    "account_access": ("password", "account", "sign in", "login", "locked", "access"),
    "delivery": ("delivery", "ship", "shipping", "arrive", "tracking", "order"),
    "cancellation": ("cancel", "unsubscribe", "close account"),
    "general_inquiry": ("what", "how", "when", "where", "help"),
}


def classify_intent(text: str) -> dict:
    lowered = text.lower()
    scores = {intent: sum(1 for term in terms if re.search(r"\b" + re.escape(term) + r"\b", lowered)) for intent, terms in INTENTS.items()}
    intent, score = max(scores.items(), key=lambda item: item[1])
    if score == 0:
        intent = "general_inquiry"
    return {"intent": intent, "confidence": round(min(0.99, 0.45 + score * 0.12), 2), "scores": scores}
