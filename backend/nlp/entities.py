"""Entity extraction helper for support emails and customer tickets."""
import re

ORDER_RE = re.compile(r"\b(?:order|tracking|ticket|id|inv|invoice)\s*#?\s*([A-[Z0-9_-]{4,16})\b", re.I)
ORDER_HASH_RE = re.compile(r"#[A-Za-z0-9_-]{4,16}\b")
MONEY_RE = re.compile(r"(?:\$|€|£|USD\s*)\d+(?:\.\d{2})?\b", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
DEADLINE_RE = re.compile(r"\b(?:within\s+\d+\s+(?:hours?|days?)|asap|by\s+(?:today|tomorrow|friday|monday)|urgently|immediately)\b", re.I)


def extract_entities(text: str) -> dict:
    if not text:
        return {"order_ids": [], "amounts": [], "emails": [], "deadlines": [], "key_phrases": []}

    order_ids = set()
    for m in ORDER_RE.finditer(text):
        order_ids.add(m.group(0))
    for m in ORDER_HASH_RE.finditer(text):
        order_ids.add(m.group(0))

    amounts = list(set(MONEY_RE.findall(text)))
    emails = list(set(EMAIL_RE.findall(text)))
    deadlines = list(set(DEADLINE_RE.findall(text)))

    return {
        "order_ids": sorted(list(order_ids)),
        "amounts": amounts,
        "emails": emails,
        "deadlines": deadlines,
    }
