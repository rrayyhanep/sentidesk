"""Deterministic URL and email security analysis helpers."""
import re
from urllib.parse import urlparse

URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "tiny.cc", "cutt.ly"
}

FREEMAILS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "gmx.com"
}

COMMON_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "bankofamerica", "chase"
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _check_lookalike(domain: str) -> bool:
    if not domain:
        return False
    domain_lowered = domain.lower().split(":")[0]
    parts = domain_lowered.split(".")
    tokens = []
    subparts = parts[:-1] if len(parts) > 1 else parts
    for p in subparts:
        tokens.extend(p.split("-"))

    for token in tokens:
        if not token:
            continue
        normalized = (
            token.replace("0", "o")
            .replace("1", "i")
            .replace("l", "i")
            .replace("vv", "w")
            .replace("rn", "m")
        )
        for brand in COMMON_BRANDS:
            if token == brand:
                continue
            if normalized == brand:
                return True
            dist = _levenshtein_distance(token, brand)
            if 1 <= dist <= 2 and len(token) >= 4:
                return True
    return False


def extract_urls_and_analyze(text: str, sender_email: str | None = None) -> list[dict]:
    if not text:
        return []
    urls = URL_REGEX.findall(text)
    results = []
    seen = set()

    sender_domain = ""
    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].lower()

    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path.split("/")[0]).lower().split(":")[0]
        
        is_https = url.lower().startswith("https://")
        is_ip_based = bool(IP_REGEX.match(domain))
        is_shortened = domain in SHORTENERS
        is_lookalike = _check_lookalike(domain)

        # Domain mismatch: Sender claims to be from brand/org domain, but link points elsewhere
        domain_mismatch = False
        if sender_domain and sender_domain not in FREEMAILS:
            if domain != sender_domain and not domain.endswith("." + sender_domain):
                if any(brand in text.lower() for brand in COMMON_BRANDS):
                    domain_mismatch = True

        # Accurately flag suspicious URLs ONLY when genuine red flags are present
        has_sensitive_context = any(w in text.lower() for w in ("password", "login", "verify", "credit card", "bank", "otp", "ssn", "urgent"))
        is_suspicious = is_ip_based or is_lookalike or is_shortened or domain_mismatch or (not is_https and has_sensitive_context)

        risk_score = 0
        potential_issue = "Legitimate link"
        if is_ip_based:
            risk_score += 45
            potential_issue = "Raw IP-address host detected"
        if is_lookalike:
            risk_score += 50
            potential_issue = "Lookalike / typosquatted domain pattern"
        if is_shortened:
            risk_score += 25
            potential_issue = "URL shortener hiding true destination"
        if domain_mismatch:
            risk_score += 35
            potential_issue = "URL domain mismatch from sender domain"
        if not is_https and has_sensitive_context:
            risk_score += 20
            potential_issue = "Unencrypted HTTP URL combined with sensitive request"

        results.append({
            "url": url,
            "domain": domain,
            "is_https": is_https,
            "is_ip_based": is_ip_based,
            "is_shortened": is_shortened,
            "is_lookalike": is_lookalike,
            "is_suspicious": is_suspicious,
            "potential_issue": potential_issue if is_suspicious else "None",
            "url_risk_score": min(100, risk_score) if is_suspicious else 0,
        })
    return results


def extract_emails_and_analyze(text: str, sender_email: str | None = None) -> list[dict]:
    if not text:
        return []
    emails = EMAIL_REGEX.findall(text)
    lowered_text = text.lower()
    results = []
    seen = set()

    mentioned_brand = any(brand in lowered_text for brand in COMMON_BRANDS)

    for email in emails:
        if email.lower() in seen:
            continue
        seen.add(email.lower())
        parts = email.lower().split("@")
        domain = parts[1] if len(parts) == 2 else ""

        is_freemail = domain in FREEMAILS
        
        domain_mismatch = False
        reason = "Normal email domain"
        potential_impersonation = False

        if mentioned_brand:
            matches_official_brand = any(f"{brand}.com" in domain for brand in COMMON_BRANDS)
            if not matches_official_brand:
                domain_mismatch = True
                potential_impersonation = True
                reason = "Domain does not match expected organization domain"

        email_risk_score = 0
        if domain_mismatch:
            email_risk_score += 45
        if any(term in domain for term in ("verify", "security", "update", "alert", "bank", "login")):
            email_risk_score += 30
            potential_impersonation = True
            reason = "Domain contains suspicious security keywords"
        if is_freemail and mentioned_brand:
            email_risk_score += 25
            potential_impersonation = True
            reason = "Free-mail domain used for official brand claims"

        results.append({
            "email": email,
            "domain": domain,
            "is_freemail": is_freemail,
            "domain_mismatch": domain_mismatch,
            "potential_impersonation": potential_impersonation,
            "reason": reason,
            "email_risk_score": min(100, email_risk_score),
        })
    return results
