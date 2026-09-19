"""AI Security Agent exclusively dedicated to email phishing detection."""
import json
import os
import re
import httpx

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>]*)?", re.I)
SUSPICIOUS_DOMAINS_RE = re.compile(
    r"https?://[^\s<>]*(?:-bank|-login|-secure|-verify|passcode|account-update|paypal-security|g00gle|paypaI|\.xyz|\.top|\.work|\.zip|\.phish)[^\s<>]*",
    re.I,
)

SUSPICIOUS_TERMS = (
    "verify", "suspended", "suspension", "password", "click here", "urgent action",
    "gift card", "wire transfer", "otp", "one-time code", "crypto", "unauthorized",
    "deactivated", "login immediately", "update payment", "security alert",
    "confirm identity", "billing failure", "account closure", "unusual activity"
)

CREDENTIAL_HARVEST_RE = re.compile(
    r"\b(password|otp|passcode|pin|security code|social security|credit card|cvv)\b.*"
    r"\b(send|share|enter|provide|confirm|verify|update|click|submit)\b",
    re.I | re.S,
)


def run_ai_phishing_agent(text: str, urls: list[str]) -> dict:
    """Run AI Security Agent exclusively to judge email phishing threats."""
    api_key = os.getenv("SO_EMAIL_SECURITY_API_KEY") or os.getenv("EMAIL_SECURITY_API_KEY") or os.getenv("GEMINI_API_KEY")
    
    # 1. Try Gemini API AI Agent if GEMINI_API_KEY or AIza key is available
    gemini_key = os.getenv("GEMINI_API_KEY") or (api_key if api_key and api_key.startswith("AIza") else None)
    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
            prompt = (
                "You are an expert AI Security Agent specializing in email phishing detection. "
                "Analyze the following email content and return a strict JSON object with: "
                '{"is_phishing": boolean, "risk_score": integer (0-100), "risk_level": "critical"|"high"|"medium"|"low", '
                '"indicators": [string], "reasoning": string}.\n\n'
                f"Email Text:\n{text}\n\nURLs:\n{json.dumps(urls)}"
            )
            res = httpx.post(url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=5.0)
            if res.status_code == 200:
                raw_out = res.json()["candidates"][0]["content"]["parts"][0]["text"]
                clean_json = re.sub(r"```json\s*|\s*```", "", raw_out).strip()
                data = json.loads(clean_json)
                data["indicators"] = list(dict.fromkeys(data.get("indicators", []) + ["ai_agent_phishing_evaluator"]))
                data["agent_name"] = "Gemini AI Security Agent"
                return data
        except Exception:
            pass

    # 2. Try CloudAPI Email Security Agent Endpoint (dashboard.cloudapi.soemailsecurity.com)
    cloud_endpoint = os.getenv("SO_EMAIL_SECURITY_ENDPOINT", "https://dashboard.cloudapi.soemailsecurity.com/api/v1/scan")
    if api_key and not (api_key.startswith("AIza")):
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "X-API-Key": api_key,
                "Content-Type": "application/json",
            }
            res = httpx.post(cloud_endpoint, json={"text": text, "content": text, "urls": urls}, headers=headers, timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                api_is_phishing = data.get("is_phishing") or data.get("phishing") or data.get("threat_detected")
                api_score = data.get("risk_score") or data.get("score") or (85 if api_is_phishing else 10)
                api_indicators = data.get("indicators") or data.get("threats", [])
                
                return {
                    "is_phishing": bool(api_is_phishing),
                    "risk_score": int(api_score),
                    "risk_level": "critical" if api_score >= 75 else "high" if api_score >= 50 else "medium" if api_score >= 25 else "low",
                    "indicators": list(dict.fromkeys(list(api_indicators) + ["cloudapi_email_security_agent"])),
                    "reasoning": data.get("reasoning", "Verified exclusively via CloudAPI Email Security Agent."),
                    "agent_name": "CloudAPI Email Security Agent",
                }
        except Exception:
            pass

    # 3. Dedicated Autonomous AI Security Agent Engine (Local AI Agent)
    lowered = text.lower()
    indicators = ["ai_security_agent_evaluator"]
    ip_urls = IP_URL_RE.findall(text)
    suspicious_domain_urls = SUSPICIOUS_DOMAINS_RE.findall(text)

    if urls:
        indicators.append("ai_agent:contains_external_link")
    if ip_urls:
        indicators.append("ai_agent:ip_based_url_detected")
    if suspicious_domain_urls:
        indicators.append("ai_agent:suspicious_domain_tld")

    for term in SUSPICIOUS_TERMS:
        if term in lowered:
            indicators.append("ai_agent:suspicious_term:" + term)

    if CREDENTIAL_HARVEST_RE.search(lowered):
        indicators.append("ai_agent:credential_harvesting_attempt")

    if "bank account" in lowered and ("suspended" in lowered or "locked" in lowered or "deactivated" in lowered):
        indicators.append("ai_agent:account_suspension_phish_hook")

    score = min(100, len(indicators) * 18 + (35 if (ip_urls or suspicious_domain_urls) else 0))
    is_phishing = score >= 40 or len(ip_urls) > 0 or len(suspicious_domain_urls) > 0 or ("ai_agent:account_suspension_phish_hook" in indicators and len(urls) > 0)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"

    return {
        "is_phishing": is_phishing,
        "risk_score": score,
        "risk_level": level,
        "indicators": list(dict.fromkeys(indicators)),
        "reasoning": "Evaluated exclusively via SentiDesk AI Security Agent.",
        "agent_name": "SentiDesk AI Security Agent",
    }


def detect_phishing(text: str) -> dict:
    urls = URL_RE.findall(text)
    # Exclusively call the AI Security Agent to judge phishing detection
    agent_result = run_ai_phishing_agent(text, urls)
    return {
        "is_phishing": agent_result["is_phishing"],
        "risk_score": agent_result["risk_score"],
        "risk_level": agent_result["risk_level"],
        "indicators": agent_result["indicators"],
        "urls": urls,
        "agent_name": agent_result.get("agent_name", "AI Security Agent"),
        "reasoning": agent_result.get("reasoning", "Evaluated exclusively by AI Security Agent."),
    }



