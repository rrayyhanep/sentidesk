"""FastAPI application for support intelligence and threat detection."""
from __future__ import annotations
import json
import os
import secrets
import base64
import hashlib
import hmac
import smtplib
import httpx
from urllib.parse import urlencode
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None
try:
    import resend
except ImportError:
    resend = None

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
try:
    from jose import JWTError, jwt
except ImportError:  # Keep the demo runnable before optional requirements are installed.
    class JWTError(Exception):
        pass

    class _JWT:
        @staticmethod
        def encode(payload, key, algorithm="HS256"):
            header = {"alg": algorithm, "typ": "JWT"}
            enc = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
            body = enc(header) + "." + enc(payload)
            signature = hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
            return body + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        @staticmethod
        def decode(token, key, algorithms=None):
            try:
                header, body, signature = token.split(".")
                expected = hmac.new(key.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
                actual = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
                if not hmac.compare_digest(expected, actual):
                    raise JWTError
                payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
                if payload.get("exp", 0) < datetime.now(timezone.utc).timestamp():
                    raise JWTError
                return payload
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                raise JWTError
    jwt = _JWT()

try:
    from models import AnalysisRequest, BulkAnalysisRequest, ContractAnalysisRequest, ContractBatchRequest, ConversationCreate, ConversationUpdate, EmailVerification, Message, Token, UserCreate, UserLogin, ProviderConnection, ProviderMessage
    from storage import init_db, load_users, save_user, delete_user, load_pending_users, save_pending_user, delete_pending_user, load_conversations, save_conversation, load_connections, save_connection, delete_connection, load_provider_messages, save_provider_message
    from nlp.classify import classify_intent
    from nlp.phishing import detect_phishing
    from nlp.risk_scoring import calculate_risk
    from nlp.sentiment import analyze_sentiment
    from nlp.social_engineering import detect_social_engineering
    from nlp.summarize import summarize
except ModuleNotFoundError:  # Supports both `uvicorn main:app` and `uvicorn backend.main:app`.
    from .models import AnalysisRequest, BulkAnalysisRequest, ContractAnalysisRequest, ContractBatchRequest, ConversationCreate, ConversationUpdate, EmailVerification, Message, Token, UserCreate, UserLogin, ProviderConnection, ProviderMessage
    from .storage import init_db, load_users, save_user, delete_user, load_pending_users, save_pending_user, delete_pending_user, load_conversations, save_conversation, load_connections, save_connection, delete_connection, load_provider_messages, save_provider_message
    from .nlp.classify import classify_intent
    from .nlp.phishing import detect_phishing
    from .nlp.risk_scoring import calculate_risk
    from .nlp.sentiment import analyze_sentiment
    from .nlp.social_engineering import detect_social_engineering
    from .nlp.summarize import summarize

BASE_DIR = Path(__file__).resolve().parent
if load_dotenv:
    load_dotenv(BASE_DIR / ".env")
else:
    # Keep local `.env` support working when Uvicorn uses a system Python
    # without python-dotenv installed.
    env_file = BASE_DIR / ".env"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
SECRET_KEY = os.getenv("JWT_SECRET", "senti-desk-demo-secret-change-me")
ALGORITHM = "HS256"
DEMO_MODE = os.getenv("SENTIDESK_DEMO_MODE", "true").lower() in {"1", "true", "yes"}
init_db()
app = FastAPI(title="SentiDesk Support Intelligence API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer(auto_error=False)

USERS: dict[str, dict[str, Any]] = load_users()
PENDING_USERS: dict[str, dict[str, Any]] = load_pending_users()
for _email, _user in list(USERS.items()):
    if not _user.get("email_verified", False):
        if _user.get("verification_code") and _user.get("verification_token"):
            PENDING_USERS.setdefault(_email, _user)
            save_pending_user(PENDING_USERS[_email])
            delete_user(_email)
            USERS.pop(_email, None)
CONVERSATIONS: dict[str, dict[str, dict[str, Any]]] = load_conversations()
CONNECTIONS: dict[str, dict[str, dict[str, Any]]] = load_connections()
OAUTH_STATES: dict[str, dict[str, Any]] = {}

def _load_data() -> None:
    global CONVERSATIONS
    if CONVERSATIONS.get("demo@company.com"):
        return
    try:
        data = json.loads((BASE_DIR / "conversations.json").read_text())
        # Seed data belongs only to the demo workspace, never to every user.
        CONVERSATIONS = {"demo@company.com": {item["id"]: item for item in data}}
        for item in data:
            save_conversation("demo@company.com", item)
    except (OSError, ValueError):
        CONVERSATIONS = {}

_load_data()

@app.get("/")
def root() -> dict[str, str]:
    return {"name": app.title, "docs": "/docs", "health": "/health"}

def _password_digest(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

if "demo@company.com" not in USERS:
    USERS["demo@company.com"] = {"username": "demo", "email": "demo@company.com", "password": _password_digest("demo123"), "email_verified": True, "created_at": datetime.now(timezone.utc).isoformat()}
    save_user(USERS["demo@company.com"])

def _normalize_email(email: str) -> str:
    return email.strip().lower()

def _token(email: str) -> str:
    return jwt.encode({"sub": email, "exp": int((datetime.now(timezone.utc) + timedelta(hours=12)).timestamp())}, SECRET_KEY, algorithm=ALGORITHM)

def _verification_token(email: str) -> str:
    return jwt.encode({"purpose": "email_verification", "sub": email, "exp": int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())}, SECRET_KEY, algorithm=ALGORITHM)

def _send_verification_email(email: str, code: str, token: str) -> bool:
    """Send through the official Resend SDK first, then SMTP when configured."""
    resend_key = os.getenv("RESEND_API_KEY")
    resend_from = os.getenv("RESEND_FROM")
    if resend_key and resend_from and resend:
        resend.api_key = resend_key
        params = {
            "from": resend_from,
            "to": [email],
            "subject": "Verify your SentiDesk account",
            "html": f"<p>Your SentiDesk verification code is <strong>{code}</strong>.</p><p>This code expires in 24 hours.</p>",
        }
        try:
            result = resend.Emails.send(params)
            if not result:
                raise RuntimeError("Resend returned an empty email response")
            return True
        except (resend.exceptions.ResendError, OSError) as exc:
            message = str(exc).strip() or exc.__class__.__name__
            raise RuntimeError(f"Resend email delivery failed: {message}") from exc

    host = os.getenv("SMTP_HOST")
    if not host:
        return False
    message = EmailMessage()
    message["Subject"] = "Verify your SentiDesk account"
    message["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@sentidesk.local"))
    message["To"] = email
    message.set_content(f"Your SentiDesk verification code is {code}.\nVerification token: {token}")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as smtp:
        if os.getenv("SMTP_TLS", "true").lower() in {"1", "true", "yes"}:
            smtp.starttls()
        if os.getenv("SMTP_USER"):
            smtp.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
        smtp.send_message(message)
    return True

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        email = _normalize_email(jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]).get("sub", ""))
        if not email or email not in USERS:
            raise ValueError
        user = USERS[email]
        return user
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})

def _analysis(text: str) -> dict[str, Any]:
    sentiment = analyze_sentiment(text)
    intent = classify_intent(text)
    phishing = detect_phishing(text)
    social = detect_social_engineering(text)
    risk = calculate_risk(phishing, social, sentiment)
    return {"sentiment": sentiment, "classification": intent, "phishing": phishing, "social_engineering": social,
            "risk": risk, "summary": summarize(text)}

def _contract_analysis(conversation_id: str, text: str) -> dict[str, Any]:
    result = _analysis(text)
    category = result["classification"]["intent"]
    priority = "critical" if result["risk"]["risk_level"] == "high" else "high" if result["sentiment"]["label"] == "negative" else "medium"
    unresolved = not any(word in text.lower() for word in ("resolved", "fixed", "thank you", "all set"))
    threat = "phishing" if result["phishing"]["is_phishing"] else "social_engineering" if result["social_engineering"]["detected"] else "none"
    return {
        "conversation_id": conversation_id, "category": category, "sentiment": result["sentiment"]["label"],
        "emotion": "frustration" if result["sentiment"]["label"] == "negative" else "satisfaction" if result["sentiment"]["label"] == "positive" else "confusion",
        "priority": priority, "resolution_status": "Unresolved" if unresolved else "Resolved",
        "summary": result["summary"], "security": {
            "threat_type": threat, "suspicious_url": bool(result["phishing"]["urls"]),
            "suspicious_email": False, "social_engineering": "Detected" if result["social_engineering"]["detected"] else "None",
            "risk_level": result["risk"]["risk_level"]},
        "recommended_action": "Escalate to security team immediately; do not click links or share credentials." if threat != "none" else ("Escalate to support and follow up with the customer." if unresolved else "No further action required.")
    }

def _conversation_view(item: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(m["content"] for m in item.get("messages", []))
    return {**item, "analysis": _analysis(text) if text else None}

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentidesk-backend",
            "email_provider": "resend" if os.getenv("RESEND_API_KEY") and os.getenv("RESEND_FROM") else "smtp" if os.getenv("SMTP_HOST") else "unconfigured"}

@app.post("/auth/register", response_model=Token, status_code=201)
def register(payload: UserCreate) -> Token:
    email = _normalize_email(payload.email)
    if email in USERS:
        raise HTTPException(409, "Email already registered")
    if email in PENDING_USERS:
        raise HTTPException(409, "A verification code was already sent for this email")
    username = payload.username or email.split("@", 1)[0]
    verification = _verification_token(email)
    code = f"{secrets.randbelow(1000000):06d}"
    pending = {"username": username, "email": email, "password": _password_digest(payload.password),
               "email_verified": False, "verification_token": verification, "verification_code": code,
               "created_at": datetime.now(timezone.utc).isoformat()}
    try:
        sent = _send_verification_email(email, code, verification)
    except (OSError, smtplib.SMTPException, RuntimeError) as exc:
        raise HTTPException(503, str(exc)) from exc
    if not sent and not DEMO_MODE:
        raise HTTPException(503, "SMTP is not configured; registration is temporarily unavailable")
    PENDING_USERS[email] = pending
    save_pending_user(pending)
    access = _token(email)
    return Token(access_token=access, token=access, verification_required=True,
                 verification_token=verification if DEMO_MODE and not sent else None,
                 verification_code=code if DEMO_MODE and not sent else None)

@app.post("/auth/login", response_model=Token)
def login(payload: UserLogin) -> Token:
    email = _normalize_email(payload.email)
    user = USERS.get(email)
    if not user or not secrets.compare_digest(user["password"], _password_digest(payload.password)):
        raise HTTPException(401, "Incorrect email or password")
    access = _token(email)
    return Token(access_token=access, token=access)

@app.post("/auth/verify-email")
@app.get("/auth/verify-email")
@app.post("/auth/verify")
@app.get("/auth/verify")
def verify_email(token: str | None = Query(None), payload: EmailVerification | None = None) -> dict[str, Any]:
    token = token or (payload.token if payload else None)
    code = payload.code if payload else None
    email = None
    if token:
        try:
            claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email = _normalize_email(claims.get("sub", ""))
            if claims.get("purpose") != "email_verification" or (email not in USERS and email not in PENDING_USERS):
                raise ValueError
        except (JWTError, ValueError):
            raise HTTPException(400, "Invalid or expired verification token")
    elif code:
        email = _normalize_email(str(payload.email)) if payload and payload.email else None
        if not email or email not in PENDING_USERS or not secrets.compare_digest(PENDING_USERS[email].get("verification_code", ""), code):
            raise HTTPException(400, "Invalid verification code")
    else:
        raise HTTPException(400, "Verification token or code is required")
    if email in PENDING_USERS:
        user = {k: v for k, v in PENDING_USERS[email].items() if k not in {"verification_code", "verification_token"}}
        user["email_verified"] = True
        USERS[email] = user
        save_user(user)
        PENDING_USERS.pop(email, None)
        delete_pending_user(email)
    else:
        USERS[email]["email_verified"] = True
        save_user(USERS[email])
    return {"verified": True, "email": email}

@app.get("/auth/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {k: v for k, v in user.items() if k not in {"password", "verification_token"}}

@app.post("/auth/logout")
def logout(user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    return {"status": "logged_out"}

@app.get("/conversations")
def list_conversations(status_filter: str | None = Query(None, alias="status"), user: dict = Depends(current_user)) -> list[dict]:
    values = list(CONVERSATIONS.get(user["email"], {}).values())
    if status_filter:
        values = [v for v in values if v.get("status") == status_filter]
    return [_conversation_view(v) for v in values]

@app.post("/conversations", status_code=201)
def create_conversation(payload: ConversationCreate, user: dict = Depends(current_user)) -> dict:
    cid = "conv-" + secrets.token_hex(5)
    item = {"id": cid, "customer_name": payload.customer_name, "email": payload.email, "status": "open",
            "priority": payload.priority, "messages": [m.model_dump(mode="json") for m in payload.messages]}
    CONVERSATIONS.setdefault(user["email"], {})[cid] = item
    save_conversation(user["email"], item)
    return _conversation_view(item)

@app.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, user: dict = Depends(current_user)) -> dict:
    item = CONVERSATIONS.get(user["email"], {}).get(conversation_id)
    if not item:
        raise HTTPException(404, "Conversation not found")
    return _conversation_view(item)

@app.patch("/conversations/{conversation_id}")
def update_conversation(conversation_id: str, payload: ConversationUpdate, user: dict = Depends(current_user)) -> dict:
    item = CONVERSATIONS.get(user["email"], {}).get(conversation_id)
    if not item:
        raise HTTPException(404, "Conversation not found")
    item.update(payload.model_dump(exclude_none=True))
    save_conversation(user["email"], item)
    return _conversation_view(item)

@app.post("/conversations/{conversation_id}/messages")
def add_message(conversation_id: str, payload: Message, user: dict = Depends(current_user)) -> dict:
    item = CONVERSATIONS.get(user["email"], {}).get(conversation_id)
    if not item:
        raise HTTPException(404, "Conversation not found")
    message = payload.model_dump(mode="json")
    message["timestamp"] = message["timestamp"] or datetime.now(timezone.utc).isoformat()
    item.setdefault("messages", []).append(message)
    save_conversation(user["email"], item)
    return _conversation_view(item)

@app.post("/analyze")
def analyze(payload: AnalysisRequest, user: dict = Depends(current_user)) -> dict:
    return _analysis(payload.text)

@app.post("/analyze-contract")
def analyze_contract(payload: ContractAnalysisRequest, user: dict = Depends(current_user)) -> dict:
    result = _contract_analysis(payload.conversation_id, payload.text)
    CONVERSATIONS.setdefault(user["email"], {})[payload.conversation_id] = {"id": payload.conversation_id, "customer_name": "Analyzed customer", "email": None, "status": "open", "priority": result["priority"], "messages": [{"role": "customer", "content": payload.text}]}
    save_conversation(user["email"], CONVERSATIONS[user["email"]][payload.conversation_id])
    return result

@app.post("/analyze-batch")
def analyze_batch(payload: ContractBatchRequest, user: dict = Depends(current_user)) -> list[dict]:
    return [_contract_analysis(item.conversation_id, item.text) for item in payload.conversations]

@app.post("/analyze/sentiment")
def sentiment(payload: AnalysisRequest, user: dict = Depends(current_user)) -> dict:
    return analyze_sentiment(payload.text)

@app.post("/analyze/phishing")
def phishing(payload: AnalysisRequest, user: dict = Depends(current_user)) -> dict:
    result = detect_phishing(payload.text)
    social = detect_social_engineering(payload.text)
    return {**result, "social_engineering": social, "risk": calculate_risk(result, social)}

@app.post("/analyze/bulk")
def bulk_analyze(payload: BulkAnalysisRequest, user: dict = Depends(current_user)) -> list[dict]:
    return [{"message": message.model_dump(mode="json"), "analysis": _analysis(message.content)} for message in payload.messages]

@app.get("/dashboard/stats")
def dashboard_stats(user: dict = Depends(current_user)) -> dict[str, Any]:
    items = list(CONVERSATIONS.get(user["email"], {}).values())
    analyses = [_analysis(" ".join(m["content"] for m in i.get("messages", []))) for i in items if i.get("messages")]
    return {"total_conversations": len(items), "open_conversations": sum(i.get("status") == "open" for i in items),
            "resolved_conversations": sum(i.get("status") == "resolved" for i in items),
            "high_risk_conversations": sum(a["risk"]["risk_level"] == "high" for a in analyses),
            "sentiment_breakdown": {label: sum(a["sentiment"]["label"] == label for a in analyses) for label in ("positive", "neutral", "negative")}}

@app.get("/dashboard-stats")
def dashboard_stats_contract(user: dict = Depends(current_user)) -> dict[str, Any]:
    items = list(CONVERSATIONS.get(user["email"], {}).values())
    analyses = [_contract_analysis(i["id"], " ".join(m["content"] for m in i.get("messages", []))) for i in items if i.get("messages")]
    categories: dict[str, int] = {}
    issues: dict[str, int] = {}
    for a in analyses:
        categories[a["category"]] = categories.get(a["category"], 0) + 1
        issues[a["category"]] = issues.get(a["category"], 0) + 1
    sentiments = {label: sum(a["sentiment"] == label for a in analyses) for label in ("positive", "neutral", "negative")}
    risk_levels = ("critical", "high", "medium", "low")
    risk_breakdown = {level: sum(a["security"]["risk_level"] == level for a in analyses) for level in risk_levels}
    coverage = {"summary": len(analyses), "risk": len(analyses),
                "phishing": sum(a["security"]["threat_type"] == "phishing" for a in analyses),
                "social_engineering": sum(a["security"]["social_engineering"] == "Detected" for a in analyses)}
    return {"total_conversations": len(items), "sentiment_breakdown": sentiments,
            "top_categories": [{"name": k, "count": v} for k, v in sorted(categories.items(), key=lambda x: -x[1])],
            "critical_count": sum(a["priority"] == "critical" for a in analyses),
            "unresolved_count": sum(a["resolution_status"] == "Unresolved" for a in analyses),
            "resolved_count": sum(a["resolution_status"] == "Resolved" for a in analyses),
            "risk_breakdown": risk_breakdown, "coverage": coverage,
            "frequently_reported_issues": [{"issue": k, "count": v} for k, v in sorted(issues.items(), key=lambda x: -x[1])]}

@app.get("/conversation/{conversation_id}")
def conversation_contract(conversation_id: str, user: dict = Depends(current_user)) -> dict:
    item = CONVERSATIONS.get(user["email"], {}).get(conversation_id)
    if not item:
        raise HTTPException(404, "Conversation not found")
    text = " ".join(m["content"] for m in item.get("messages", []))
    return {**item, "analysis": _contract_analysis(conversation_id, text)}

@app.get("/category/{category_name}")
def category_contract(category_name: str, user: dict = Depends(current_user)) -> list[dict]:
    result = []
    for item in CONVERSATIONS.get(user["email"], {}).values():
        text = " ".join(m["content"] for m in item.get("messages", []))
        analysis = _contract_analysis(item["id"], text)
        if analysis["category"].lower() == category_name.lower():
            result.append({**item, "analysis": analysis})
    return result

PROVIDERS = {
    "gmail": ("GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET"),
    "instagram": ("INSTAGRAM_CLIENT_ID", "INSTAGRAM_CLIENT_SECRET"),
    "whatsapp": ("WHATSAPP_ACCESS_TOKEN", "WHATSAPP_VERIFY_TOKEN"),
}

OAUTH_CONFIG = {
    "gmail": {
        "client_id": "GMAIL_CLIENT_ID", "client_secret": "GMAIL_CLIENT_SECRET",
        "redirect_uri": "GMAIL_REDIRECT_URI",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
    },
    "instagram": {
        "client_id": "INSTAGRAM_CLIENT_ID", "client_secret": "INSTAGRAM_CLIENT_SECRET",
        "redirect_uri": "INSTAGRAM_REDIRECT_URI",
        "authorize_url": "https://www.facebook.com/v20.0/dialog/oauth",
        "scope": "instagram_basic,instagram_manage_messages,pages_show_list",
    },
}

def _require_provider(provider: str) -> None:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unsupported provider")

def _provider_configured(provider: str) -> bool:
    names = ("WHATSAPP_ACCESS_TOKEN", "WHATSAPP_VERIFY_TOKEN",
             "WHATSAPP_PHONE_NUMBER_ID", "WHATSAPP_BUSINESS_ACCOUNT_ID") if provider == "whatsapp" else PROVIDERS[provider]
    return all(os.getenv(name) for name in names)

def _oauth_state_digest(state: str) -> str:
    return hmac.new(SECRET_KEY.encode(), state.encode(), hashlib.sha256).hexdigest()

def _oauth_configured(provider: str) -> bool:
    config = OAUTH_CONFIG[provider]
    return all(os.getenv(config[key]) for key in ("client_id", "client_secret", "redirect_uri"))

def _oauth_unconfigured(provider: str) -> None:
    if not _oauth_configured(provider):
        raise HTTPException(503, "Provider OAuth is not configured on the server")

def _protect_token(token: str) -> str:
    """Encrypt provider tokens before persisting them; the key never leaves this process."""
    try:
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
        return "fernet:" + Fernet(key).encrypt(token.encode()).decode()
    except ImportError as exc:
        raise RuntimeError("cryptography is required for provider token storage") from exc

def _unprotect_token(value: str) -> str:
    if not value.startswith("fernet:"):
        raise HTTPException(503, "Stored provider credentials use an unsupported encryption format")
    try:
        from cryptography.fernet import Fernet, InvalidToken
        key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
        return Fernet(key).decrypt(value[7:].encode()).decode()
    except (ImportError, InvalidToken, UnicodeDecodeError) as exc:
        raise HTTPException(503, "Stored provider credentials could not be decrypted") from exc

def _connection_token(connection: dict[str, Any], field: str = "access_token") -> str:
    value = connection.get(field)
    if not value:
        raise HTTPException(409, "Provider authorization did not return the required token")
    return _unprotect_token(value)

def _oauth_token_exchange(provider: str, code: str, redirect_uri: str) -> dict[str, Any]:
    config = OAUTH_CONFIG[provider]
    client_id = os.environ[config["client_id"]]
    client_secret = os.environ[config["client_secret"]]
    if provider == "gmail":
        url = "https://oauth2.googleapis.com/token"
        data = {"code": code, "client_id": client_id, "client_secret": client_secret,
                "redirect_uri": redirect_uri, "grant_type": "authorization_code"}
    else:
        url = "https://graph.facebook.com/v20.0/oauth/access_token"
        data = {"code": code, "client_id": client_id, "client_secret": client_secret,
                "redirect_uri": redirect_uri}
    try:
        response = httpx.post(url, data=data, timeout=15.0)
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(502, "Provider token exchange could not be completed") from exc
    if not isinstance(body, dict) or response.status_code >= 400 or body.get("error") or not body.get("access_token"):
        raise HTTPException(502, "Provider rejected the OAuth authorization code")
    return body

def _provider_status(provider: str, user: dict[str, Any]) -> dict[str, Any]:
    _require_provider(provider)
    configured = _provider_configured(provider)
    connection = CONNECTIONS.get(user["email"], {}).get(provider, {})
    authenticated = bool(connection.get("authenticated"))
    return {"provider": provider, "status": "connected" if authenticated else "available",
            "configured": configured, "credentials": "environment",
            "authenticated": authenticated,
            "message": None if configured else "Configure provider credentials in environment variables"}

@app.post("/connections/connect")
def connect_platform(payload: ProviderConnection, user: dict = Depends(current_user)) -> dict[str, Any]:
    """Compatibility endpoint; credentials are intentionally never persisted."""
    platform = payload.platform
    _require_provider(platform)
    if not _provider_configured(platform):
        raise HTTPException(503, "Provider credentials are not configured on the server")
    CONNECTIONS.setdefault(user["email"], {})[platform] = {
        "connected_at": datetime.now(timezone.utc).isoformat(), "authenticated": False,
    }
    save_connection(user["email"], platform, CONNECTIONS[user["email"]][platform])
    result = _provider_status(platform, user)
    return {**result, "message": "OAuth authorization is required before provider access."}

@app.post("/connections/{provider}/connect")
def connect_provider(provider: str, user: dict = Depends(current_user)) -> dict[str, Any]:
    _require_provider(provider)
    if not _provider_configured(provider):
        raise HTTPException(503, "Provider credentials are not configured on the server")
    CONNECTIONS.setdefault(user["email"], {})[provider] = {
        "connected_at": datetime.now(timezone.utc).isoformat(), "authenticated": False,
    }
    save_connection(user["email"], provider, CONNECTIONS[user["email"]][provider])
    return _provider_status(provider, user)

@app.post("/connections/{provider}/disconnect")
def disconnect_provider(provider: str, user: dict = Depends(current_user)) -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unsupported provider")
    CONNECTIONS.get(user["email"], {}).pop(provider, None)
    delete_connection(user["email"], provider)
    return _provider_status(provider, user)

@app.get("/connections/{provider}/status")
def provider_status(provider: str, user: dict = Depends(current_user)) -> dict[str, Any]:
    return _provider_status(provider, user)

@app.get("/connections")
def connections(user: dict = Depends(current_user)) -> list[str]:
    # Preserve the original response shape for existing clients.
    return sorted(CONNECTIONS.get(user["email"], {}))

@app.get("/connections/status")
def connection_statuses(user: dict = Depends(current_user)) -> list[dict[str, Any]]:
    return [_provider_status(provider, user) for provider in PROVIDERS]

@app.get("/connections/{provider}/oauth/start")
def oauth_start(provider: str, user: dict = Depends(current_user)) -> dict[str, Any]:
    """Create a short-lived, single-use OAuth state; secrets remain server-side."""
    if provider not in OAUTH_CONFIG:
        _require_provider(provider)
        raise HTTPException(400, "This provider does not use OAuth")
    _oauth_unconfigured(provider)
    state = secrets.token_urlsafe(32)
    OAUTH_STATES[_oauth_state_digest(state)] = {
        "provider": provider, "email": user["email"],
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
    }
    config = OAUTH_CONFIG[provider]
    params = {
        "client_id": os.environ[config["client_id"]], "redirect_uri": os.environ[config["redirect_uri"]],
        "response_type": "code", "scope": config["scope"], "state": state,
    }
    if provider == "gmail":
        params["access_type"] = "offline"
        params["prompt"] = "consent"
    return {"provider": provider, "state": state, "authorization_url": f"{config['authorize_url']}?{urlencode(params)}"}

@app.get("/connections/{provider}/oauth/state")
def oauth_state(provider: str, state: str = Query(...), user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    _require_provider(provider)
    record = OAUTH_STATES.get(_oauth_state_digest(state))
    valid = bool(record and record["provider"] == provider and record["email"] == user["email"]
                and record["expires_at"] > datetime.now(timezone.utc))
    return {"provider": provider, "valid": valid, "expires_in_seconds": max(
        0, int((record["expires_at"] - datetime.now(timezone.utc)).total_seconds())) if valid else 0}

@app.get("/connections/{provider}/oauth/callback")
def oauth_callback(provider: str, code: str | None = Query(None), state: str | None = Query(None),
                   error: str | None = Query(None)) -> dict[str, Any]:
    if provider not in OAUTH_CONFIG:
        _require_provider(provider)
    _oauth_unconfigured(provider)
    if error:
        raise HTTPException(400, f"Provider authorization failed: {error}")
    if not code or not state:
        raise HTTPException(400, "OAuth callback requires code and state")
    digest = _oauth_state_digest(state)
    record = OAUTH_STATES.pop(digest, None)
    if not record or record["provider"] != provider or record["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(400, "Invalid or expired OAuth state")
    config = OAUTH_CONFIG[provider]
    token_data = _oauth_token_exchange(provider, code, os.environ[config["redirect_uri"]])
    connection = {
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "authenticated": True,
        "token_type": token_data.get("token_type", "Bearer"),
        "expires_in": token_data.get("expires_in"),
        "scope": token_data.get("scope"),
        "access_token": _protect_token(token_data["access_token"]),
        "refresh_token": _protect_token(token_data["refresh_token"]) if token_data.get("refresh_token") else None,
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=int(token_data["expires_in"]))).isoformat()
            if token_data.get("expires_in") else None,
    }
    CONNECTIONS.setdefault(record["email"], {})[provider] = connection
    save_connection(record["email"], provider, connection)
    return {"provider": provider, "status": "connected", "authenticated": True,
            "message": "OAuth authorization completed successfully"}

@app.post("/connections/whatsapp/onboard")
def whatsapp_onboard(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    configured = _provider_configured("whatsapp")
    if configured:
        connection = CONNECTIONS.setdefault(user["email"], {}).setdefault("whatsapp", {})
        connection.update({"authenticated": True, "connected_at": connection.get("connected_at") or datetime.now(timezone.utc).isoformat(),
                            "phone_number_id": os.getenv("WHATSAPP_PHONE_NUMBER_ID"),
                            "account_id": os.getenv("WHATSAPP_BUSINESS_ACCOUNT_ID")})
        save_connection(user["email"], "whatsapp", connection)
    authenticated = bool(CONNECTIONS.get(user["email"], {}).get("whatsapp", {}).get("authenticated"))
    return {"provider": "whatsapp", "configured": configured,
            "authenticated": authenticated,
            "status": "ready" if configured else "unconfigured",
            "message": "Use Meta's official Cloud API onboarding and webhooks; WhatsApp Web QR/session scraping is not supported."
            if configured else "Configure WHATSAPP_ACCESS_TOKEN, WHATSAPP_VERIFY_TOKEN, WHATSAPP_PHONE_NUMBER_ID, and WHATSAPP_BUSINESS_ACCOUNT_ID."}

def _gmail_token(email: str) -> str:
    connection = CONNECTIONS.get(email, {}).get("gmail", {})
    token = _connection_token(connection)
    expires_at = connection.get("expires_at")
    if expires_at:
        try:
            expired = datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc) + timedelta(seconds=30)
        except ValueError:
            expired = True
        if expired:
            refresh = connection.get("refresh_token")
            if not refresh:
                raise HTTPException(409, "Gmail access token expired and no refresh token is available")
            response = httpx.post("https://oauth2.googleapis.com/token", data={
                "client_id": os.environ["GMAIL_CLIENT_ID"], "client_secret": os.environ["GMAIL_CLIENT_SECRET"],
                "refresh_token": _unprotect_token(refresh), "grant_type": "refresh_token"}, timeout=15.0)
            if response.status_code >= 400:
                raise HTTPException(502, "Gmail token refresh failed")
            body = response.json()
            if not body.get("access_token"):
                raise HTTPException(502, "Gmail token refresh returned no access token")
            connection["access_token"] = _protect_token(body["access_token"])
            if body.get("expires_in"):
                connection["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=int(body["expires_in"]))).isoformat()
            CONNECTIONS[email]["gmail"] = connection
            save_connection(email, "gmail", connection)
            token = body["access_token"]
    return token

def _gmail_text(part: dict[str, Any]) -> str:
    import base64 as _b64
    data = (part.get("body") or {}).get("data")
    if data:
        try:
            return _b64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
        except (ValueError, UnicodeError):
            return ""
    return "".join(_gmail_text(p) for p in part.get("parts", []) if isinstance(p, dict))

def _sync_gmail(email: str) -> list[dict[str, Any]]:
    token = _gmail_token(email)
    headers = {"Authorization": f"Bearer {token}"}
    listed = httpx.get("https://gmail.googleapis.com/gmail/v1/users/me/messages",
                       headers=headers, params={"maxResults": 25, "labelIds": "INBOX"}, timeout=15.0)
    if listed.status_code >= 400:
        raise HTTPException(502, "Gmail inbox listing failed")
    messages = []
    for item in listed.json().get("messages", []):
        message_id = item.get("id")
        if not message_id:
            continue
        response = httpx.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
                             headers=headers, params={"format": "full"}, timeout=15.0)
        if response.status_code >= 400:
            continue
        data = response.json()
        payload = data.get("payload", {})
        headers_by_name = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers", [])}
        sender = headers_by_name.get("from", "unknown")
        content = _gmail_text(payload) or data.get("snippet", "")
        if not content:
            continue
        message = {"sender": sender, "content": content[:10000], "external_id": message_id,
                   "timestamp": headers_by_name.get("date") or datetime.now(timezone.utc).isoformat(),
                   "subject": headers_by_name.get("subject", ""), "thread_id": data.get("threadId")}
        save_provider_message(email, "gmail", message)
        messages.append(message)
    return load_provider_messages(email, "gmail")

@app.get("/connections/{provider}/inbox")
def provider_inbox(provider: str, user: dict = Depends(current_user)) -> dict[str, Any]:
    _require_provider(provider)
    if not CONNECTIONS.get(user["email"], {}).get(provider, {}).get("authenticated"):
        raise HTTPException(409, "Provider is not connected")
    messages = load_provider_messages(user["email"], provider)
    return {"provider": provider, "messages": messages, "count": len(messages)}

@app.post("/connections/{provider}/inbox/sync")
def sync_provider_inbox(provider: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    _require_provider(provider)
    connected = bool(CONNECTIONS.get(user["email"], {}).get(provider, {}).get("authenticated"))
    configured = _provider_configured(provider)
    if not configured:
        return {"provider": provider, "status": "unconfigured", "configured": False,
                "authenticated": connected, "messages": [], "count": 0,
                "message": "Provider credentials are not configured on the server; no external request was made."}
    if not connected:
        return {"provider": provider, "status": "not_authenticated", "configured": True,
                "authenticated": False, "messages": [], "count": 0,
                "message": "Provider authorization is required before inbox sync."}
    if provider == "gmail":
        try:
            messages = _sync_gmail(user["email"])
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(502, "Gmail inbox sync failed") from exc
        return {"provider": provider, "status": "synced", "configured": True,
                "authenticated": True, "messages": messages, "count": len(messages)}
    messages = load_provider_messages(user["email"], provider)
    return {"provider": provider, "status": "webhook_driven", "configured": True,
            "authenticated": True, "messages": messages, "count": len(messages),
            "message": f"{provider.title()} messages are received through the signed webhook endpoint."}

def _webhook_owner(provider: str, account_id: str | None) -> str | None:
    candidates = []
    for email, providers in CONNECTIONS.items():
        connection = providers.get(provider, {})
        if connection.get("authenticated"):
            candidates.append((email, connection))
            if account_id and account_id in {connection.get("account_id"), connection.get("phone_number_id"),
                                             connection.get("page_id")}:
                return email
    return candidates[0][0] if len(candidates) == 1 else None

def _save_webhook_message(provider: str, owner: str, sender: str, content: str,
                          external_id: str | None, timestamp: Any = None) -> None:
    save_provider_message(owner, provider, {"sender": sender or "unknown", "content": content[:10000],
        "external_id": external_id, "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "source": "webhook"})

@app.get("/webhooks/{provider}")
def verify_provider_webhook(provider: str, hub_mode: str | None = Query(None, alias="hub.mode"),
                            hub_token: str | None = Query(None, alias="hub.verify_token"),
                            hub_challenge: str | None = Query(None, alias="hub.challenge")) -> Any:
    if provider not in {"instagram", "whatsapp"}:
        raise HTTPException(404, "Unsupported webhook provider")
    expected = os.getenv("WHATSAPP_VERIFY_TOKEN" if provider == "whatsapp" else "INSTAGRAM_VERIFY_TOKEN")
    if hub_mode != "subscribe" or not expected or not hub_token or not secrets.compare_digest(hub_token, expected):
        raise HTTPException(403, "Webhook verification failed")
    return int(hub_challenge) if hub_challenge and hub_challenge.isdigit() else (hub_challenge or "")

@app.post("/webhooks/{provider}")
async def receive_provider_webhook(provider: str, request: Request) -> dict[str, Any]:
    if provider not in {"instagram", "whatsapp"}:
        raise HTTPException(404, "Unsupported webhook provider")
    raw = await request.body()
    secret = os.getenv("WHATSAPP_APP_SECRET" if provider == "whatsapp" else "INSTAGRAM_APP_SECRET")
    signature = request.headers.get("x-hub-signature-256", "")
    if not secret or not signature.startswith("sha256=") or not hmac.compare_digest(
        signature[7:], hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()):
        raise HTTPException(403, "Invalid webhook signature")
    try:
        body = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Webhook body must be JSON") from exc
    saved = 0
    if provider == "whatsapp":
        for entry in body.get("entry", []):
            account_id = entry.get("id")
            for change in entry.get("changes", []):
                value = change.get("value", {})
                account_id = value.get("metadata", {}).get("phone_number_id") or account_id
                owner = _webhook_owner(provider, account_id)
                if not owner:
                    continue
                for message in value.get("messages", []):
                    text = message.get("text", {}).get("body") or message.get("button", {}).get("text")
                    if text:
                        _save_webhook_message(provider, owner, message.get("from", "unknown"), text,
                                              message.get("id"), message.get("timestamp"))
                        saved += 1
    else:
        for entry in body.get("entry", []):
            owner = _webhook_owner(provider, str(entry.get("id", "")))
            if not owner:
                continue
            for event in entry.get("messaging", []):
                message = event.get("message", {})
                if message.get("text"):
                    _save_webhook_message(provider, owner, event.get("sender", {}).get("id", "unknown"),
                                          message["text"], message.get("mid"), event.get("timestamp"))
                    saved += 1
    return {"received": True, "saved": saved}

@app.post("/connections/{provider}/inbox", status_code=201)
def add_provider_message(provider: str, payload: ProviderMessage, user: dict = Depends(current_user)) -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unsupported provider")
    if provider not in CONNECTIONS.get(user["email"], {}):
        raise HTTPException(409, "Provider is not connected")
    message = payload.model_dump(mode="json")
    message["timestamp"] = message["timestamp"] or datetime.now(timezone.utc).isoformat()
    save_provider_message(user["email"], provider, message)
    return message

@app.post("/sync")
def sync_dataset(user: dict = Depends(current_user)) -> dict[str, Any]:
    # The local seed is available only to the demo account. Never overwrite
    # another user's in-memory workspace during a sync.
    if user["email"] == "demo@company.com" and not CONVERSATIONS.get(user["email"]):
        _load_data()
    return {"synced": True, "count": len(CONVERSATIONS.get(user["email"], {}))}
