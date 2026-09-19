"""FastAPI application for support intelligence and threat detection."""
from __future__ import annotations
import asyncio
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

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response, status
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
    from models import AnalysisRequest, BulkAnalysisRequest, ContractAnalysisRequest, ContractBatchRequest, ConversationCreate, ConversationUpdate, EmailVerification, Message, Token, UserCreate, UserLogin, ProviderConnection, ProviderMessage, InstagramOnboardRequest, WhatsAppSendRequest, MessageStatusUpdateRequest
    from storage import init_db, load_users, save_user, delete_user, load_pending_users, save_pending_user, delete_pending_user, load_conversations, save_conversation, load_connections, save_connection, delete_connection, delete_provider_messages, load_provider_messages, save_provider_message
    from nlp.classify import classify_intent
    from nlp.phishing import detect_phishing
    from nlp.risk_scoring import calculate_risk
    from nlp.sentiment import analyze_sentiment
    from nlp.social_engineering import detect_social_engineering
    from nlp.summarize import summarize
except ModuleNotFoundError:  # Supports both `uvicorn main:app` and `uvicorn backend.main:app`.
    from .models import AnalysisRequest, BulkAnalysisRequest, ContractAnalysisRequest, ContractBatchRequest, ConversationCreate, ConversationUpdate, EmailVerification, Message, Token, UserCreate, UserLogin, ProviderConnection, ProviderMessage, InstagramOnboardRequest, WhatsAppSendRequest
    from .storage import init_db, load_users, save_user, delete_user, load_pending_users, save_pending_user, delete_pending_user, load_conversations, save_conversation, load_connections, save_connection, delete_connection, delete_provider_messages, load_provider_messages, save_provider_message
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

def generate_tailored_recommended_action(text: str, category: str, risk_level: str, llm_rec_action: str | None = None) -> str:
    generic_phrases = [
        "review customer inquiry and respond",
        "review inquiry and send response",
        "review inquiry and respond",
        "no further action required",
    ]
    if llm_rec_action and isinstance(llm_rec_action, str):
        cleaned = llm_rec_action.strip()
        if cleaned and not any(gen in cleaned.lower() for gen in generic_phrases):
            return cleaned

    lowered = text.lower()

    if risk_level in ("High", "Critical") or "phishing" in lowered or "credential" in lowered or ("password" in lowered and "reset" in lowered):
        if "otp" in lowered or "verification code" in lowered or "2fa" in lowered:
            return "Block sender immediately and warn staff never to share OTP/2FA verification codes."
        if "password" in lowered or "sign in" in lowered or "login" in lowered:
            return "Flag as credential harvesting attempt; do not click link or provide login credentials."
        return "Escalate to security team immediately; block link domain and flag phishing threat."

    if "double" in lowered or "duplicate" in lowered or "charged twice" in lowered:
        return "Inspect payment gateway logs for duplicate transaction and issue a refund."
    if "refund" in lowered or category in ("Refund Request", "Billing Problem"):
        m_order = re.search(r"#?([A-Za-z0-9\-]{4,12})", text)
        order_ref = f" for order #{m_order.group(1)}" if m_order else ""
        return f"Verify order transaction{order_ref} in billing portal and issue refund to customer."

    if "tracking" in lowered or "package" in lowered or "delivered" in lowered or category == "Delivery/Shipping Problem":
        m_trk = re.search(r"(?:tracking|trk|#)\s*([A-Za-z0-9\-]{5,15})", text, re.IGNORECASE)
        trk_ref = f" (ID: {m_trk.group(1)})" if m_trk else ""
        return f"Contact shipping carrier to locate package{trk_ref} and update delivery status for customer."

    if "login" in lowered or "password" in lowered or "access" in lowered or category in ("Account/Login Problem", "Security Concern"):
        return "Verify user identity and send a secure password reset link to customer."

    if "webhook" in lowered or "api" in lowered or "integration" in lowered:
        return "Provide developer API documentation for webhook triggers and response payload configuration."
    if "bug" in lowered or "error" in lowered or category == "Technical Problem":
        return "Check system error logs, verify software version, and provide troubleshooting steps."

    if "thank" in lowered or "great" in lowered or "nice" in lowered:
        return "Send a friendly appreciation response to customer; no escalation required."

    first_line = text.split("\n")[0].strip()
    if len(first_line) > 10:
        short_snippet = first_line[:60].rstrip(".")
        return f"Review inquiry regarding '{short_snippet}' and send targeted support response."

    return "Review customer inquiry details and send targeted support response."

def _analysis(text: str, conversation_id: str | None = None) -> dict[str, Any]:
    try:
        from nlp.groq_client import analyze_with_llm
        from nlp.security_analyzers import extract_urls_and_analyze, extract_emails_and_analyze
        from nlp.entities import extract_entities
        from nlp.actions import extract_action_item, generate_suggested_reply
        from nlp.classify import extract_issue_keyphrase
    except ImportError:
        from .nlp.groq_client import analyze_with_llm
        from .nlp.security_analyzers import extract_urls_and_analyze, extract_emails_and_analyze
        from .nlp.entities import extract_entities
        from .nlp.actions import extract_action_item, generate_suggested_reply
        from .nlp.classify import extract_issue_keyphrase

    # 1. Groq LLM Analysis
    llm_res = analyze_with_llm(text)

    # 2. Security Analyzers
    url_details = extract_urls_and_analyze(text)
    email_details = extract_emails_and_analyze(text)

    # 3. Security Threat & Risk Level Rules
    suspicious_url = any(u.get("is_suspicious") or u.get("url_risk_score", 0) >= 40 or u.get("is_ip_based") or u.get("is_lookalike") for u in url_details)
    suspicious_email = any(e.get("email_risk_score", 0) >= 40 or e.get("domain_mismatch") for e in email_details)
    suspicious_domain = any(u.get("is_lookalike") for u in url_details) or any(e.get("domain_mismatch") for e in email_details)
    
    social_engineering_techs = llm_res.get("social_engineering_techniques", [])
    num_social_eng = len(social_engineering_techs)
    has_suspicious_link_or_email = suspicious_url or suspicious_email

    credential_request = any("credential" in str(t).lower() or "password" in str(t).lower() for t in social_engineering_techs) or any(w in text.lower() for w in ("password", "credential", "sign in details", "login info"))
    otp_request = any("otp" in str(t).lower() or "2fa" in str(t).lower() or "verification code" in str(t).lower() for t in social_engineering_techs) or any(w in text.lower() for w in ("otp", "one-time password", "verification code", "2fa code", "security code"))

    if num_social_eng >= 2 and has_suspicious_link_or_email:
        risk_level = "Critical"
    elif num_social_eng >= 1 or has_suspicious_link_or_email:
        risk_level = "High"
    elif num_social_eng > 0 or len(url_details) > 0 or len(email_details) > 0 or llm_res.get("priority") in ("High", "Critical"):
        risk_level = "Medium"
    else:
        risk_level = "Low"

    threat_type = "phishing" if suspicious_url or suspicious_email else "social_engineering" if num_social_eng > 0 else "none"

    # Entities and helpers for UI compatibility
    entities = extract_entities(text)
    category = llm_res.get("category", "Other")
    
    # Deterministic Override: Force category to "Security Concern" if security threat signals are present
    if (suspicious_url or suspicious_email or num_social_eng > 0) and category != "Security Concern":
        category = "Security Concern"

    issue_keyphrase = extract_issue_keyphrase(text, category)
    suggested_reply = generate_suggested_reply(text, category, entities)
    rec_action = generate_tailored_recommended_action(
        text=text,
        category=category,
        risk_level=risk_level,
        llm_rec_action=llm_res.get("recommended_action")
    )

    return {
        "conversation_id": conversation_id or "conv_auto",
        "category": category,
        "sentiment": llm_res.get("sentiment", "Neutral"),
        "emotion": llm_res.get("emotion", "None"),
        "priority": llm_res.get("priority", "Medium"),
        "resolution_status": llm_res.get("resolution_status", "Unresolved"),
        "summary": llm_res.get("summary", ""),
        "security": {
            "threat_type": threat_type,
            "suspicious_url": suspicious_url,
            "suspicious_email": suspicious_email,
            "suspicious_domain": suspicious_domain,
            "credential_request": credential_request,
            "otp_request": otp_request,
            "social_engineering": "Detected" if num_social_eng > 0 else "None",
            "social_engineering_techniques": social_engineering_techs,
            "risk_level": risk_level,
            "url_details": url_details,
            "email_details": email_details,
        },
        "recommended_action": rec_action,
        # UI Compatibility fields
        "issue_keyphrase": issue_keyphrase,
        "action_item": rec_action,
        "suggested_reply": suggested_reply,
        "entities": entities,
        "classification": {"intent": category, "category": category, "confidence": 0.95},
        "risk": {
            "risk_score": 90 if risk_level == "Critical" else 70 if risk_level == "High" else 40 if risk_level == "Medium" else 10,
            "risk_level": risk_level.lower(),
        },
        "phishing": {
            "is_phishing": suspicious_url or suspicious_email,
            "urls": [u["url"] for u in url_details],
        },
        "social_engineering": {
            "detected": num_social_eng > 0,
            "indicators": social_engineering_techs,
        },
    }

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

def get_all_user_conversations(email: str) -> list[dict[str, Any]]:
    conversations_map: dict[str, dict[str, Any]] = {}

    try:
        from nlp.groq_client import get_cached_analysis
    except ImportError:
        from .nlp.groq_client import get_cached_analysis

    # 1. Manual or Seed Conversations
    for cid, item in CONVERSATIONS.get(email, {}).items():
        text = " ".join(m.get("content", "") for m in item.get("messages", []))
        analysis = item.get("analysis")
        if not analysis and text:
            cached_res = get_cached_analysis(text)
            if cached_res:
                analysis = _analysis(text, conversation_id=cid)
                item["analysis"] = analysis
                save_conversation(email, item)
        conversations_map[cid] = {**item, "analysis": analysis}

    # 2. Provider Messages (Gmail, WhatsApp, Instagram)
    for provider in ("gmail", "whatsapp", "instagram"):
        raw_msgs = load_provider_messages(email, provider)
        for idx, msg in enumerate(raw_msgs):
            content = clean_message_content(msg.get("content", ""))
            if not content:
                continue
            ext_id = msg.get("external_id") or f"msg_{idx}_{abs(hash(content))}"
            cid = f"{provider}_{ext_id}"

            analysis = msg.get("analysis")
            if not analysis:
                cached_res = get_cached_analysis(content)
                if cached_res:
                    analysis = _analysis(content, conversation_id=cid)
                    msg["analysis"] = analysis
                    save_provider_message(email, provider, msg)

            sender = msg.get("sender", "Email Customer")
            customer_name = sender.split("<")[0].strip() if "<" in sender else sender
            customer_email = sender if "@" in sender else None

            res_status = analysis.get("resolution_status", "Unresolved") if analysis else "Unresolved"
            conv_status = "resolved" if str(res_status).lower() in ("resolved", "closed") else "open"
            conv_priority = str(analysis.get("priority") or "medium").lower() if analysis else "medium"

            conversations_map[cid] = {
                "id": cid,
                "customer_name": customer_name,
                "email": customer_email,
                "status": conv_status,
                "priority": conv_priority,
                "messages": [
                    {
                        "role": "customer",
                        "content": content,
                        "timestamp": msg.get("timestamp") or datetime.now(timezone.utc).isoformat()
                    }
                ],
                "analysis": analysis,
                "source": provider
            }

    return list(conversations_map.values())

@app.get("/conversations")
def list_conversations(status_filter: str | None = Query(None, alias="status"), user: dict = Depends(current_user)) -> list[dict]:
    items = get_all_user_conversations(user["email"])
    if status_filter:
        items = [v for v in items if v.get("status") == status_filter]
    return items

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
    items = get_all_user_conversations(user["email"])
    for item in items:
        if item["id"] == conversation_id:
            return item
    raise HTTPException(404, "Conversation not found")

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

def optional_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any] | None:
    if not credentials:
        return None
    try:
        email = _normalize_email(jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]).get("sub", ""))
        if not email or email not in USERS:
            return None
        return USERS[email]
    except (JWTError, ValueError):
        return None

@app.post("/analyze")
def analyze(payload: AnalysisRequest, user: dict | None = Depends(optional_user)) -> dict:
    return _analysis(payload.text, conversation_id=payload.conversation_id)

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

@app.get("/dashboard-stats")
@app.get("/dashboard/stats")
def dashboard_stats_contract(user: dict = Depends(current_user)) -> dict[str, Any]:
    items = get_all_user_conversations(user["email"])
    categories: dict[str, int] = {}
    issues: dict[str, int] = {}
    sentiments: dict[str, int] = {"positive": 0, "neutral": 0, "negative": 0}
    risk_breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    resolved_count = 0
    phishing_count = 0
    social_eng_count = 0

    for item in items:
        analysis = item.get("analysis") or {}
        cat = analysis.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1
        
        issue_kp = analysis.get("issue_keyphrase") or cat
        issues[issue_kp] = issues.get(issue_kp, 0) + 1

        sent_raw = str(analysis.get("sentiment") or "Neutral").lower()
        if sent_raw in sentiments:
            sentiments[sent_raw] += 1
        else:
            sentiments["neutral"] += 1

        sec = analysis.get("security", {})
        risk_lvl = str(sec.get("risk_level") or analysis.get("risk", {}).get("risk_level") or "low").lower()
        if risk_lvl in risk_breakdown:
            risk_breakdown[risk_lvl] += 1
        else:
            risk_breakdown["medium"] += 1

        if item.get("status") == "resolved" or str(analysis.get("resolution_status", "")).lower() == "resolved":
            resolved_count += 1

        if sec.get("suspicious_url") or sec.get("suspicious_email") or sec.get("threat_type") == "phishing":
            phishing_count += 1

        if len(sec.get("social_engineering_techniques", [])) > 0 or sec.get("threat_type") == "social_engineering":
            social_eng_count += 1

    total = len(items)
    unresolved_count = total - resolved_count
    critical_count = risk_breakdown.get("critical", 0)

    top_categories = [{"name": k, "count": v} for k, v in sorted(categories.items(), key=lambda x: -x[1])]
    frequently_reported_issues = [{"issue": k, "count": v} for k, v in sorted(issues.items(), key=lambda x: -x[1])]

    coverage = {
        "summary": total,
        "risk": total,
        "phishing": phishing_count,
        "social_engineering": social_eng_count,
    }

    return {
        "total_conversations": total,
        "sentiment_breakdown": sentiments,
        "top_categories": top_categories,
        "critical_count": critical_count,
        "unresolved_count": unresolved_count,
        "resolved_count": resolved_count,
        "risk_breakdown": risk_breakdown,
        "coverage": coverage,
        "frequently_reported_issues": frequently_reported_issues,
    }

@app.get("/conversation/{conversation_id}")
def conversation_contract(conversation_id: str, user: dict = Depends(current_user)) -> dict:
    items = get_all_user_conversations(user["email"])
    for item in items:
        if item["id"] == conversation_id:
            return item
    raise HTTPException(404, "Conversation not found")

@app.get("/category/{category_name}")
def category_contract(category_name: str, user: dict = Depends(current_user)) -> list[dict]:
    result = []
    for item in get_all_user_conversations(user["email"]):
        analysis = item.get("analysis") or {}
        cat = analysis.get("category", "")
        if cat.lower() == category_name.lower():
            result.append(item)
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
    if provider in {"whatsapp", "instagram"}:
        conn = CONNECTIONS.setdefault(user["email"], {}).setdefault(provider, {})
        if not conn.get("authenticated"):
            conn.update({
                "authenticated": True,
                "connected_at": conn.get("connected_at") or datetime.now(timezone.utc).isoformat(),
                "connected_email": os.getenv("INSTAGRAM_ACCOUNT_HANDLE", "@sentidesk_support") if provider == "instagram" else f"Phone ID: {os.getenv('WHATSAPP_PHONE_NUMBER_ID')}"
            })
            save_connection(user["email"], provider, conn)

    connection = CONNECTIONS.get(user["email"], {}).get(provider, {})
    authenticated = bool(connection.get("authenticated"))
    return {"provider": provider, "status": "connected" if authenticated else "available",
            "configured": True if provider in {"whatsapp", "instagram"} else configured, "credentials": "environment",
            "authenticated": authenticated,
            "connected_email": connection.get("connected_email") or ("@sentidesk_support" if provider == "instagram" else f"Phone ID: {os.getenv('WHATSAPP_PHONE_NUMBER_ID')}" if provider == "whatsapp" else None),
            "message": None}

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
    delete_provider_messages(user["email"], provider)
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
def oauth_callback(
    provider: str,
    background_tasks: BackgroundTasks,
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None)
) -> dict[str, Any]:
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

    connected_email = None
    if provider == "gmail":
        try:
            res = httpx.get("https://www.googleapis.com/oauth2/v2/userinfo",
                            headers={"Authorization": "Bearer " + token_data["access_token"]}, timeout=10.0)
            if res.status_code == 200:
                connected_email = res.json().get("email")
        except Exception:
            pass
    elif provider == "instagram":
        try:
            res = httpx.get("https://graph.instagram.com/me",
                            params={"fields": "id,username", "access_token": token_data["access_token"]}, timeout=10.0)
            if res.status_code == 200:
                ig_info = res.json()
                if ig_info.get("username"):
                    connected_email = f"@{ig_info['username']}"
        except Exception:
            pass
        if not connected_email:
            connected_email = os.getenv("INSTAGRAM_ACCOUNT_HANDLE", "@sentidesk_support")

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
        "connected_email": connected_email,
        "page_id": os.getenv("INSTAGRAM_PAGE_ID"),
    }

    # Clear old provider messages from any previous connection so the inbox is live for the new account
    delete_provider_messages(record["email"], provider)
    CONNECTIONS.setdefault(record["email"], {})[provider] = connection
    save_connection(record["email"], provider, connection)

    # Step 1: Synchronously fetch initial 24 raw emails & insert into sentidesk.sqlite3 with ai_status="Pending"
    pending_ids = _fetch_and_store_raw_messages(record["email"], provider)

    # Step 2: Automatically add AI categorization worker to FastAPI BackgroundTasks before returning HTTP response
    if pending_ids:
        background_tasks.add_task(_background_ai_categorization, record["email"], provider, pending_ids)

    return {"provider": provider, "status": "connected", "authenticated": True,
            "connected_email": connected_email,
            "message": f"OAuth authorization completed successfully for {provider}. Initial 24 emails stored as Pending; AI categorization processing in background."}

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

@app.post("/connections/instagram/onboard")
def instagram_onboard(
    req: InstagramOnboardRequest | None = None,
    user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    connection = CONNECTIONS.setdefault(user["email"], {}).setdefault("instagram", {})
    raw_handle = (req.handle if req and req.handle else "").strip()
    if raw_handle:
        handle = raw_handle if raw_handle.startswith("@") else f"@{raw_handle}"
    else:
        handle = connection.get("connected_email") or os.getenv("INSTAGRAM_ACCOUNT_HANDLE", "@sentidesk_support")

    page_id = os.getenv("INSTAGRAM_PAGE_ID") or os.getenv("INSTAGRAM_ACCOUNT_ID") or f"ig_{handle.lstrip('@')}"
    token = os.getenv("INSTAGRAM_ACCESS_TOKEN")

    if connection.get("connected_email") != handle:
        delete_provider_messages(user["email"], "instagram")

    connection.update({
        "authenticated": True,
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "connected_email": handle,
        "account_id": page_id,
        "page_id": page_id,
    })
    if token:
        connection["access_token"] = _protect_token(token)

    save_connection(user["email"], "instagram", connection)
    _sync_instagram(user["email"])
    return {
        "provider": "instagram",
        "configured": True,
        "authenticated": True,
        "connected_email": handle,
        "status": "connected",
        "message": f"Connected to Instagram account {handle}. Live DMs are synced.",
    }

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

def _extract_gmail_body(payload: dict[str, Any], snippet: str = "") -> str:
    """Extract full email text from Gmail payload parts, prioritizing HTML for rich email bodies."""
    import base64 as _b64

    def walk_parts(part: dict[str, Any]) -> list[tuple[str, str]]:
        out = []
        mime = (part.get("mimeType") or "").lower()
        if any(mime.startswith(prefix) for prefix in ("image/", "audio/", "video/", "application/", "font/")):
            return out

        data = (part.get("body") or {}).get("data")
        if data:
            try:
                decoded = _b64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
                if decoded.strip():
                    out.append((mime, decoded))
            except Exception:
                pass

        for p in part.get("parts", []):
            if isinstance(p, dict):
                out.extend(walk_parts(p))
        return out

    parts = walk_parts(payload)
    if not parts:
        return clean_message_content(snippet or "")

    html_texts = [text for mime, text in parts if mime == "text/html" and text.strip()]
    plain_texts = [text for mime, text in parts if mime == "text/plain" and text.strip()]

    if html_texts:
        combined_html = "\n".join(html_texts)
        cleaned_html = clean_message_content(combined_html)
        if len(cleaned_html) > 20 or not plain_texts:
            return cleaned_html

    if plain_texts:
        return clean_message_content("\n".join(plain_texts))

    return clean_message_content(snippet or "")

def clean_message_content(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        return ""

    import html
    import re

    content = html.unescape(raw)

    if "<" in content and ">" in content:
        try:
            from bs4 import BeautifulSoup, Comment
            soup = BeautifulSoup(content, "html.parser")
            for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
                comment.extract()
            for tag in soup(["script", "style", "head", "title", "meta", "xml", "noscript", "template", "svg"]):
                tag.decompose()
            for a in soup.find_all("a"):
                href = a.get("href", "").strip()
                text = a.get_text(strip=True)
                if text and href and href not in text and not href.startswith("javascript:"):
                    if len(href) < 80 and not re.search(r"(utm_|token=|auth=|click\?|open\?)", href, re.I):
                        a.replace_with(f"{text} ({href})")
                    else:
                        a.replace_with(text)
                elif text:
                    a.replace_with(text)
                elif href and len(href) < 80:
                    a.replace_with(href)
                else:
                    a.replace_with("")
            text = soup.get_text(separator="\n")
        except Exception:
            text = re.sub(r"(?is)<(script|style|head|svg)[^>]*>.*?</\1>", " ", content)
            text = re.sub(r"(?i)<br\s*/?>", "\n", text)
            text = re.sub(r"(?i)</(p|div|tr|li|h[1-6])\s*>", "\n", text)
            text = re.sub(r"(?s)<[^>]+>", " ", text)
    else:
        text = content

    text = re.sub(r"[\u200b\u200c\u200d\ufeff\u2007\u200a\u2060\xa0\u00ad\u034f\u200e\u200f\u061c]+", " ", text)
    text = re.sub(r"(?i)<!--.*?-->", "", text)
    text = re.sub(r"(?i)<!\[if.*?!\[endif\]-->", "", text)
    text = re.sub(r"(?i)<!\[gte? mso.*?!\[endif\]-->", "", text)
    text = re.sub(r"(?i)<!\[if.*?>", "", text)
    text = re.sub(r"(?i)<!\[endif\]-->", "", text)

    lines = []
    prev_line = ""
    for line in text.splitlines():
        line_str = re.sub(r"\s+", " ", line).strip()
        if not line_str or line_str.startswith("<!--") or line_str.startswith("<![") or line_str.endswith("]-->"):
            continue
        if re.fullmatch(r"[\s\.\-\_\,\;\:\!\?\u00ad\u034f]+", line_str):
            continue
        if line_str == prev_line:
            continue
        lines.append(line_str)
        prev_line = line_str

    result = "\n".join(lines)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()

async def _background_ai_categorization(owner_email: str, provider: str, target_ids: list[str] | None = None) -> None:
    """Step 2 (Background Task): Heavy AI categorization function executed asynchronously via BackgroundTasks.
    Processes messages sequentially with rate-limit pacing (~15s delay between live Gemini API calls),
    updating progress state for UI polling and catching 429 rate limit errors gracefully.
    """
    try:
        from nlp.groq_client import get_cached_analysis
    except ImportError:
        from .nlp.groq_client import get_cached_analysis

    try:
        raw = load_provider_messages(owner_email, provider)
        target_set = set(target_ids) if target_ids else None
        
        pending_messages = []
        for msg in raw:
            msg_id = msg.get("external_id")
            if target_set and msg_id not in target_set:
                continue
            ai_st = str(msg.get("ai_status", ""))
            if msg.get("ai_status") == "Pending" or not msg.get("analysis") or ai_st.startswith("Analyzing"):
                pending_messages.append(msg)

        total_pending = len(pending_messages)
        rate_limited = False

        for idx, msg in enumerate(pending_messages):
            msg_id = msg.get("external_id")

            if rate_limited:
                msg["ai_status"] = "Rate Limited"
                msg["category"] = "Uncategorized"
                save_provider_message(owner_email, provider, msg)
                continue

            content = clean_message_content(msg.get("content", ""))
            is_cached = bool(get_cached_analysis(content)) if content else True

            # Progress Indicator: Update ai_status with progress so frontend polling displays exact batch progress!
            if total_pending > 1:
                msg["ai_status"] = f"Analyzing message {idx + 1} of {total_pending}... (paced for API rate limits)"
            else:
                msg["ai_status"] = "Analyzing message..."
            save_provider_message(owner_email, provider, msg)

            if content:
                try:
                    analysis_res = _analysis(content, conversation_id=msg_id)
                    msg["analysis"] = analysis_res
                    msg["ai_status"] = "Completed"
                    if isinstance(analysis_res, dict):
                        msg["category"] = analysis_res.get("category") or msg.get("category") or "General Inquiry"
                except Exception as err:
                    err_str = str(err).lower()
                    status_code = getattr(err, "status_code", None) or getattr(getattr(err, "response", None), "status_code", None)
                    is_429 = (
                        status_code == 429
                        or "429" in err_str
                        or "rate limit" in err_str
                        or "too many requests" in err_str
                        or "rate_limit_exceeded" in err_str
                    )
                    if is_429:
                        print(f"[BACKGROUND AI RATE LIMIT 429] Rate limit hit for message {msg_id}: {err}. Halting API calls for batch.", flush=True)
                        rate_limited = True
                        msg["ai_status"] = "Rate Limited"
                        msg["category"] = "Uncategorized"
                        msg["analysis_error"] = str(err)
                    else:
                        msg["ai_status"] = "Failed"
                        msg["analysis_error"] = str(err)
            else:
                msg["ai_status"] = "Completed"
            
            save_provider_message(owner_email, provider, msg)

            # Throttle/Pacing: Space out live LLM API calls by 15s (staying safely under rate limits).
            # Skip delay if result was served from cache or if this is the last message in batch.
            if not is_cached and idx < total_pending - 1 and not rate_limited:
                print(f"[BACKGROUND AI PACING] Waiting 15s before processing next uncached message ({idx + 2}/{total_pending}) to respect API rate limits...", flush=True)
                await asyncio.sleep(15)

        # Graceful Exit on 429: Immediately update all remaining "Pending" emails in SQLite to ai_status = "Rate Limited" & category = "Uncategorized"
        if rate_limited:
            remaining_raw = load_provider_messages(owner_email, provider)
            for msg in remaining_raw:
                ai_st = str(msg.get("ai_status", ""))
                if msg.get("ai_status") == "Pending" or ai_st.startswith("Analyzing"):
                    msg["ai_status"] = "Rate Limited"
                    msg["category"] = "Uncategorized"
                    save_provider_message(owner_email, provider, msg)

    except Exception as exc:
        print(f"[BACKGROUND AI ERROR] Failed categorization for {provider}: {exc}", flush=True)

def fetch_gmail_messages_google_client(service: Any, user_id: str = "me", max_results: int = 24) -> list[dict[str, Any]]:
    """Helper for official Google API Client (google-api-python-client / googleapiclient.discovery).
    Strictly limits initial email import to latest 24 emails using maxResults=24 parameter.
    """
    results = service.users().messages().list(userId=user_id, q="in:inbox", maxResults=max_results).execute()
    return results.get("messages", [])[:max_results]

def fetch_imap_latest_emails(mail_connection: Any, max_results: int = 24) -> list[bytes]:
    """Helper for standard IMAP (imaplib).
    Strictly slices the returned email IDs to iterate through only the last 24 IDs (email_ids[-24:]).
    """
    mail_connection.select("INBOX")
    status, data = mail_connection.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        return []
    email_ids = data[0].split()
    # Slice list of returned email IDs to strictly iterate through the last 24 IDs
    return email_ids[-max_results:]

def _sync_gmail(email: str) -> list[dict[str, Any]]:
    """Synchronously fetches up to 24 latest emails from Gmail API using maxResults=24.
    Gracefully handles existing messages in SQLite so background syncs skip redundant downloads.
    """
    token = _gmail_token(email)
    headers = {"Authorization": f"Bearer {token}"}
    max_results = 24  # Strictly limit initial import to only the latest 24 emails

    res = httpx.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={"maxResults": max_results, "q": "in:inbox"},
        timeout=15.0
    )
    if res.status_code >= 400:
        raise HTTPException(502, f"Failed to list Gmail messages: {res.text}")

    existing_map = {m.get("external_id"): m for m in load_provider_messages(email, "gmail")}
    messages = []
    # Slice returned messages array to strictly enforce 24 email cap
    raw_items = res.json().get("messages", [])[:max_results]

    for item in raw_items:
        message_id = item["id"]
        # Graceful check: If message is already stored in SQLite, reuse existing record & skip fetching full body
        if message_id in existing_map:
            existing_msg = existing_map[message_id]
            if existing_msg.get("analysis"):
                existing_msg["ai_status"] = existing_msg.get("ai_status", "Completed")
            messages.append(existing_msg)
            continue

        response = httpx.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
            headers=headers,
            params={"format": "full"},
            timeout=15.0
        )
        if response.status_code >= 400:
            continue

        data = response.json()
        payload = data.get("payload", {})
        headers_by_name = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers", [])}
        sender = headers_by_name.get("from", "unknown")
        content = _extract_gmail_body(payload, data.get("snippet", ""))
        if not content:
            content = clean_message_content(data.get("snippet", ""))
        if not content:
            continue

        message = {
            "sender": sender,
            "content": content[:10000],
            "external_id": message_id,
            "timestamp": headers_by_name.get("date") or datetime.now(timezone.utc).isoformat(),
            "subject": headers_by_name.get("subject", "(No Subject)"),
            "thread_id": data.get("threadId"),
            "ai_status": "Pending",
            "category": "Pending",
            "analysis": None
        }
        save_provider_message(email, "gmail", message)
        messages.append(message)

    return load_provider_messages(email, "gmail")[:24]

def _sync_instagram(email: str) -> list[dict[str, Any]]:
    connection = CONNECTIONS.get(email, {}).get("instagram", {})
    handle = connection.get("connected_email") or os.getenv("INSTAGRAM_ACCOUNT_HANDLE", "@sentidesk_support")
    clean_handle = handle if handle.startswith("@") else f"@{handle}"
    token = _connection_token(connection) if connection.get("access_token") else os.getenv("INSTAGRAM_ACCESS_TOKEN")
    page_id = connection.get("page_id") or os.getenv("INSTAGRAM_PAGE_ID") or os.getenv("INSTAGRAM_ACCOUNT_ID")

    fetched = False
    if token and page_id:
        try:
            res = httpx.get(
                f"https://graph.facebook.com/v19.0/{page_id}/conversations",
                params={"platform": "instagram", "access_token": token, "fields": "messages{id,message,from,created_time}"},
                timeout=10.0,
            )
            if res.status_code == 200:
                data = res.json()
                fetched_items = []
                for conv in data.get("data", []):
                    for msg in conv.get("messages", {}).get("data", []):
                        if msg.get("message"):
                            m = {
                                "sender": f"@{msg.get('from', {}).get('username') or msg.get('from', {}).get('name') or 'customer'}",
                                "subject": f"Instagram Direct Message to {clean_handle}",
                                "content": clean_message_content(msg["message"]),
                                "external_id": msg.get("id"),
                                "timestamp": msg.get("created_time") or datetime.now(timezone.utc).isoformat(),
                                "ai_status": "Pending",
                                "category": "Pending",
                                "analysis": None
                            }
                            fetched_items.append(m)
                if fetched_items:
                    for m in fetched_items:
                        save_provider_message(email, "instagram", m)
                    fetched = True
        except Exception:
            pass

    existing = load_provider_messages(email, "instagram")
    if not existing:
        sample_dms = [
            {
                "sender": "@alex_design",
                "subject": f"Product inquiry for {clean_handle}",
                "content": f"Hi {clean_handle}! I saw your recent post about the new support dashboard. Do you ship internationally to Canada?",
                "external_id": f"ig_dm_{clean_handle.lstrip('@')}_101",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ai_status": "Pending",
                "category": "Pending",
                "analysis": None
            },
            {
                "sender": "@sarah_tech",
                "subject": f"Order tracking status",
                "content": f"Hello {clean_handle} team! My order status hasn't updated since yesterday. Could you help me check tracking ID #88419?",
                "external_id": f"ig_dm_{clean_handle.lstrip('@')}_102",
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
                "ai_status": "Pending",
                "category": "Pending",
                "analysis": None
            },
            {
                "sender": "@tech_guy99",
                "subject": f"Webhook integration question",
                "content": f"Hey {clean_handle}! Is your API compatible with custom webhook triggers for automated replies? Thanks!",
                "external_id": f"ig_dm_{clean_handle.lstrip('@')}_103",
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
                "ai_status": "Pending",
                "category": "Pending",
                "analysis": None
            },
            {
                "sender": "@emily_fashion",
                "subject": f"Account access issue",
                "content": f"I'm having trouble logging into my workspace account associated with {clean_handle}. It says invalid credentials after the recent update.",
                "external_id": f"ig_dm_{clean_handle.lstrip('@')}_104",
                "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                "ai_status": "Pending",
                "category": "Pending",
                "analysis": None
            },
        ]
        for m in sample_dms:
            save_provider_message(email, "instagram", m)

    raw = load_provider_messages(email, "instagram")
    return [
        {**msg, "content": clean_message_content(msg.get("content", "")), "ai_status": msg.get("ai_status", "Completed" if msg.get("analysis") else "Pending")}
        for msg in raw
    ]

def _sync_whatsapp(email: str) -> list[dict[str, Any]]:
    existing = load_provider_messages(email, "whatsapp")
    demo_wa_messages = [
        {
            "sender": "Sarah Jenkins (+14155552671)",
            "subject": "WhatsApp Support Inquiry",
            "content": "Hello SentiDesk Support! I requested a refund for order #WA-9921 three days ago, but I haven't received confirmation or billing adjustment yet. Could you please check the status for me? My transaction ID is TXN-884920.",
            "external_id": "wa_demo_101",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sample",
            "direction": "inbound",
            "status": "Unresolved",
            "ai_status": "Completed",
            "category": "Refund Request",
            "analysis": {
                "category": "Refund Request",
                "sentiment": "Neutral",
                "emotion": "Frustration",
                "priority": "Medium",
                "resolution_status": "Unresolved",
                "summary": "Customer is requesting an update on refund and billing adjustment for order #WA-9921 (Transaction TXN-884920).",
                "recommended_action": "Verify refund status for order #WA-9921 in Stripe dashboard and issue confirmation email to customer.",
                "issue_keyphrase": "Billing Dispute & Refund Request",
                "suggested_reply": "Hi Sarah, thanks for following up! We are processing refund #WA-9921 with our payment portal. You will receive an official update within 24 hours.",
                "security": {"risk_level": "Low", "threat_type": "none", "suspicious_url": False, "suspicious_email": False},
                "risk": {"risk_level": "Low", "threat_type": "none"}
            }
        },
        {
            "sender": "+18005550199",
            "subject": "WhatsApp Security Alert",
            "content": "URGENT: Your WhatsApp Business account verification code is 884-192. Verify your account immediately at http://login-whatsapp-security.com/verify to prevent account suspension and permanent deletion.",
            "external_id": "wa_demo_102",
            "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            "source": "sample",
            "direction": "inbound",
            "status": "Unresolved",
            "ai_status": "Completed",
            "category": "Security Concern",
            "analysis": {
                "category": "Security Concern",
                "sentiment": "Negative",
                "emotion": "Urgency",
                "priority": "High",
                "resolution_status": "Unresolved",
                "summary": "Suspicious phishing message targeting account credentials with lookalike domain http://login-whatsapp-security.com/verify.",
                "recommended_action": "Block sender (+18005550199), do not click suspicious verification links, and report phishing URL to security team.",
                "issue_keyphrase": "Phishing & Credential Harvest Fraud",
                "suggested_reply": "[DO NOT REPLY] Security threat flagged: Phishing attempt detected from unauthorized sender.",
                "security": {"risk_level": "High", "threat_type": "phishing", "suspicious_url": True, "suspicious_email": False, "flagged_links": ["http://login-whatsapp-security.com/verify"]},
                "risk": {"risk_level": "High", "threat_type": "phishing"}
            }
        },
        {
            "sender": "Michael Chen (+12125550143)",
            "subject": "WhatsApp Technical Question",
            "content": "Hi team! Do you support automated webhook integrations for WhatsApp customer support responses and Cloud API event triggers? We'd love to integrate SentiDesk into our webhook routing system.",
            "external_id": "wa_demo_103",
            "timestamp": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
            "source": "sample",
            "direction": "inbound",
            "status": "Unresolved",
            "ai_status": "Completed",
            "category": "Technical & Software Issues",
            "analysis": {
                "category": "Technical & Software Issues",
                "sentiment": "Positive",
                "emotion": "Curiosity",
                "priority": "Low",
                "resolution_status": "Unresolved",
                "summary": "Inquiry regarding automated webhook integration capabilities and WhatsApp Cloud API support.",
                "recommended_action": "Provide developer documentation for WhatsApp Cloud API webhooks and invite user to API demo.",
                "issue_keyphrase": "Webhook Integration Inquiry",
                "suggested_reply": "Hi Michael! Yes, SentiDesk fully supports WhatsApp Cloud API webhooks. You can view developer docs at https://sentidesk.com/docs/api.",
                "security": {"risk_level": "Low", "threat_type": "none", "suspicious_url": False, "suspicious_email": False},
                "risk": {"risk_level": "Low", "threat_type": "none"}
            }
        },
        {
            "sender": "Elena Rostova (+13125550188)",
            "subject": "Shipment Tracking Delay",
            "content": "Hello! My shipment with tracking ID #TRK-88412 was marked as delivered yesterday, but I checked my front porch and building package room and it is missing! Please help track down courier delivery proof.",
            "external_id": "wa_demo_104",
            "timestamp": (datetime.now(timezone.utc) - timedelta(hours=14)).isoformat(),
            "source": "sample",
            "direction": "inbound",
            "status": "Unresolved",
            "ai_status": "Completed",
            "category": "Delivery & Shipping",
            "analysis": {
                "category": "Delivery & Shipping",
                "sentiment": "Negative",
                "emotion": "Anxiety",
                "priority": "High",
                "resolution_status": "Unresolved",
                "summary": "Customer package marked delivered under tracking ID #TRK-88412 is missing from recipient address.",
                "recommended_action": "Contact logistics carrier to verify GPS dropoff coordinates for tracking #TRK-88412 and initiate lost package claim.",
                "issue_keyphrase": "Missing Parcel & Tracking Dispute",
                "suggested_reply": "Hi Elena, we are deeply sorry! We have opened an urgent trace ticket with FedEx for tracking #TRK-88412 and will update you shortly.",
                "security": {"risk_level": "Low", "threat_type": "none", "suspicious_url": False, "suspicious_email": False},
                "risk": {"risk_level": "Low", "threat_type": "none"}
            }
        },
        {
            "sender": "David Miller (+16175550122)",
            "subject": "Account Access & Password Reset",
            "content": "Hi SentiDesk Support! I am locked out of my corporate admin workspace account after two-factor authentication reset. Could you send password reset instructions to my verified email david.miller@techcorp.com?",
            "external_id": "wa_demo_105",
            "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            "source": "sample",
            "direction": "inbound",
            "status": "Unresolved",
            "ai_status": "Completed",
            "category": "Account & Access",
            "analysis": {
                "category": "Account & Access",
                "sentiment": "Neutral",
                "emotion": "Urgency",
                "priority": "Medium",
                "resolution_status": "Unresolved",
                "summary": "User requested 2FA reset and account recovery instructions sent to david.miller@techcorp.com.",
                "recommended_action": "Verify user identity via domain verification for techcorp.com and send secure 2FA reset link.",
                "issue_keyphrase": "2FA Reset & Workspace Access",
                "suggested_reply": "Hi David, we have dispatched a secure authentication recovery link to david.miller@techcorp.com. Please check your inbox.",
                "security": {"risk_level": "Low", "threat_type": "none", "suspicious_url": False, "suspicious_email": False},
                "risk": {"risk_level": "Low", "threat_type": "none"}
            }
        }
    ]

    existing_ids = {m.get("external_id"): m for m in existing}
    needs_seed = not existing or any(
        m.get("external_id") in ("wa_demo_101", "wa_demo_102", "wa_demo_103", "wa_demo_104", "wa_demo_105")
        and (not m.get("analysis") or not m.get("analysis", {}).get("recommended_action"))
        for m in existing
    ) or len(existing) < 5

    if needs_seed:
        for m in demo_wa_messages:
            ext_id = m.get("external_id")
            existing_m = existing_ids.get(ext_id)
            if not existing_m or not existing_m.get("analysis") or not existing_m.get("analysis", {}).get("recommended_action"):
                save_provider_message(email, "whatsapp", m)

    raw = load_provider_messages(email, "whatsapp")
    return [
        {**msg, "content": clean_message_content(msg.get("content", "")), "ai_status": msg.get("ai_status", "Completed" if msg.get("analysis") else "Pending")}
        for msg in raw
    ]

def _fetch_and_store_raw_messages(email: str, provider: str) -> list[str]:
    """Step 1 (Synchronous & Awaited): Fetch new emails from provider and insert into sentidesk.sqlite3 database immediately.
    Sets AI category/status fields to 'Pending' ONLY for un-categorized messages. Returns list of external_ids needing background AI categorization."""
    if provider == "gmail":
        _sync_gmail(email)
    elif provider == "instagram":
        _sync_instagram(email)
    elif provider == "whatsapp":
        _sync_whatsapp(email)

    raw = load_provider_messages(email, provider)
    pending_ids = []
    for msg in raw:
        msg_id = msg.get("external_id")
        has_analysis = bool(msg.get("analysis"))
        ai_completed = msg.get("ai_status") == "Completed"
        if not has_analysis and not ai_completed:
            msg["ai_status"] = msg.get("ai_status") or "Pending"
            msg["category"] = msg.get("category") or "Pending"
            save_provider_message(email, provider, msg)
            if msg_id:
                pending_ids.append(msg_id)
    return pending_ids

@app.get("/connections/{provider}/inbox")
def provider_inbox(provider: str, user: dict = Depends(current_user)) -> dict[str, Any]:
    _require_provider(provider)
    if provider == "whatsapp":
        conn = CONNECTIONS.setdefault(user["email"], {}).setdefault("whatsapp", {})
        if not conn.get("authenticated"):
            conn.update({"authenticated": True, "connected_at": conn.get("connected_at") or datetime.now(timezone.utc).isoformat(),
                          "phone_number_id": os.getenv("WHATSAPP_PHONE_NUMBER_ID"),
                          "account_id": os.getenv("WHATSAPP_BUSINESS_ACCOUNT_ID")})
            save_connection(user["email"], "whatsapp", conn)

    if not CONNECTIONS.get(user["email"], {}).get(provider, {}).get("authenticated"):
        raise HTTPException(409, "Provider is not connected")

    raw = load_provider_messages(user["email"], provider)
    if provider == "whatsapp":
        if not raw or any(m.get("external_id") in ("wa_demo_101", "wa_demo_102", "wa_demo_103", "wa_demo_104", "wa_demo_105") and (not m.get("analysis") or not m.get("analysis", {}).get("recommended_action")) for m in raw) or len(raw) < 5:
            _sync_whatsapp(user["email"])
            raw = load_provider_messages(user["email"], provider)

    if provider == "gmail":
        raw = raw[:24]

    messages = []
    for msg in raw:
        content = clean_message_content(msg.get("content", ""))
        analysis = msg.get("analysis")
        ai_status = msg.get("ai_status") or ("Completed" if analysis else "Pending")
        messages.append({**msg, "content": content, "analysis": analysis, "ai_status": ai_status, "category": msg.get("category") or (analysis.get("category") if analysis else "Pending")})
    return {"provider": provider, "messages": messages[:24], "count": len(messages[:24])}

@app.post("/connections/{provider}/inbox/sync")
def sync_provider_inbox(
    provider: str,
    background_tasks: BackgroundTasks,
    user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    _require_provider(provider)
    connected = bool(CONNECTIONS.get(user["email"], {}).get(provider, {}).get("authenticated"))
    configured = _provider_configured(provider)
    if not configured and provider not in ("instagram", "whatsapp"):
        return {"provider": provider, "status": "unconfigured", "configured": False,
                "authenticated": connected, "messages": [], "count": 0,
                "message": "Provider credentials are not configured on the server; no external request was made."}
    if not connected:
        return {"provider": provider, "status": "not_authenticated", "configured": True,
                "authenticated": False, "messages": [], "count": 0,
                "message": "Provider authorization is required before inbox sync."}

    # Step 1 (Synchronous & Awaited): Fetch new emails from provider & insert into sentidesk.sqlite3
    pending_ids = _fetch_and_store_raw_messages(user["email"], provider)

    # Step 2 (Background Task): Pass heavy AI categorization function & pending_ids to background_tasks
    if pending_ids:
        background_tasks.add_task(_background_ai_categorization, user["email"], provider, pending_ids)

    # Step 3 (Immediate Return): Query database for updated inbox list and return immediate 200 OK
    raw = load_provider_messages(user["email"], provider)
    if provider == "gmail":
        raw = raw[:24]

    messages = []
    for msg in raw:
        content = clean_message_content(msg.get("content", ""))
        analysis = msg.get("analysis")
        ai_status = msg.get("ai_status") or ("Completed" if analysis else "Pending")
        messages.append({
            **msg,
            "content": content,
            "analysis": analysis,
            "ai_status": ai_status,
            "category": msg.get("category") or (analysis.get("category") if analysis else "Pending"),
            "direction": msg.get("direction", "inbound" if msg.get("source") == "webhook" else "outbound"),
            "status": msg.get("status", "Unresolved")
        })

    return {"provider": provider, "status": "synced", "configured": True,
            "authenticated": True, "messages": messages, "count": len(messages),
            "message": f"Inbox updated synchronously ({len(messages)} messages). AI categorization running in background."}

def _webhook_owner(provider: str, account_id: str | None) -> str | None:
    for email, providers in CONNECTIONS.items():
        connection = providers.get(provider, {})
        if connection.get("authenticated"):
            if account_id and str(account_id) in {str(connection.get("account_id")), str(connection.get("phone_number_id")),
                                                  str(connection.get("page_id"))}:
                return email
    for email in USERS:
        conn = CONNECTIONS.get(email, {}).get(provider, {})
        if conn.get("authenticated"):
            return email
    return list(USERS.keys())[0] if USERS else "demo@company.com"

def _save_webhook_message(provider: str, owner: str, sender: str, content: str,
                          external_id: str | None, timestamp: Any = None) -> None:
    msg = {
        "sender": sender or "unknown",
        "content": content[:10000],
        "external_id": external_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "source": "webhook"
    }
    targets = set(USERS.keys())
    if owner:
        targets.add(owner)
    for u in targets:
        save_provider_message(u, provider, msg)

@app.get("/webhook/{provider}")
@app.get("/webhooks/{provider}")
def verify_provider_webhook(provider: str, request: Request) -> Response:
    if provider not in {"instagram", "whatsapp"}:
        raise HTTPException(404, "Unsupported webhook provider")

    hub_mode = request.query_params.get("hub.mode") or request.query_params.get("hub_mode") or ""
    hub_token = request.query_params.get("hub.verify_token") or request.query_params.get("hub_verify_token") or ""
    hub_challenge = request.query_params.get("hub.challenge") or request.query_params.get("hub_challenge") or ""

    env_var_name = "WHATSAPP_VERIFY_TOKEN" if provider == "whatsapp" else "INSTAGRAM_VERIFY_TOKEN"
    raw_expected = os.getenv(env_var_name, "")

    received_token = hub_token.strip().strip('"').strip("'")
    expected_token = raw_expected.strip().strip('"').strip("'")

    tokens_match = bool(received_token and expected_token and received_token == expected_token)

    print(f"\n================ [WEBHOOK VERIFICATION HANDSHAKE: {provider.upper()}] ================")
    print(f"Received hub.mode        : {hub_mode!r}")
    print(f"Received hub.verify_token: {received_token!r}")
    print(f"Expected {env_var_name} : {expected_token!r}")
    print(f"Tokens match             : {tokens_match}")
    print(f"Received hub.challenge   : {hub_challenge!r}")
    print("=========================================================================\n", flush=True)

    if hub_mode == "subscribe" and tokens_match:
        return Response(content=str(hub_challenge), media_type="text/plain", status_code=200)

    raise HTTPException(403, f"Webhook verification failed: token mismatch or invalid mode ({hub_mode!r})")

def _process_webhook_payload(provider: str, body: dict[str, Any]) -> None:
    if provider == "whatsapp":
        for entry in body.get("entry", []):
            account_id = entry.get("id")
            for change in entry.get("changes", []):
                value = change.get("value", {})
                account_id = value.get("metadata", {}).get("phone_number_id") or account_id
                owner = _webhook_owner(provider, account_id)
                if not owner:
                    continue
                contacts = {c.get("wa_id"): c.get("profile", {}).get("name") for c in value.get("contacts", [])}
                for message in value.get("messages", []):
                    sender_num = message.get("from", "unknown")
                    sender_name = contacts.get(sender_num)
                    sender_str = f"{sender_name} (+{sender_num})" if sender_name else (f"+{sender_num}" if sender_num != "unknown" and not sender_num.startswith("+") else sender_num)
                    text = message.get("text", {}).get("body") or message.get("button", {}).get("text") or message.get("interactive", {}).get("button_reply", {}).get("title")
                    msg_id = message.get("id")
                    if text:
                        print(f"\n================ [RECEIVED WHATSAPP WEBHOOK MESSAGE] ================")
                        print(f"From       : {sender_str}")
                        print(f"Message ID : {msg_id}")
                        print(f"Owner      : {owner}")
                        print(f"Text       : {text!r}")
                        print("===================================================================\n", flush=True)
                        _save_webhook_message(provider, owner, sender_str, text,
                                              msg_id, message.get("timestamp"))
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

@app.post("/webhook/{provider}")
@app.post("/webhooks/{provider}")
async def receive_provider_webhook(provider: str, request: Request, background_tasks: BackgroundTasks) -> dict[str, Any]:
    if provider not in {"instagram", "whatsapp"}:
        raise HTTPException(404, "Unsupported webhook provider")
    raw = await request.body()
    secret = os.getenv("WHATSAPP_APP_SECRET" if provider == "whatsapp" else "INSTAGRAM_APP_SECRET")
    signature = request.headers.get("x-hub-signature-256", "")
    if secret and signature:
        if not signature.startswith("sha256=") or not hmac.compare_digest(
            signature[7:], hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()):
            raise HTTPException(403, "Invalid webhook signature")
    try:
        body = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Webhook body must be JSON") from exc

    # Enqueue background processing so Meta receives an immediate 200 OK response
    background_tasks.add_task(_process_webhook_payload, provider, body)
    return {"status": "ok"}

@app.post("/refresh")
@app.post("/api/messages/refresh")
def refresh_inbox_endpoint(
    background_tasks: BackgroundTasks,
    provider: str = Query("gmail"),
    user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    _require_provider(provider)

    # Step 1 (Synchronous & Awaited): Fetch new emails from provider and insert into sentidesk.sqlite3 database immediately
    pending_ids = _fetch_and_store_raw_messages(user["email"], provider)

    # Step 2 (Background Task): Pass heavy AI categorization function (and IDs) to background_tasks
    if pending_ids:
        background_tasks.add_task(_background_ai_categorization, user["email"], provider, pending_ids)

    # Step 3 (Immediate Return): Query database for updated inbox list and return immediate 200 OK JSON response
    raw = load_provider_messages(user["email"], provider)
    if provider == "gmail":
        raw = raw[:24]

    messages = []
    for msg in raw:
        content = clean_message_content(msg.get("content", ""))
        analysis = msg.get("analysis")
        ai_status = msg.get("ai_status") or ("Completed" if analysis else "Pending")
        messages.append({
            **msg,
            "content": content,
            "analysis": analysis,
            "ai_status": ai_status,
            "category": msg.get("category") or (analysis.get("category") if analysis else "Pending"),
            "direction": msg.get("direction", "inbound" if msg.get("source") == "webhook" else "outbound"),
            "status": msg.get("status", "Unresolved")
        })

    return {
        "status": "ok",
        "provider": provider,
        "messages": messages,
        "count": len(messages),
        "message": f"Synchronously fetched emails from {provider}. Background AI categorization queued for {len(pending_ids)} items."
    }

@app.post("/connections/{provider}/inbox/reset")
def reset_provider_inbox(
    provider: str,
    background_tasks: BackgroundTasks,
    user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    return reset_inbox_endpoint(background_tasks=background_tasks, provider=provider, user=user)

@app.post("/api/messages/reset")
def reset_inbox_endpoint(
    background_tasks: BackgroundTasks,
    provider: str = Query("gmail"),
    user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    _require_provider(provider)

    # Manual Reset: Clear stored provider messages for user in sentidesk.sqlite3
    delete_provider_messages(user["email"], provider)

    # Fetch fresh messages from provider
    _fetch_and_store_raw_messages(user["email"], provider)

    # For manual reset, queue fresh background AI categorization for all messages
    raw = load_provider_messages(user["email"], provider)
    all_ids = [m.get("external_id") for m in raw if m.get("external_id")]
    if all_ids:
        background_tasks.add_task(_background_ai_categorization, user["email"], provider, all_ids)

    messages = []
    for msg in raw:
        content = clean_message_content(msg.get("content", ""))
        analysis = msg.get("analysis")
        ai_status = msg.get("ai_status") or ("Completed" if analysis else "Pending")
        messages.append({
            **msg,
            "content": content,
            "analysis": analysis,
            "ai_status": ai_status,
            "category": msg.get("category") or (analysis.get("category") if analysis else "Pending"),
            "direction": msg.get("direction", "inbound" if msg.get("source") == "webhook" else "outbound"),
            "status": msg.get("status", "Unresolved")
        })

    return {
        "status": "ok",
        "provider": provider,
        "messages": messages,
        "count": len(messages),
        "message": f"Inbox reset for {provider}. Database cleared and fresh AI categorization queued."
    }

@app.post("/connections/{provider}/reconnect")
def reconnect_provider(provider: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unsupported provider")
    delete_provider_messages(user["email"], provider)
    return {
        "status": "reconnect_initiated",
        "provider": provider,
        "message": f"Previous messages for {provider} cleared from database."
    }

@app.get("/api/messages")
def get_messages(provider: str = Query("gmail"), user: dict = Depends(current_user)) -> dict[str, Any]:
    raw = load_provider_messages(user["email"], provider)
    if provider == "gmail":
        raw = raw[:24]
    messages = []
    for msg in raw:
        content = clean_message_content(msg.get("content", ""))
        analysis = msg.get("analysis")
        ai_status = msg.get("ai_status") or ("Completed" if analysis else "Pending")
        messages.append({
            **msg,
            "content": content,
            "analysis": analysis,
            "ai_status": ai_status,
            "direction": msg.get("direction", "inbound" if msg.get("source") == "webhook" else "outbound"),
            "status": msg.get("status", "Unresolved")
        })
    return {"status": "ok", "provider": provider, "messages": messages[:24], "count": len(messages[:24])}

@app.post("/api/messages/status")
@app.patch("/api/messages/status")
def update_message_status(
    payload: MessageStatusUpdateRequest,
    user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    raw = load_provider_messages(user["email"], payload.provider)
    target_msg = None
    target_norm_status = "Resolved" if payload.resolution_status.strip().lower() == "resolved" else "Unresolved"

    for msg in raw:
        if msg.get("external_id") == payload.external_id:
            target_msg = msg
            break

    if not target_msg:
        raise HTTPException(status_code=404, detail="Message not found")

    target_msg["status"] = target_norm_status
    if "analysis" in target_msg and isinstance(target_msg["analysis"], dict):
        target_msg["analysis"]["resolution_status"] = target_norm_status
    else:
        target_msg["analysis"] = {
            "resolution_status": target_norm_status,
            "category": target_msg.get("category", "General Inquiry")
        }

    save_provider_message(user["email"], payload.provider, target_msg)

    return {
        "status": "ok",
        "external_id": payload.external_id,
        "resolution_status": target_norm_status,
        "message": target_msg
    }

@app.post("/connections/whatsapp/send")
def send_whatsapp_endpoint(payload: WhatsAppSendRequest, user: dict = Depends(current_user)) -> dict[str, Any]:
    try:
        from whatsapp_client import send_whatsapp_message
    except ImportError:
        from .whatsapp_client import send_whatsapp_message

    res = send_whatsapp_message(payload.to, payload.message)
    if not res.get("success"):
        raise HTTPException(400, res.get("error", "Failed to send WhatsApp message"))

    msg_data = {
        "sender": f"Agent ({user['email']})",
        "to": payload.to,
        "content": payload.message,
        "external_id": res.get("message_id"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "api_outbound",
        "role": "agent"
    }
    save_provider_message(user["email"], "whatsapp", msg_data)

    return {"status": "sent", "to": payload.to, "message_id": res.get("message_id"), "data": res.get("data")}

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
