"""LLM provider integration for support conversation analysis (Gemini & Groq) with persistent & in-memory analysis caching."""
import json
import logging
import os
import re
import time
import hashlib
from pathlib import Path
from dotenv import load_dotenv

try:
    from storage import get_analysis_cache, save_analysis_cache
except ModuleNotFoundError:
    from ..storage import get_analysis_cache, save_analysis_cache

logger = logging.getLogger("sentidesk.llm")
logging.basicConfig(level=logging.INFO)

# Ensure environment variables are loaded from .env
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# Active LLM Provider ("gemini", "groq", "openrouter", or "cerebras")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").lower()

# Model Configurations
CEREBRAS_PRIMARY_MODEL = os.getenv("CEREBRAS_MODEL", "gpt-oss-120b")
OPENROUTER_PRIMARY_MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/free")

GEMINI_PRIMARY_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_FALLBACK_MODELS = [
    GEMINI_PRIMARY_MODEL,
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.6-flash",
]

GROQ_PRIMARY_MODEL = os.getenv("GROQ_MODEL", "groq/compound-mini")
GROQ_FALLBACK_MODELS = [
    GROQ_PRIMARY_MODEL,
    "groq/compound-mini",
    "qwen/qwen3.8-27b",
    "groq/compound",
]

# Analysis Caching & Circuit Breaker State
_IN_MEMORY_CACHE: dict[str, dict] = {}
_GEMINI_CALL_COUNT = 0
_GEMINI_CIRCUIT_TRIPPED = False
_CEREBRAS_CALL_COUNT = 0
_CEREBRAS_CIRCUIT_TRIPPED = False
_OPENROUTER_CALL_COUNT = 0
_OPENROUTER_CIRCUIT_TRIPPED = False

def get_cached_analysis(text: str) -> dict | None:
    if not text:
        return None
    cache_key = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
    if cache_key in _IN_MEMORY_CACHE:
        return _IN_MEMORY_CACHE[cache_key]
    try:
        db_cached = get_analysis_cache(cache_key)
        if db_cached:
            _IN_MEMORY_CACHE[cache_key] = db_cached
            return db_cached
    except Exception as exc:
        logger.warning(f"Failed reading analysis cache from SQLite: {exc}")
    return None

def store_analysis_cache(text: str, result: dict) -> None:
    if not text or not result:
        return
    cache_key = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
    _IN_MEMORY_CACHE[cache_key] = result
    try:
        save_analysis_cache(cache_key, result)
    except Exception as exc:
        logger.warning(f"Could not persist analysis to SQLite cache: {exc}")

FALLBACK_ANALYSIS = {
    "category": "Other",
    "sentiment": "Neutral",
    "emotion": "None",
    "priority": "Medium",
    "resolution_status": "Unresolved",
    "summary": "Customer support conversation received.",
    "social_engineering_techniques": [],
    "recommended_action": "Review customer inquiry and respond.",
    "_is_fallback": True,
}

PROMPT_TEMPLATE = """Analyze the following customer support conversation and return ONLY a valid JSON object (no markdown, no code fences, no explanation) with these exact fields:
- category: one of [Payment/Transaction Issue, Account/Login Problem, Product Issue, Delivery/Shipping Problem, Refund Request, Subscription Issue, Technical Problem, Service Quality, Billing Problem, Security Concern, Other]
- sentiment: one of [Positive, Neutral, Negative]
- emotion: one of [Anger, Frustration, Satisfaction, Confusion, Urgency, Disappointment, None]
- priority: one of [Low, Medium, High, Critical]
- resolution_status: one of [Resolved, Unresolved]
- summary: a 1-3 sentence summary of the issue, what the customer wants, and current status
- social_engineering_techniques: array from [Urgency/Fear, Authority Impersonation, Credential Request, Threat/Intimidation, Too-Good-To-Be-True Offer, Suspicious Link Prompt], empty array if none detected
- recommended_action: one short actionable sentence

CLASSIFICATION RULE:
Only use category 'Other' if the email does not fit any more specific category listed AND contains no complaint, request, or security concern. Any email containing a suspicious URL, credential/password/OTP request, urgency + link combination, or impersonation attempt MUST be classified as 'Security Concern', never 'Other', regardless of confidence.

FEW-SHOT EXAMPLES:

Example 1 (Phishing / Security Threat):
Conversation: "URGENT: Your PayPal account has been suspended due to suspicious activity. Click http://paypaI-verify.xyz/login immediately to verify your identity or your account will be deleted within 24 hours."
Output:
{{
  "category": "Security Concern",
  "sentiment": "Negative",
  "emotion": "Urgency",
  "priority": "Critical",
  "resolution_status": "Unresolved",
  "summary": "Received an urgent phishing attempt impersonating PayPal asking the user to log in at a lookalike URL.",
  "social_engineering_techniques": ["Urgency/Fear", "Authority Impersonation", "Credential Request", "Suspicious Link Prompt"],
  "recommended_action": "Do not click link or share credentials; flag as phishing threat immediately."
}}

Example 2 (Billing Problem):
Conversation: "I was charged twice $49.99 for my monthly subscription on my credit card statement this morning. Please refund the extra charge."
Output:
{{
  "category": "Billing Problem",
  "sentiment": "Negative",
  "emotion": "Frustration",
  "priority": "High",
  "resolution_status": "Unresolved",
  "summary": "Customer reported duplicate $49.99 charge on their subscription and requested a refund.",
  "social_engineering_techniques": [],
  "recommended_action": "Verify transaction logs and issue a refund for the duplicate charge."
}}

Example 3 (Delivery/Shipping Problem):
Conversation: "Hi, package tracking number #TRK9921 shows delivered but I haven't received it at my address. Can you please check with the carrier?"
Output:
{{
  "category": "Delivery/Shipping Problem",
  "sentiment": "Negative",
  "emotion": "Confusion",
  "priority": "Medium",
  "resolution_status": "Unresolved",
  "summary": "Customer has not received package despite tracking status showing delivered.",
  "social_engineering_techniques": [],
  "recommended_action": "Contact carrier to locate package and update the customer."
}}

Example 4 (Social Engineering / Credential Harvesting):
Conversation: "Dear customer, this is IT support. We noticed suspicious logins on your corporate email. Reply immediately with your current password and OTP code to prevent lock out."
Output:
{{
  "category": "Security Concern",
  "sentiment": "Negative",
  "emotion": "Urgency",
  "priority": "Critical",
  "resolution_status": "Unresolved",
  "summary": "Social engineering attack requesting user password and OTP under pretense of IT support.",
  "social_engineering_techniques": ["Authority Impersonation", "Credential Request", "Urgency/Fear"],
  "recommended_action": "Block sender, warn staff, and do not share credentials or OTP."
}}

Example 5 (Generic / No Issue -> Other):
Conversation: "Just wanted to say thanks for the great service, have a nice weekend!"
Output:
{{
  "category": "Other",
  "sentiment": "Positive",
  "emotion": "Satisfaction",
  "priority": "Low",
  "resolution_status": "Resolved",
  "summary": "Customer sent a friendly thank-you note with no active issues.",
  "social_engineering_techniques": [],
  "recommended_action": "No further action required."
}}

Now analyze this conversation:
Conversation:
{conversation_text}"""


def _parse_json_safely(raw_text: str) -> dict | None:
    if not raw_text:
        return None
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and start < end:
            substring = cleaned[start : end + 1]
            try:
                return json.loads(substring)
            except json.JSONDecodeError:
                pass
    return None


def extract_retry_seconds(err: Exception) -> float | None:
    """Extract exact retry_delay from Gemini 429 error response if present."""
    err_str = str(err)
    m = re.search(r"retry\s+in\s+([\d\.]+)\s*s", err_str, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    m2 = re.search(r"(?:retry_delay\s*\{\s*)?seconds:\s*(\d+)", err_str)
    if m2:
        try:
            return float(m2.group(1))
        except ValueError:
            pass
    return None


def analyze_with_gemini(conversation_text: str) -> dict:
    global _GEMINI_CALL_COUNT, _GEMINI_CIRCUIT_TRIPPED

    # 1. Check persistent/in-memory cache first
    cached = get_cached_analysis(conversation_text)
    if cached:
        logger.info(f"[LLM CACHE HIT] Using cached analysis for text snippet: {conversation_text[:60]!r}")
        return dict(cached)

    # 2. Check circuit breaker safety net
    if _GEMINI_CIRCUIT_TRIPPED:
        logger.warning("[LLM CIRCUIT BREAKER] Gemini API circuit breaker TRIPPED due to previous 429 error. Returning safe fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.warning("GEMINI_API_KEY not found in environment; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    try:
        import google.generativeai as genai
    except ImportError:
        logger.error("google-generativeai package not installed; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    genai.configure(api_key=api_key)

    generation_config = {
        "temperature": 0.15,
        "response_mime_type": "application/json",
    }

    prompt = PROMPT_TEMPLATE.format(conversation_text=conversation_text)

    seen_models = set()
    models_to_try = []
    for m in GEMINI_FALLBACK_MODELS:
        if m not in seen_models:
            seen_models.add(m)
            models_to_try.append(m)

    for model_name in models_to_try:
        try:
            _GEMINI_CALL_COUNT += 1
            logger.info(f"[LLM API CALL #{_GEMINI_CALL_COUNT}] Calling Gemini API (model={model_name!r}) for new message snippet: {conversation_text[:60]!r}")

            model = genai.GenerativeModel(
                model_name=model_name,
                generation_config=generation_config
            )
            response = model.generate_content(prompt)
            content = getattr(response, "text", "") or ""
            parsed = _parse_json_safely(content)
            
            if parsed:
                category = parsed.get("category", "Other")
                confidence = 0.95 if category != "Other" else 0.60
                
                if category == "Other" or confidence < 0.8:
                    logger.warning(
                        f"[Gemini Classification Review] Low confidence or 'Other' category assigned (confidence={confidence}) for text snippet: {conversation_text[:100]!r}"
                    )
                
                result = {
                    "category": category,
                    "sentiment": parsed.get("sentiment", "Neutral"),
                    "emotion": parsed.get("emotion", "None"),
                    "priority": parsed.get("priority", "Medium"),
                    "resolution_status": parsed.get("resolution_status", "Unresolved"),
                    "summary": parsed.get("summary", "Customer support conversation analyzed."),
                    "social_engineering_techniques": parsed.get("social_engineering_techniques", []),
                    "recommended_action": parsed.get("recommended_action", "Review inquiry and send response."),
                    "confidence": confidence,
                }

                # Store result in persistent cache
                store_analysis_cache(conversation_text, result)
                return result
            else:
                logger.warning(f"Failed to parse JSON from Gemini response using model {model_name!r}: {content[:200]!r}.")
        except Exception as exc:
            err_msg = str(exc).lower()
            status_code = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
            is_404 = "404" in err_msg or "not found" in err_msg or "no longer available" in err_msg
            is_rate_limit = status_code == 429 or "429" in err_msg or "rate limit" in err_msg or "quota" in err_msg or "resourceexhausted" in err_msg
            
            if is_404:
                logger.info(f"Gemini model {model_name!r} not found or deprecated, trying next fallback model...")
                continue
            elif is_rate_limit:
                retry_seconds = extract_retry_seconds(exc)
                if retry_seconds and 0 < retry_seconds <= 3.0:
                    wait_time = retry_seconds + 0.5
                    logger.info(f"[429 EXACT RETRY DELAY] Gemini instructed to retry in {retry_seconds:.2f}s. Sleeping {wait_time:.2f}s before retry attempt...")
                    time.sleep(wait_time)
                    try:
                        _GEMINI_CALL_COUNT += 1
                        logger.info(f"[LLM API CALL #{_GEMINI_CALL_COUNT} RETRY] Retrying Gemini API call for model={model_name!r}")
                        response = model.generate_content(prompt)
                        content = getattr(response, "text", "") or ""
                        parsed = _parse_json_safely(content)
                        if parsed:
                            category = parsed.get("category", "Other")
                            confidence = 0.95 if category != "Other" else 0.60
                            result = {
                                "category": category,
                                "sentiment": parsed.get("sentiment", "Neutral"),
                                "emotion": parsed.get("emotion", "None"),
                                "priority": parsed.get("priority", "Medium"),
                                "resolution_status": parsed.get("resolution_status", "Unresolved"),
                                "summary": parsed.get("summary", "Customer support conversation analyzed."),
                                "social_engineering_techniques": parsed.get("social_engineering_techniques", []),
                                "recommended_action": parsed.get("recommended_action", "Review inquiry and send response."),
                                "confidence": confidence,
                            }
                            store_analysis_cache(conversation_text, result)
                            return result
                    except Exception as retry_exc:
                        logger.error(f"[LLM 429 RETRY FAILED] Retry attempt also failed: {retry_exc}")
                logger.warning(f"Gemini model {model_name!r} rate limited/quota reached: {exc}. Trying next fallback model...")
                continue
            elif "invalid api key" in err_msg or "api_key_invalid" in err_msg or "permissiondenied" in err_msg or "unauthenticated" in err_msg:
                logger.error(f"Gemini API Key is invalid or unauthorized: {exc}")
                return dict(FALLBACK_ANALYSIS)
            else:
                logger.error(f"Gemini API error ({type(exc).__name__}) with model {model_name!r}: {exc}")

    logger.warning("All Gemini models failed or unavailable; returning fallback analysis.")
    return dict(FALLBACK_ANALYSIS)


def analyze_with_groq(conversation_text: str) -> dict:
    cached = get_cached_analysis(conversation_text)
    if cached:
        logger.info(f"[LLM CACHE HIT] Using cached Groq analysis for text snippet: {conversation_text[:60]!r}")
        return dict(cached)

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        logger.warning("GROQ_API_KEY not found in environment; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    try:
        from groq import Groq, NotFoundError
    except ImportError:
        logger.error("groq package not installed; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    client = Groq(api_key=api_key)
    prompt = PROMPT_TEMPLATE.format(conversation_text=conversation_text)
    messages = [{"role": "user", "content": prompt}]

    seen_models = set()
    models_to_try = []
    for m in GROQ_FALLBACK_MODELS:
        if m not in seen_models:
            seen_models.add(m)
            models_to_try.append(m)

    for model in models_to_try:
        max_retries = 1
        for attempt in range(max_retries + 1):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=0.15,
                    max_tokens=1000,
                )
                content = response.choices[0].message.content or ""
                parsed = _parse_json_safely(content)
                if parsed:
                    category = parsed.get("category", "Other")
                    confidence = 0.95 if category != "Other" else 0.60
                    
                    if category == "Other" or confidence < 0.8:
                        logger.warning(
                            f"[Classification Review] Low confidence or 'Other' category assigned (confidence={confidence}) for text snippet: {conversation_text[:100]!r}"
                        )
                    
                    result = {
                        "category": category,
                        "sentiment": parsed.get("sentiment", "Neutral"),
                        "emotion": parsed.get("emotion", "None"),
                        "priority": parsed.get("priority", "Medium"),
                        "resolution_status": parsed.get("resolution_status", "Unresolved"),
                        "summary": parsed.get("summary", "Customer support conversation analyzed."),
                        "social_engineering_techniques": parsed.get("social_engineering_techniques", []),
                        "recommended_action": parsed.get("recommended_action", "Review inquiry and send response."),
                        "confidence": confidence,
                    }
                    store_analysis_cache(conversation_text, result)
                    return result
            except NotFoundError:
                logger.info(f"Model {model!r} not available on Groq account, trying next fallback model...")
                break
            except Exception as exc:
                err_msg = str(exc).lower()
                status_code = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
                if status_code == 429 or "429" in err_msg or "rate limit" in err_msg or "too many requests" in err_msg or "rate_limit_exceeded" in err_msg:
                    logger.warning(f"Groq API 429 Rate Limit error with model {model!r}: {exc}. Trying next fallback model...")
                    break
                if attempt < max_retries:
                    logger.warning(f"Groq API error with model {model!r}: {exc}. Retrying...")
                    time.sleep(1.0)
                    continue
                else:
                    logger.warning(f"Failed analysis with model {model!r}: {exc}")

    logger.warning("All Groq models failed or unavailable; returning fallback analysis.")
    return dict(FALLBACK_ANALYSIS)


def analyze_with_cerebras(conversation_text: str) -> dict:
    global _CEREBRAS_CALL_COUNT, _CEREBRAS_CIRCUIT_TRIPPED

    # 1. Check persistent/in-memory cache first
    cached = get_cached_analysis(conversation_text)
    if cached:
        logger.info(f"[LLM CACHE HIT] Using cached Cerebras analysis for text snippet: {conversation_text[:60]!r}")
        return dict(cached)

    # 2. Check circuit breaker safety net
    if _CEREBRAS_CIRCUIT_TRIPPED:
        logger.warning("[LLM CIRCUIT BREAKER] Cerebras API circuit breaker TRIPPED due to previous 429 error. Returning safe fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    api_key = os.getenv("CEREBRAS_API_KEY")
    if not api_key:
        logger.warning("CEREBRAS_API_KEY not found in environment; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    try:
        from cerebras.cloud.sdk import Cerebras
    except ImportError:
        logger.error("cerebras-cloud-sdk package not installed; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    client = Cerebras(api_key=api_key)
    prompt = PROMPT_TEMPLATE.format(conversation_text=conversation_text)
    messages = [{"role": "user", "content": prompt}]
    model_name = CEREBRAS_PRIMARY_MODEL

    try:
        _CEREBRAS_CALL_COUNT += 1
        logger.info(f"[LLM API CALL #{_CEREBRAS_CALL_COUNT}] Calling Cerebras API (model={model_name!r}) for text snippet: {conversation_text[:60]!r}")

        response = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.15,
            response_format={"type": "json_object"}
        )

        content = ""
        if response and response.choices:
            content = response.choices[0].message.content or ""
        
        parsed = _parse_json_safely(content)
        if parsed:
            category = parsed.get("category", "Other")
            confidence = 0.95 if category != "Other" else 0.60

            if category == "Other" or confidence < 0.8:
                logger.warning(
                    f"[Cerebras Classification Review] Low confidence or 'Other' category assigned (confidence={confidence}) for text snippet: {conversation_text[:100]!r}"
                )

            result = {
                "category": category,
                "sentiment": parsed.get("sentiment", "Neutral"),
                "emotion": parsed.get("emotion", "None"),
                "priority": parsed.get("priority", "Medium"),
                "resolution_status": parsed.get("resolution_status", "Unresolved"),
                "summary": parsed.get("summary", "Customer support conversation analyzed."),
                "social_engineering_techniques": parsed.get("social_engineering_techniques", []),
                "recommended_action": parsed.get("recommended_action", "Review inquiry and send response."),
                "confidence": confidence,
            }

            # Store in persistent cache
            store_analysis_cache(conversation_text, result)
            return result
        else:
            logger.warning(f"Failed to parse JSON from Cerebras response using model {model_name!r}: {content[:200]!r}.")
    except Exception as exc:
        err_msg = str(exc).lower()
        status_code = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
        is_rate_limit = status_code == 429 or "429" in err_msg or "rate limit" in err_msg or "quota" in err_msg or "resourceexhausted" in err_msg

        if is_rate_limit:
            _CEREBRAS_CIRCUIT_TRIPPED = True
            logger.error(f"[LLM 429 RATE LIMIT] Cerebras API 429 Rate Limit error with model {model_name!r}: {exc}. Tripping circuit breaker for session.")
            return dict(FALLBACK_ANALYSIS)
        elif "invalid api key" in err_msg or "api_key_invalid" in err_msg or "permissiondenied" in err_msg or "unauthenticated" in err_msg or "401" in err_msg:
            logger.error(f"Cerebras API Key is invalid or unauthorized: {exc}")
            return dict(FALLBACK_ANALYSIS)
        else:
            logger.error(f"Cerebras API error ({type(exc).__name__}) with model {model_name!r}: {exc}")

    logger.warning("Cerebras analysis failed or unparsed; returning fallback analysis.")
    return dict(FALLBACK_ANALYSIS)


def analyze_with_openrouter(conversation_text: str) -> dict:
    global _OPENROUTER_CALL_COUNT, _OPENROUTER_CIRCUIT_TRIPPED

    # 1. Check persistent/in-memory cache first
    cached = get_cached_analysis(conversation_text)
    if cached:
        logger.info(f"[LLM CACHE HIT] Using cached OpenRouter analysis for text snippet: {conversation_text[:60]!r}")
        return dict(cached)

    # 2. Check circuit breaker safety net
    if _OPENROUTER_CIRCUIT_TRIPPED:
        logger.warning("[LLM CIRCUIT BREAKER] OpenRouter API circuit breaker TRIPPED due to previous 429 error. Returning safe fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    api_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
    if not api_key:
        logger.warning("OPENROUTER_API_KEY not found in environment; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    try:
        from openai import OpenAI
    except ImportError:
        logger.error("openai package not installed; returning fallback analysis.")
        return dict(FALLBACK_ANALYSIS)

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    prompt = PROMPT_TEMPLATE.format(conversation_text=conversation_text)
    messages = [{"role": "user", "content": prompt}]
    model_name = OPENROUTER_PRIMARY_MODEL

    try:
        _OPENROUTER_CALL_COUNT += 1
        logger.info(f"[LLM API CALL #{_OPENROUTER_CALL_COUNT}] Calling OpenRouter API (model={model_name!r}) for text snippet: {conversation_text[:60]!r}")

        response = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.15,
            response_format={"type": "json_object"}
        )

        content = ""
        if response and response.choices:
            content = response.choices[0].message.content or ""
        
        parsed = _parse_json_safely(content)
        if parsed:
            category = parsed.get("category", "Other")
            confidence = 0.95 if category != "Other" else 0.60

            if category == "Other" or confidence < 0.8:
                logger.warning(
                    f"[OpenRouter Classification Review] Low confidence or 'Other' category assigned (confidence={confidence}) for text snippet: {conversation_text[:100]!r}"
                )

            result = {
                "category": category,
                "sentiment": parsed.get("sentiment", "Neutral"),
                "emotion": parsed.get("emotion", "None"),
                "priority": parsed.get("priority", "Medium"),
                "resolution_status": parsed.get("resolution_status", "Unresolved"),
                "summary": parsed.get("summary", "Customer support conversation analyzed."),
                "social_engineering_techniques": parsed.get("social_engineering_techniques", []),
                "recommended_action": parsed.get("recommended_action", "Review inquiry and send response."),
                "confidence": confidence,
            }

            # Store in persistent cache
            store_analysis_cache(conversation_text, result)
            return result
        else:
            logger.warning(f"Failed to parse JSON from OpenRouter response using model {model_name!r}: {content[:200]!r}.")
    except Exception as exc:
        err_msg = str(exc).lower()
        status_code = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
        is_rate_limit = status_code == 429 or "429" in err_msg or "rate limit" in err_msg or "quota" in err_msg or "resourceexhausted" in err_msg

        if is_rate_limit:
            _OPENROUTER_CIRCUIT_TRIPPED = True
            logger.error(f"[LLM 429 RATE LIMIT] OpenRouter API 429 Rate Limit error with model {model_name!r}: {exc}. Tripping circuit breaker for session.")
            return dict(FALLBACK_ANALYSIS)
        elif "invalid api key" in err_msg or "api_key_invalid" in err_msg or "permissiondenied" in err_msg or "unauthenticated" in err_msg or "401" in err_msg:
            logger.error(f"OpenRouter API Key is invalid or unauthorized: {exc}")
            return dict(FALLBACK_ANALYSIS)
        else:
            logger.error(f"OpenRouter API error ({type(exc).__name__}) with model {model_name!r}: {exc}")

    logger.warning("OpenRouter analysis failed or unparsed; returning fallback analysis.")
    return dict(FALLBACK_ANALYSIS)


def analyze_with_llm(conversation_text: str) -> dict:
    cached = get_cached_analysis(conversation_text)
    if cached:
        logger.info(f"[LLM CACHE HIT] Using cached analysis for text snippet: {conversation_text[:60]!r}")
        return dict(cached)

    primary_provider = os.getenv("LLM_PROVIDER", "gemini").lower()

    # Priority order of providers to try (primary provider first, then fallbacks)
    all_providers = ["gemini", "groq", "cerebras", "openrouter"]
    providers_to_try = [primary_provider] + [p for p in all_providers if p != primary_provider]

    provider_funcs = {
        "gemini": analyze_with_gemini,
        "groq": analyze_with_groq,
        "cerebras": analyze_with_cerebras,
        "openrouter": analyze_with_openrouter,
    }

    for provider in providers_to_try:
        func = provider_funcs.get(provider)
        if not func:
            continue
        try:
            res = func(conversation_text)
            if res and not res.get("_is_fallback", False):
                return res
        except Exception as exc:
            logger.warning(f"LLM Provider {provider!r} failed with error: {exc}. Failover to next provider...")
            continue

    logger.warning("All LLM providers failed or returned fallbacks; returning safe default analysis.")
    return dict(FALLBACK_ANALYSIS)
