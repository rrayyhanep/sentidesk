"""WhatsApp Business Cloud API integration module."""
import logging
import os
from pathlib import Path
import httpx
from dotenv import load_dotenv

logger = logging.getLogger("sentidesk.whatsapp")
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)


def get_whatsapp_config() -> dict[str, str]:
    return {
        "phone_number_id": os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip(),
        "account_id": os.getenv("WHATSAPP_BUSINESS_ACCOUNT_ID", "").strip(),
        "access_token": os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip(),
        "verify_token": os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip(),
    }


def send_whatsapp_message(to_number: str, message: str) -> dict:
    config = get_whatsapp_config()
    phone_number_id = config["phone_number_id"]
    access_token = config["access_token"]

    if not phone_number_id or not access_token:
        error_msg = (
            "WhatsApp credentials (WHATSAPP_PHONE_NUMBER_ID and WHATSAPP_ACCESS_TOKEN) "
            "are missing in environment variables."
        )
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    # Clean phone number (digits only, removing any formatting)
    clean_to = "".join(c for c in to_number if c.isdigit() or c == "+")
    if clean_to.startswith("+"):
        clean_to = clean_to[1:]

    url = f"https://graph.facebook.com/v20.0/{phone_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": clean_to,
        "type": "text",
        "text": {"body": message},
    }

    try:
        response = httpx.post(url, headers=headers, json=payload, timeout=15.0)
        data = response.json() if response.content else {}

        if response.status_code >= 400 or "error" in data:
            meta_error = data.get("error", {})
            code = meta_error.get("code")
            subcode = meta_error.get("error_subcode")
            user_msg = (
                meta_error.get("error_user_msg")
                or meta_error.get("message")
                or "WhatsApp API request failed."
            )

            if code == 190 or response.status_code == 401:
                friendly_error = (
                    "WhatsApp Access Token is invalid or expired. "
                    "Please update WHATSAPP_ACCESS_TOKEN in your .env file."
                )
            elif code == 131030 or subcode == 131030:
                friendly_error = (
                    f"Recipient number ({to_number}) is not registered in Meta's Cloud API test numbers list."
                )
            elif code == 130429 or response.status_code == 429:
                friendly_error = "WhatsApp API rate limit exceeded. Please wait before sending another message."
            else:
                friendly_error = f"WhatsApp API Error (code {code}): {user_msg}"

            logger.error(f"WhatsApp send error: {friendly_error} (raw: {meta_error})")
            return {"success": False, "error": friendly_error, "raw_error": meta_error}

        message_id = data.get("messages", [{}])[0].get("id")
        logger.info(f"WhatsApp message successfully sent to {to_number}: Message ID {message_id}")
        return {"success": True, "data": data, "message_id": message_id}

    except httpx.TimeoutException:
        error_msg = "WhatsApp API request timed out after 15 seconds."
        logger.error(error_msg)
        return {"success": False, "error": error_msg}
    except httpx.HTTPError as exc:
        error_msg = f"Network communication error connecting to Meta WhatsApp API: {exc}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}
    except Exception as exc:
        error_msg = f"Unexpected error sending WhatsApp message: {exc}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}
