"""Action item extraction and Smart AI response drafting."""
import re


def extract_action_item(text: str, intent: str, risk_level: str) -> str:
    lowered = text.lower()
    if risk_level == "high" or "phishing" in lowered or "password" in lowered and "reset" in lowered:
        return "Action Required: Verify identity & follow security protocol (Do not share secrets)"
    if intent == "billing":
        return "Action Required: Inspect invoice / payment status and process refund if requested"
    if intent == "technical_support":
        return "Action Required: Investigate error logs and provide troubleshooting steps"
    if intent == "account_access":
        return "Action Required: Verify account email and issue secure login link"
    if intent == "delivery":
        return "Action Required: Check carrier tracking status and update customer"
    if intent == "cancellation":
        return "Action Required: Review retention policy and process cancellation request"

    return "Action Required: Review inquiry and send helpful response"


def generate_suggested_reply(text: str, intent: str, entities: dict) -> str:
    order_str = entities.get("order_ids", [""])[0] if entities.get("order_ids") else ""
    order_ref = f" regarding {order_str}" if order_str else ""

    if intent == "billing":
        return f"Hello, thank you for reaching out{order_ref}. I have reviewed your billing details and am happy to assist you with your payment inquiry. Please let me know if you would like me to process a refund or send an updated receipt."
    if intent == "technical_support":
        return f"Hi there, thanks for bringing this to our attention. Our technical team is reviewing the issue. Could you please share your browser/app version so we can resolve this as quickly as possible?"
    if intent == "account_access":
        return f"Hello, I can certainly help you regain access to your account. Please click the secure password reset link sent to your registered email address, or let us know if you need further assistance."
    if intent == "delivery":
        return f"Hi! Thanks for checking in on your order status{order_ref}. I have verified with our shipping carrier, and your package is on its way. You can track live updates using your order ID."
    if intent == "cancellation":
        return f"Hello, we are sorry to hear you'd like to cancel. Your request has been received. Please let us know if there is anything we can do to improve your experience."

    return f"Hi, thank you for contacting support! We have received your message and our team is looking into it. We will get back to you shortly with an update."
