"""Register the SentiDesk sending domain with Resend.

Run with RESEND_API_KEY set in the environment. The command only creates the
domain; copy the returned DNS records into your DNS provider and verify the
domain in Resend before sending production mail.
"""
import os

import resend


domain = os.getenv("RESEND_DOMAIN", "rrayyhan.work.gd")
api_key = os.getenv("RESEND_API_KEY")
if not api_key:
    raise SystemExit("RESEND_API_KEY is not set")

resend.api_key = api_key
result = resend.Domains.create({"name": domain})
print(result)
