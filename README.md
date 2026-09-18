# AI-Powered Customer Support Intelligence & Phishing Threat Detection

Hackathon-ready full-stack demo with a React/Vite/Tailwind frontend and an offline FastAPI analysis service. Analysis uses transparent keyword and pattern heuristics, so it runs without model downloads or external credentials.

## Run the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The API is available at `http://localhost:8000` and interactive docs are at `/docs`.
Demo credentials: `demo@company.com` / `demo123`.

## Run the frontend

In a second terminal:

```bash
npm install
npm run dev
```

Vite serves the app at `http://localhost:5173`. The Axios client defaults to `http://localhost:8000`; set `VITE_API_URL` if the API is hosted elsewhere:

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

FastAPI enables CORS for the local Vite development origin. Accounts, conversations, provider connections, and inbox messages are persisted in `backend/sentidesk.sqlite3` (override with `SENTIDESK_DB`).

Registration always starts an email verification flow. The backend uses the official Resend Python SDK for real delivery. Configure Resend (preferred):

```bash
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxx \
RESEND_FROM="SentiDesk <onboarding@your-verified-domain.com>" \
SENTIDESK_DEMO_MODE=false JWT_SECRET=change-me
```

The `RESEND_FROM` address must use a domain or sender identity verified in Resend. The API key is read only from the server environment and is never sent to the browser.

For local development, copy `backend/.env.example` to `backend/.env`, replace the placeholder values with a newly generated Resend key and a verified sender, then restart Uvicorn. The backend loads `backend/.env` automatically.

### Registering the Resend domain

The project includes a safe helper for registering the configured domain:

```bash
cd backend
source .venv/bin/activate
RESEND_API_KEY="your-new-key" RESEND_DOMAIN="rrayyhan.work.gd" \
  python register_resend_domain.py
```

Resend will return DNS records for domain verification. Add those records at
your DNS provider, wait for propagation, and verify the domain in Resend.
Only after verification should the backend use:

```env
RESEND_FROM=SentiDesk <onboarding@rrayyhan.work.gd>
```

SMTP can be used as a fallback:

```bash
SMTP_HOST=smtp.example.com SMTP_PORT=587 SMTP_USER=... SMTP_PASSWORD=... \
SMTP_FROM=no-reply@example.com SENTIDESK_DEMO_MODE=false JWT_SECRET=change-me
```

Without Resend or SMTP (demo mode), registration returns a development verification code in the API response. It is never automatically verified; submit it with `POST /auth/verify-email` as `{ "email": "...", "code": "123456" }`. Copy [backend/.env.example](./backend/.env.example) to `.env` or export equivalent variables before starting the API.

Email verification is required to complete account verification, but it is not required to sign in. A user can sign in while their account is pending verification and complete verification later.

Provider credentials are read from environment variables (`GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `INSTAGRAM_CLIENT_ID`, `INSTAGRAM_CLIENT_SECRET`, `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_VERIFY_TOKEN`). The provider pages and inbox storage are implemented per user, and provider-specific inbox data is available at `GET/POST /connections/{provider}/inbox`. Live Gmail/Instagram/WhatsApp ingestion additionally requires each provider's OAuth/app approval, redirect URL, scopes, webhook, and production credentials; the app does not pretend that an unconfigured provider has live access.

## Main API routes

- `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`
- `POST /connections/connect`, `GET /connections`
- `POST /analyze-contract`, `POST /analyze-batch`
- `GET /dashboard-stats`, `GET /category/{category_name}`, `GET /conversation/{id}`
- Additional conversation and `/analyze/*` routes are available for the UI and API exploration.
 #sentidesk
