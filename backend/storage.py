"""Small SQLite persistence layer used by the API."""
from __future__ import annotations
import json
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.getenv("SENTIDESK_DB", Path(__file__).with_name("sentidesk.sqlite3")))

def connection():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          email TEXT PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL,
          email_verified INTEGER NOT NULL DEFAULT 0, verification_code TEXT,
          verification_token TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending_users (
          email TEXT PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL,
          verification_code TEXT NOT NULL, verification_token TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS conversations (
          id TEXT PRIMARY KEY, owner_email TEXT NOT NULL, payload TEXT NOT NULL,
          FOREIGN KEY(owner_email) REFERENCES users(email)
        );
        CREATE TABLE IF NOT EXISTS connections (
          owner_email TEXT NOT NULL, provider TEXT NOT NULL, payload TEXT NOT NULL,
          PRIMARY KEY(owner_email, provider), FOREIGN KEY(owner_email) REFERENCES users(email)
        );
        CREATE TABLE IF NOT EXISTS provider_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT, owner_email TEXT NOT NULL,
          provider TEXT NOT NULL, payload TEXT NOT NULL,
          FOREIGN KEY(owner_email) REFERENCES users(email)
        );
        CREATE TABLE IF NOT EXISTS analysis_cache (
          cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)

def load_users():
    with connection() as db:
        return {r["email"]: {**dict(r), "email_verified": bool(r["email_verified"])}
                for r in db.execute("SELECT * FROM users")}

def save_user(user):
    with connection() as db:
        db.execute("""INSERT OR REPLACE INTO users
          (email,username,password,email_verified,verification_code,verification_token,created_at)
          VALUES (?,?,?,?,?,?,?)""", (user["email"], user["username"], user["password"],
          int(user.get("email_verified", False)), user.get("verification_code"),
          user.get("verification_token"), user.get("created_at", "")))

def delete_user(email):
    with connection() as db:
        db.execute("DELETE FROM users WHERE email=?", (email,))

def load_pending_users():
    with connection() as db:
        return {r["email"]: dict(r) for r in db.execute("SELECT * FROM pending_users")}

def save_pending_user(user):
    with connection() as db:
        db.execute("""INSERT OR REPLACE INTO pending_users
          (email,username,password,verification_code,verification_token,created_at)
          VALUES (?,?,?,?,?,?)""", (user["email"], user["username"], user["password"],
          user["verification_code"], user["verification_token"], user["created_at"]))

def delete_pending_user(email):
    with connection() as db:
        db.execute("DELETE FROM pending_users WHERE email=?", (email,))

def load_conversations():
    with connection() as db:
        out = {}
        for r in db.execute("SELECT owner_email,id,payload FROM conversations"):
            out.setdefault(r["owner_email"], {})[r["id"]] = json.loads(r["payload"])
        return out

def save_conversation(owner, item):
    with connection() as db:
        db.execute("INSERT OR REPLACE INTO conversations(owner_email,id,payload) VALUES(?,?,?)",
                   (owner, item["id"], json.dumps(item)))

def load_connections():
    with connection() as db:
        out = {}
        for r in db.execute("SELECT owner_email,provider,payload FROM connections"):
            out.setdefault(r["owner_email"], {})[r["provider"]] = json.loads(r["payload"])
        return out

def save_connection(owner, provider, payload):
    with connection() as db:
        db.execute("INSERT OR REPLACE INTO connections VALUES(?,?,?)",
                   (owner, provider, json.dumps(payload)))

def delete_connection(owner, provider):
    with connection() as db:
        db.execute("DELETE FROM connections WHERE owner_email=? AND provider=?", (owner, provider))

def delete_provider_messages(owner, provider):
    with connection() as db:
        db.execute("DELETE FROM provider_messages WHERE owner_email=? AND provider=?", (owner, provider))


def load_provider_messages(owner, provider):
    with connection() as db:
        return [json.loads(r["payload"]) for r in db.execute(
            "SELECT payload FROM provider_messages WHERE owner_email=? AND provider=? ORDER BY id DESC",
            (owner, provider))]

def save_provider_message(owner, provider, payload):
    with connection() as db:
        external_id = payload.get("external_id")
        if external_id:
            existing_row = db.execute(
                "SELECT payload FROM provider_messages WHERE owner_email=? AND provider=? "
                "AND json_extract(payload, '$.external_id')=? LIMIT 1",
                (owner, provider, external_id),
            ).fetchone()
            if existing_row:
                try:
                    existing_payload = json.loads(existing_row["payload"])
                    if existing_payload.get("analysis") and not payload.get("analysis"):
                        payload["analysis"] = existing_payload["analysis"]
                    if existing_payload.get("category") and existing_payload["category"] != "Pending" and (not payload.get("category") or payload.get("category") == "Pending"):
                        payload["category"] = existing_payload["category"]
                    if existing_payload.get("ai_status") == "Completed" and payload.get("ai_status") in ("Pending", None):
                        payload["ai_status"] = "Completed"
                    if existing_payload.get("status") and not payload.get("status"):
                        payload["status"] = existing_payload["status"]
                except Exception:
                    pass
                db.execute(
                    "UPDATE provider_messages SET payload=? WHERE owner_email=? AND provider=? "
                    "AND json_extract(payload, '$.external_id')=?",
                    (json.dumps(payload), owner, provider, external_id),
                )
                return
        db.execute("INSERT INTO provider_messages(owner_email,provider,payload) VALUES(?,?,?)",
                   (owner, provider, json.dumps(payload)))

def get_analysis_cache(cache_key: str) -> dict | None:
    with connection() as db:
        r = db.execute("SELECT payload FROM analysis_cache WHERE cache_key=?", (cache_key,)).fetchone()
        return json.loads(r["payload"]) if r else None

def save_analysis_cache(cache_key: str, payload: dict) -> None:
    from datetime import datetime, timezone
    with connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO analysis_cache(cache_key,payload,created_at) VALUES(?,?,?)",
            (cache_key, json.dumps(payload), datetime.now(timezone.utc).isoformat())
        )
