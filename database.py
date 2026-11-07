import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().with_name("password_history.db")
PBKDF2_ITERATIONS = 300_000

def _connect():
    return sqlite3.connect(DB_PATH)

def initialize_database():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL DEFAULT 'Saved password',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)

def save_password_hash(password: str, label: str = "Saved password") -> None:
    initialize_database()
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO password_history (label, salt, password_hash) VALUES (?, ?, ?)",
            (label.strip() or "Saved password", salt, digest)
        )

def was_password_used(password: str) -> bool:
    initialize_database()
    candidate = password.encode("utf-8")
    with _connect() as conn:
        rows = conn.execute("SELECT salt, password_hash FROM password_history").fetchall()
    for salt, stored_hash in rows:
        candidate_hash = hashlib.pbkdf2_hmac("sha256", candidate, salt, PBKDF2_ITERATIONS)
        if hmac.compare_digest(candidate_hash, stored_hash):
            return True
    return False

def get_history():
    initialize_database()
    with _connect() as conn:
        return conn.execute(
            "SELECT id, label, created_at FROM password_history ORDER BY id DESC"
        ).fetchall()

def delete_history():
    initialize_database()
    with _connect() as conn:
        conn.execute("DELETE FROM password_history")
        # Reset the SQLite autoincrement counter where present.
        conn.execute("DELETE FROM sqlite_sequence WHERE name='password_history'")
