# ============================================================
#   DATABASE SETUP - database.py
#   Creates SQLite database with users table
# ============================================================

import sqlite3
import os

DB_PATH = "users.db"

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initialize database and create tables"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,       -- bcrypt hash stored here
            totp_secret TEXT    DEFAULT NULL,   -- 2FA secret key
            is_2fa_enabled INTEGER DEFAULT 0,   -- 0 = disabled, 1 = enabled
            created_at  TEXT    DEFAULT (datetime('now')),
            last_login  TEXT    DEFAULT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully.")