"""
One-time panel initialization.
Creates SQLite DB, random admin username/password and port, writes panel.env.
Must be run as root. Call from dnstt-deploy.sh when installing in SSH mode.
"""

import os
import secrets
import sqlite3
import hashlib
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("DNSTT_CONFIG_DIR", "/etc/dnstt"))
DB_PATH = CONFIG_DIR / "panel.db"
CONFIG_ENV_PATH = CONFIG_DIR / "panel.env"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def main():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    admin_user = "admin_" + secrets.token_hex(4)
    admin_pass = secrets.token_hex(12)
    panel_port = str(secrets.SystemRandom().randint(5000, 65000))

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tunnel_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        ("admin_username", admin_user),
    )
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        ("admin_password_hash", hash_password(admin_pass)),
    )
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        ("panel_port", panel_port),
    )
    conn.commit()
    conn.close()

    with open(CONFIG_ENV_PATH, "w") as f:
        f.write(f"PANEL_PORT={panel_port}\n")
        f.write(f"DB_PATH={DB_PATH}\n")

    os.chmod(CONFIG_ENV_PATH, 0o600)
    print(f"DNSTT_PANEL_ADMIN_USER={admin_user}")
    print(f"DNSTT_PANEL_ADMIN_PASSWORD={admin_pass}")
    print(f"DNSTT_PANEL_PORT={panel_port}")


if __name__ == "__main__":
    main()
