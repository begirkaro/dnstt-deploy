"""
DNSTT SSH User Management Panel
Manages system users for SSH tunnel mode (useradd / userdel / chpasswd).
Run as root. Uses SQLite for panel config and tunnel user list.
"""

import os
import re
import sqlite3
import subprocess
import secrets
import hashlib
import json
import base64
import platform
import time
from functools import wraps
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response

# Paths (overridable by env)
BASE_DIR = Path(os.environ.get("DNSTT_PANEL_BASE", "/opt/dnstt-panel"))
CONFIG_DIR = Path(os.environ.get("DNSTT_CONFIG_DIR", "/etc/dnstt"))
DB_PATH = CONFIG_DIR / "panel.db"
CONFIG_ENV_PATH = CONFIG_DIR / "panel.env"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_config(key, default=None):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_config(key, value):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value)
        )
        conn.commit()


# Default DNSTT client config (stored in panel settings; addr/ns editable in Settings)
DNSTT_PUBLIC_KEY_DEFAULT = "8c53a40bebb0ed22030f2611c38b95c0f935652e4fedfbe4b1f381b926aaee60"
DNS_ADDR_DEFAULT = "8.8.8.8:53"
DNS_NS_DEFAULT = "d.getcpcod.info"


def build_user_dns_config(username, password):
    """Build JSON config for tunnel user and return dns://<base64> URL."""
    addr = get_config("dns_addr") or DNS_ADDR_DEFAULT
    ns = get_config("dns_ns") or DNS_NS_DEFAULT
    pubkey = get_config("dnstt_public_key") or DNSTT_PUBLIC_KEY_DEFAULT
    config = {
        "ps": username,
        "addr": addr,
        "ns": ns,
        "pubkey": pubkey,
        "user": username,
        "pass": password,
    }
    json_str = json.dumps(config, indent=2, ensure_ascii=False)
    b64 = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    return "dns://" + b64


def init_db_if_needed():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
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
        conn.commit()


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("panel_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapped


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash


# ---------- System user helpers (require root) ----------
def safe_username(name):
    """Allow only alphanumeric and underscore."""
    return re.match(r"^[a-zA-Z][a-zA-Z0-9_]{2,31}$", name) is not None


def system_user_add(username, password):
    """Create system user with home dir and bash, set password."""
    if not safe_username(username):
        return False, "Username must be 3–32 chars, start with letter, only letters, numbers, underscore."
    try:
        subprocess.run(
            ["useradd", "-m", "-s", "/bin/bash", "-c", "DNSTT tunnel user", username],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        if "already exists" in (e.stderr or "").lower() or e.returncode == 9:
            return False, "User already exists."
        return False, (e.stderr or str(e)).strip() or "useradd failed."

    try:
        p = subprocess.Popen(
            ["chpasswd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _, err = p.communicate(input=f"{username}:{password}\n", timeout=5)
        if p.returncode != 0:
            subprocess.run(["userdel", "-r", username], capture_output=True)
            return False, (err or "chpasswd failed").strip()
    except Exception as e:
        subprocess.run(["userdel", "-r", username], capture_output=True)
        return False, str(e)
    return True, None


def system_user_delete(username):
    """Remove system user and home directory."""
    if not safe_username(username):
        return False, "Invalid username."
    try:
        subprocess.run(
            ["userdel", "-r", username],
            check=True,
            capture_output=True,
            text=True,
        )
        return True, None
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or str(e)).strip() or "userdel failed."


def system_user_change_password(username, password):
    if not safe_username(username):
        return False, "Invalid username."
    try:
        p = subprocess.Popen(
            ["chpasswd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _, err = p.communicate(input=f"{username}:{password}\n", timeout=5)
        if p.returncode != 0:
            return False, (err or "chpasswd failed").strip()
        return True, None
    except Exception as e:
        return False, str(e)


# ---------- Server info & usage (for dashboard) ----------
def get_server_info():
    """Return static server info (hostname, OS, CPU model, RAM total, disk total, uptime)."""
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "uptime_seconds": None,
    }
    if psutil:
        try:
            info["uptime_seconds"] = int(time.time() - psutil.boot_time())
        except Exception:
            pass
        try:
            cpu_freq = psutil.cpu_freq()
            info["cpu_mhz"] = round(cpu_freq.current) if cpu_freq else None
            info["cpu_cores"] = psutil.cpu_count(logical=False) or psutil.cpu_count() or 0
            info["cpu_logical"] = psutil.cpu_count() or 0
        except Exception:
            info["cpu_mhz"] = None
            info["cpu_cores"] = 0
            info["cpu_logical"] = 0
        try:
            mem = psutil.virtual_memory()
            info["ram_total_bytes"] = mem.total
            info["ram_total_mb"] = round(mem.total / (1024 * 1024))
        except Exception:
            info["ram_total_bytes"] = 0
            info["ram_total_mb"] = 0
        try:
            disk = psutil.disk_usage("/")
            info["disk_total_bytes"] = disk.total
            info["disk_total_gb"] = round(disk.total / (1024 ** 3), 1)
        except Exception:
            info["disk_total_bytes"] = 0
            info["disk_total_gb"] = 0
    else:
        info["cpu_mhz"] = None
        info["cpu_cores"] = 0
        info["cpu_logical"] = 0
        info["ram_total_bytes"] = 0
        info["ram_total_mb"] = 0
        info["disk_total_bytes"] = 0
        info["disk_total_gb"] = 0
    # Uptime fallback from /proc/uptime on Linux
    if info["uptime_seconds"] is None and os.path.isfile("/proc/uptime"):
        try:
            with open("/proc/uptime") as f:
                info["uptime_seconds"] = int(float(f.read().split()[0]))
        except Exception:
            pass
    return info


def get_usage():
    """Return current usage: cpu%, ram%, disk%, network bytes sent/recv."""
    data = {
        "cpu_percent": 0,
        "ram_percent": 0,
        "ram_used_mb": 0,
        "ram_total_mb": 0,
        "disk_percent": 0,
        "disk_used_gb": 0,
        "disk_total_gb": 0,
        "network_sent_bytes": 0,
        "network_recv_bytes": 0,
        "uptime_seconds": None,
    }
    if not psutil:
        return data
    try:
        data["cpu_percent"] = round(psutil.cpu_percent(interval=0.05), 1)
    except Exception:
        pass
    try:
        mem = psutil.virtual_memory()
        data["ram_percent"] = round(mem.percent, 1)
        data["ram_used_mb"] = round(mem.used / (1024 * 1024))
        data["ram_total_mb"] = round(mem.total / (1024 * 1024))
    except Exception:
        pass
    try:
        disk = psutil.disk_usage("/")
        data["disk_percent"] = round(disk.percent, 1)
        data["disk_used_gb"] = round(disk.used / (1024 ** 3), 1)
        data["disk_total_gb"] = round(disk.total / (1024 ** 3), 1)
    except Exception:
        pass
    try:
        net = psutil.net_io_counters()
        data["network_sent_bytes"] = net.bytes_sent
        data["network_recv_bytes"] = net.bytes_recv
    except Exception:
        pass
    try:
        data["uptime_seconds"] = int(time.time() - psutil.boot_time())
    except Exception:
        if os.path.isfile("/proc/uptime"):
            try:
                with open("/proc/uptime") as f:
                    data["uptime_seconds"] = int(float(f.read().split()[0]))
            except Exception:
                pass
    return data


def run_speedtest():
    """Run speedtest via current Python (venv). Package speedtest-cli exposes module 'speedtest'."""
    import sys
    # Module name is 'speedtest' (not speedtest_cli); same Python as panel so venv's package is used
    cmd = [sys.executable, "-m", "speedtest", "--json"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            cwd=str(BASE_DIR),
        )
    except subprocess.TimeoutExpired:
        return {"error": "Speedtest timed out (90s)."}
    except FileNotFoundError:
        return {"error": "speedtest-cli not installed. Run: pip install speedtest-cli (in panel venv)."}
    except Exception as e:
        return {"error": str(e)}
    if result.returncode != 0:
        return {"error": result.stderr or result.stdout or "Speedtest failed."}
    try:
        out = json.loads(result.stdout)
        # speeds in bit/s; convert to Mbps
        download_bps = float(out.get("download", 0))
        upload_bps = float(out.get("upload", 0))
        ping_ms = float(out.get("ping", 0))
        return {
            "download_mbps": round(download_bps / 1_000_000, 2),
            "upload_mbps": round(upload_bps / 1_000_000, 2),
            "ping_ms": round(ping_ms, 1),
            "server": out.get("server", {}).get("name"),
        }
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return {"error": f"Invalid output: {e}"}


# ---------- Panel version & upgrade ----------
VERSION_URL_DEFAULT = "https://raw.githubusercontent.com/begirkaro/dnstt-deploy/main/panel/VERSION"


def get_panel_version():
    """Read current panel version from VERSION file."""
    vpath = BASE_DIR / "VERSION"
    if vpath.is_file():
        return vpath.read_text().strip() or "0.0.0"
    return "0.0.0"


def _parse_version(s):
    """Convert '1.2.3' to (1, 2, 3) for comparison."""
    try:
        return tuple(int(x) for x in (s or "0").strip().split(".")[:4])
    except (ValueError, AttributeError):
        return (0, 0, 0)


def fetch_latest_version():
    """Fetch latest version from repo (best-effort)."""
    url = os.environ.get("PANEL_VERSION_URL", VERSION_URL_DEFAULT)
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "DNSTT-Panel/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip() or None
    except Exception:
        return None


def run_upgrade():
    """Run upgrade.sh in background. Returns (success, message)."""
    script = BASE_DIR / "upgrade.sh"
    if not script.is_file():
        return False, "upgrade.sh not found."
    if not os.access(script, os.X_OK):
        try:
            os.chmod(script, 0o755)
        except Exception:
            return False, "Cannot make upgrade.sh executable."
    env = {
        **os.environ,
        "DNSTT_PANEL_BASE": str(BASE_DIR),
        "DNSTT_CONFIG_DIR": str(CONFIG_DIR),
    }
    try:
        subprocess.Popen(
            ["/bin/bash", str(script)],
            cwd=str(BASE_DIR),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:
        return False, str(e)
    return True, "Upgrade started. Panel will restart in a few seconds."


# ---------- Routes ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    init_db_if_needed()
    admin_user = get_config("admin_username")
    if not admin_user:
        return "Panel not initialized. Run init_panel.py first.", 500

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        stored_hash = get_config("admin_password_hash")
        if not stored_hash:
            flash("Panel not configured.", "error")
            return redirect(url_for("login"))
        if username == admin_user and verify_password(password, stored_hash):
            session["panel_logged_in"] = True
            return redirect(url_for("overview"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("panel_logged_in", None)
    return redirect(url_for("login"))


@app.route("/")
@app.route("/overview")
@login_required
def overview():
    init_db_if_needed()
    return render_template("overview.html", active_page="overview")


@app.route("/server")
@login_required
def server():
    init_db_if_needed()
    return render_template("server.html", active_page="server")


@app.route("/usage")
@login_required
def usage():
    init_db_if_needed()
    return render_template("usage.html", active_page="usage")


@app.route("/speedtest")
@login_required
def speedtest():
    init_db_if_needed()
    return render_template("speedtest.html", active_page="speedtest")


@app.route("/users")
@login_required
def users():
    init_db_if_needed()
    new_user_dns_config = session.pop("new_user_dns_config", None)
    with get_db() as conn:
        users_list = conn.execute(
            "SELECT id, username, created_at FROM tunnel_users ORDER BY created_at DESC"
        ).fetchall()
    return render_template(
        "users.html",
        users=users_list,
        active_page="users",
        new_user_dns_config=new_user_dns_config,
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    init_db_if_needed()
    if request.method == "POST":
        dns_addr = (request.form.get("dns_addr") or "").strip() or DNS_ADDR_DEFAULT
        dns_ns = (request.form.get("dns_ns") or "").strip() or DNS_NS_DEFAULT
        pubkey = (request.form.get("dnstt_public_key") or "").strip() or DNSTT_PUBLIC_KEY_DEFAULT
        set_config("dns_addr", dns_addr)
        set_config("dns_ns", dns_ns)
        set_config("dnstt_public_key", pubkey)
        flash("Settings saved. New user configs will use these values.", "success")
        return redirect(url_for("settings"))
    dns_addr = get_config("dns_addr") or DNS_ADDR_DEFAULT
    dns_ns = get_config("dns_ns") or DNS_NS_DEFAULT
    dnstt_public_key = get_config("dnstt_public_key") or DNSTT_PUBLIC_KEY_DEFAULT
    return render_template(
        "settings.html",
        active_page="settings",
        dns_addr=dns_addr,
        dns_ns=dns_ns,
        dnstt_public_key=dnstt_public_key,
    )


@app.route("/api/server_info")
@login_required
def api_server_info():
    return jsonify(get_server_info())


@app.route("/api/usage")
@login_required
def api_usage():
    return jsonify(get_usage())


@app.route("/api/usage/stream")
@login_required
def api_usage_stream():
    """Server-Sent Events: stream usage every 5 seconds."""
    def generate():
        interval = 1  # 5 seconds between updates
        while True:
            try:
                data = get_usage()
                yield "data: " + json.dumps(data) + "\n\n"
            except GeneratorExit:
                break
            except Exception:
                pass
            time.sleep(interval)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/speedtest/run", methods=["POST"])
@login_required
def api_speedtest_run():
    return jsonify(run_speedtest())


@app.route("/api/version")
@login_required
def api_version():
    current = get_panel_version()
    latest = fetch_latest_version()
    upgrade_available = False
    if latest and _parse_version(latest) > _parse_version(current):
        upgrade_available = True
    return jsonify({
        "version": current,
        "latest_version": latest,
        "upgrade_available": upgrade_available,
    })


@app.route("/api/upgrade", methods=["POST"])
@login_required
def api_upgrade():
    ok, message = run_upgrade()
    if not ok:
        return jsonify({"ok": False, "error": message}), 400
    return jsonify({"ok": True, "message": message})


@app.route("/user/add", methods=["POST"])
@login_required
def user_add():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username:
        flash("Username is required.", "error")
        return redirect(url_for("users"))

    ok, err = system_user_add(username, password)
    if not ok:
        flash(err, "error")
        return redirect(url_for("users"))

    with get_db() as conn:
        conn.execute(
            "INSERT INTO tunnel_users (username) VALUES (?)",
            (username,),
        )
        conn.commit()

    dns_url = build_user_dns_config(username, password)
    session["new_user_dns_config"] = dns_url
    flash(f"User '{username}' created. Copy the config below for the client.", "success")
    return redirect(url_for("users"))


@app.route("/user/<username>/delete", methods=["POST"])
@login_required
def user_delete(username):
    ok, err = system_user_delete(username)
    if not ok:
        flash(err, "error")
        return redirect(url_for("users"))
    with get_db() as conn:
        conn.execute("DELETE FROM tunnel_users WHERE username = ?", (username,))
        conn.commit()
    flash(f"User '{username}' removed.", "success")
    return redirect(url_for("users"))


@app.route("/user/<username>/password", methods=["POST"])
@login_required
def user_password(username):
    password = request.form.get("password") or ""

    with get_db() as conn:
        exists = conn.execute(
            "SELECT 1 FROM tunnel_users WHERE username = ?", (username,)
        ).fetchone()
    if not exists:
        flash("User not found.", "error")
        return redirect(url_for("users"))

    ok, err = system_user_change_password(username, password)
    if not ok:
        flash(err, "error")
    else:
        flash(f"Password updated for '{username}'.", "success")
    return redirect(url_for("users"))


def main():
    init_db_if_needed()
    port = int(os.environ.get("PANEL_PORT", get_config("panel_port", "5847")))
    host = os.environ.get("PANEL_HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
