import os
import io
import csv
import json
import zipfile
import re
import base64
import secrets
import pyotp
import qrcode
import magic
from datetime import datetime
from functools import wraps

from urllib.parse import urlparse, urljoin

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    make_response,
    session,
    jsonify,
)
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from celery import Celery

from forensis.models import db, User, Group, AnalysisHistory
from forensis.analyzers.log_analyzer import analyze_logs
from forensis.analyzers.network_analyzer import analyze_pcap
from forensis.analyzers.playbook_engine import get_playbook, analyze_generic_output
from forensis.analyzers.sigma_engine import SigmaEngine
from forensis.integrations.elk_loki import ship_events

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB_PATH = os.path.join(BASE_DIR, "instance", "forensis.db")

ALLOWED_LOG_EXT = {"log", "txt", "csv", "json"}
ALLOWED_PCAP_EXT = {"pcap", "pcapng"}
ALLOWED_MEMORY_EXT = {"txt", "log", "json", "jsonl", "ndjson", "csv", "tsv", "xml", "yaml", "yml", "zip", "vmem", "mem"}
VALID_USER_ROLES = {"admin", "analyst"}
MEMORY_ARCHIVE_MAX_BYTES = 50 * 1024 * 1024
MEMORY_FILE_MAX_BYTES = 8 * 1024 * 1024
MEMORY_TEXT_MAX_BYTES = 50 * 1024 * 1024
MEMORY_IMAGE_MAX_BYTES = 256 * 1024 * 1024
MEMORY_IMAGE_SCAN_BYTES = 64 * 1024 * 1024
MEMORY_STRINGS_MIN_LEN = 6
MEMORY_STRINGS_MAX_LINES = 20000

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FORENSIS_SECRET_KEY", "change-me-in-production")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('FORENSIS_DB_URI', f'sqlite:///{DB_PATH}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    return celery

celery = make_celery(app)

@app.context_processor
def inject_now():
    return {
        "now_year": datetime.utcnow().year,
        "csrf_token": _get_csrf_token(),
    }

@app.after_request
def set_secure_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; font-src 'self' cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

LAST_RESULTS = {
    "logs": None,
    "network": None,
    "memory": None,
}

sigma_engine = SigmaEngine(os.path.join(BASE_DIR, "sigma_rules"))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def allowed_file(filename, allowed_ext):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_ext

def _get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

def _is_valid_csrf_token(token: str) -> bool:
    current = session.get("_csrf_token")
    if not token or not current:
        return False
    return secrets.compare_digest(token, current)

def _require_csrf() -> bool:
    token = request.form.get("csrf_token", "")
    if _is_valid_csrf_token(token):
        return True
    flash("Invalid form token. Please retry.", "danger")
    return False

def _build_upload_path(original_name: str):
    clean_name = secure_filename(original_name)
    if not clean_name:
        clean_name = "artifact.bin"
    unique_name = f"{secrets.token_hex(8)}_{clean_name}"
    return clean_name, os.path.join(app.config["UPLOAD_FOLDER"], unique_name), unique_name

def _safe_unlink(path: str):
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass

def is_safe_content(path: str, category: str) -> bool:
    try:
        mime = magic.from_file(path, mime=True)
        if category == "log":
            return mime.startswith("text/") or mime in {"application/json", "application/csv", "text/csv"}
        elif category == "pcap":
            return mime in {"application/vnd.tcpdump.pcap", "application/x-pcapng", "application/octet-stream"}
        elif category == "memory_output":
            allowed = {
                "application/json",
                "application/csv",
                "text/csv",
                "application/xml",
                "text/xml",
                "application/x-yaml",
                "text/yaml",
                "application/zip",
                "application/x-zip-compressed",
                "application/octet-stream",
            }
            return mime.startswith("text/") or mime in allowed
    except Exception:
        return False
    return False

def _helper_cheatsheets():
    return {
        "Memory Forensics": [
            {"cmd": "vol -f MEM.raw windows.pslist", "desc": "List active processes"},
            {"cmd": "vol -f MEM.raw windows.netscan", "desc": "Inspect network sockets"},
            {"cmd": "vol -f MEM.raw windows.malfind", "desc": "Find injected code regions"},
            {"cmd": "vol -f MEM.raw windows.cmdline", "desc": "Review suspicious command lines"},
            {"cmd": "vol -f MEM.raw windows.filescan", "desc": "Enumerate file object artifacts"},
        ],
        "Linux Forensics": [
            {"cmd": "last -f /var/log/wtmp", "desc": "Show login history"},
            {"cmd": "find / -mmin -60", "desc": "Find files changed in last 60 mins"},
            {"cmd": "ss -tulpn", "desc": "List listening sockets and owning process"},
        ],
        "Windows Forensics": [
            {"cmd": "wevtutil qe Security /f:text", "desc": "Query Security Event Logs"},
            {"cmd": "Get-WinEvent -LogName Security -MaxEvents 50", "desc": "Read latest security events"},
            {"cmd": "net sessions", "desc": "List active SMB sessions"},
        ],
        "Network Analysis": [
            {"cmd": "tcpdump -nn -c 100", "desc": "Capture first 100 packets"},
            {"cmd": "tshark -z io,phs -r capture.pcap", "desc": "Protocol hierarchy summary"},
            {"cmd": "zeek -r capture.pcap", "desc": "Generate Zeek artifacts for triage"},
        ],
    }

def _extract_printable_strings(blob: bytes, min_len: int = MEMORY_STRINGS_MIN_LEN):
    ascii_pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_pat = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    strings = []
    seen = set()

    for match in ascii_pat.finditer(blob):
        text = match.group().decode("ascii", errors="ignore").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        strings.append(text)
        if len(strings) >= MEMORY_STRINGS_MAX_LINES:
            return strings

    for match in utf16_pat.finditer(blob):
        raw = match.group()
        text = raw.decode("utf-16le", errors="ignore").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        strings.append(text)
        if len(strings) >= MEMORY_STRINGS_MAX_LINES:
            return strings

    return strings


def _read_memory_image_strings(path: str) -> str:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read(MEMORY_IMAGE_SCAN_BYTES)
    lines = _extract_printable_strings(data)
    if not lines:
        return ""
    header = f"# memory_image_scan_bytes={len(data)} of total_bytes={size}\n"
    return header + "\n".join(lines)


def _read_memory_input(path: str, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in {"vmem", "mem"}:
        return _read_memory_image_strings(path)

    if ext != "zip":
        with open(path, "r", errors="ignore") as f:
            return f.read()

    chunks = []
    allowed_inner_ext = {"txt", "log", "json", "jsonl", "ndjson", "csv", "tsv", "xml", "yaml", "yml", "vmem", "mem"}
    with zipfile.ZipFile(path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            inner_name = info.filename
            inner_ext = inner_name.rsplit(".", 1)[-1].lower() if "." in inner_name else ""
            max_allowed = MEMORY_IMAGE_MAX_BYTES if inner_ext in {"vmem", "mem"} else MEMORY_FILE_MAX_BYTES
            if info.file_size > max_allowed:
                continue
            if inner_ext not in allowed_inner_ext:
                continue
            data = zf.read(info)

            if inner_ext in {"vmem", "mem"}:
                text = "\n".join(_extract_printable_strings(data[:MEMORY_IMAGE_SCAN_BYTES])).strip()
            else:
                text = data.decode("utf-8", errors="ignore").strip()

            if not text:
                continue
            chunks.append(f"# file: {inner_name}\n{text}")
            if len(chunks) >= 30:
                break
    return "\n\n".join(chunks)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Access denied: Admins only.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def _is_safe_redirect_url(target):
    if not target: return False
    host_url = urlparse(request.host_url)
    ref_url = urlparse(urljoin(request.host_url, target))
    return ref_url.scheme in ("http", "https") and host_url.netloc == ref_url.netloc

def _safe_redirect(target, fallback="dashboard"):
    if target and _is_safe_redirect_url(target):
        return redirect(target)
    return redirect(url_for(fallback))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        otp = request.form.get("otp", "").strip()
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if user.mfa_enabled:
                if not otp:
                     return render_template("login.html", otp_required=True, username=username, password=password)
                else:
                    totp = pyotp.TOTP(user.mfa_secret)
                    if not totp.verify(otp):
                        flash("Invalid authentication code.", "danger")
                        return render_template("login.html", otp_required=True, username=username, password=password)
            login_user(user)
            flash("Logged in successfully.", "success")
            return _safe_redirect(request.args.get("next"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html", otp_required=False)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/setup_mfa", methods=["GET", "POST"])
@login_required
def setup_mfa():
    if current_user.mfa_enabled:
        flash("MFA is already enabled.", "info")
        return redirect(url_for("manage_users"))

    if request.method == "POST":
        secret = request.form.get("secret")
        otp = request.form.get("otp")
        qr_code = request.form.get("qr_code_hidden")

        totp = pyotp.TOTP(secret)
        if totp.verify(otp):
            current_user.mfa_secret = secret
            current_user.mfa_enabled = True
            db.session.commit()
            flash("MFA enabled successfully.", "success")
            return redirect(url_for("manage_users"))

        flash("Invalid verification code. Please try again.", "danger")
        return render_template("setup_mfa.html", secret=secret, qr_code=qr_code)

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="Forensis")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return render_template("setup_mfa.html", secret=secret, qr_code=qr_b64)

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    logs_count = AnalysisHistory.query.filter_by(type="logs").count()
    network_count = AnalysisHistory.query.filter_by(type="network").count()
    memory_count = AnalysisHistory.query.filter(AnalysisHistory.type.like("memory%")).count()
    latest_log = AnalysisHistory.query.filter_by(type="logs").order_by(AnalysisHistory.timestamp.desc()).first()
    latest_net = AnalysisHistory.query.filter_by(type="network").order_by(AnalysisHistory.timestamp.desc()).first()
    log_data = latest_log.get_results() if latest_log else {}
    net_data = latest_net.get_results() if latest_net else {}
    dashboard_data = {
        "logs": {
            "total": log_data.get("summary", {}).get("parsed_events", 0),
            "anomalies": log_data.get("summary", {}).get("anomaly_count", 0),
            "top_sources": log_data.get("summary", {}).get("top_sources", []),
            "top_status": log_data.get("summary", {}).get("top_status", []),
        },
        "network": {
            "flows": net_data.get("summary", {}).get("flow_count", 0),
            "anomalies": net_data.get("summary", {}).get("anomaly_count", 0),
        },
        "memory": {"suspicious": memory_count},
        "counts": {"logs": logs_count, "network": network_count, "memory": memory_count},
        "recent_alerts": []
    }
    recent_analyses = AnalysisHistory.query.order_by(AnalysisHistory.timestamp.desc()).limit(10).all()
    alerts = []
    for a in recent_analyses:
        res = a.get_results()
        if res and res.get("anomalies"):
             for anomaly in res["anomalies"][:3]:
                 alerts.append({"timestamp": a.timestamp, "type": a.type, "message": anomaly.get("reason", "Unknown anomaly")})
    dashboard_data["recent_alerts"] = alerts
    return render_template("dashboard.html", dashboard_data=dashboard_data)

@app.route("/cheatsheets")
@login_required
def cheatsheets():
    return redirect(url_for("memory_helper", tab="cheatsheets"))

@app.route("/users")
@login_required
def manage_users():
    is_admin = current_user.role == "admin"
    users = User.query.order_by(User.id.asc()).all() if is_admin else [current_user]
    groups = Group.query.order_by(Group.name.asc()).all() if is_admin else []
    return render_template("manage_users.html", users=users, groups=groups, is_admin=is_admin)

@app.route("/manage_users")
@login_required
def manage_users_legacy():
    return redirect(url_for("manage_users"))

@app.route("/users/mfa/disable", methods=["POST"])
@login_required
def disable_mfa():
    if not current_user.mfa_enabled:
        flash("MFA is already disabled.", "info")
    else:
        current_user.mfa_enabled = False
        current_user.mfa_secret = None
        db.session.commit()
        flash("MFA disabled for your account.", "success")
    return _safe_redirect(request.referrer, "manage_users")

@app.route("/manage_users/create", methods=["POST"])
@login_required
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "analyst").strip().lower()
    group_id_raw = request.form.get("group_id", "").strip()
    group_id = int(group_id_raw) if group_id_raw.isdigit() else None

    if not username:
        flash("Username is required.", "warning")
        return redirect(url_for("manage_users"))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "warning")
        return redirect(url_for("manage_users"))
    if role not in VALID_USER_ROLES:
        flash("Invalid role.", "danger")
        return redirect(url_for("manage_users"))
    if group_id is not None and not db.session.get(Group, group_id):
        flash("Selected group does not exist.", "danger")
        return redirect(url_for("manage_users"))
    if User.query.filter_by(username=username).first():
        flash("Username already exists.", "danger")
        return redirect(url_for("manage_users"))

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, password_hash=hashed_pw, role=role, group_id=group_id)
    db.session.add(new_user)
    db.session.commit()
    flash(f"User {username} added successfully.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_users/update/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def update_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))

    username = request.form.get("username", user.username).strip()
    role = request.form.get("role", user.role).strip().lower()
    group_id_raw = request.form.get("group_id", "").strip()
    new_password = request.form.get("new_password", "").strip()

    if not username:
        flash("Username cannot be empty.", "warning")
        return redirect(url_for("manage_users"))
    existing = User.query.filter_by(username=username).first()
    if existing and existing.id != user.id:
        flash(f"Username {username} is already used by another account.", "danger")
        return redirect(url_for("manage_users"))
    if role not in VALID_USER_ROLES:
        flash("Invalid role.", "danger")
        return redirect(url_for("manage_users"))
    if user.id == current_user.id and role != "admin":
        flash("You cannot downgrade your own admin role.", "danger")
        return redirect(url_for("manage_users"))

    group_id = int(group_id_raw) if group_id_raw.isdigit() else None
    if group_id is not None and not db.session.get(Group, group_id):
        flash("Selected group does not exist.", "danger")
        return redirect(url_for("manage_users"))
    if new_password and len(new_password) < 8:
        flash("New password must be at least 8 characters.", "warning")
        return redirect(url_for("manage_users"))

    user.username = username
    user.role = role
    user.group_id = group_id
    if new_password:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    db.session.commit()
    flash(f"User {user.username} updated.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_users/mfa/reset/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def reset_user_mfa(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))
    user.mfa_enabled = False
    user.mfa_secret = None
    db.session.commit()
    flash(f"MFA reset for {user.username}.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_users/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))
    if user.username == "admin" or user.id == current_user.id:
        flash("Cannot delete default admin or yourself.", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_groups/create", methods=["POST"])
@login_required
@admin_required
def add_group():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Group name is required.", "warning")
        return redirect(url_for("manage_users"))
    if Group.query.filter_by(name=name).first():
        flash("Group already exists.", "danger")
    else:
        new_group = Group(name=name)
        db.session.add(new_group)
        db.session.commit()
        flash(f"Group {name} added.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_groups/update/<int:group_id>", methods=["POST"])
@login_required
@admin_required
def update_group(group_id):
    group = db.session.get(Group, group_id)
    if not group:
        flash("Group not found.", "danger")
        return redirect(url_for("manage_users"))
    if group.name == "Administrators":
        flash("Administrators group cannot be renamed.", "danger")
        return redirect(url_for("manage_users"))

    new_name = request.form.get("name", "").strip()
    if not new_name:
        flash("Group name cannot be empty.", "warning")
        return redirect(url_for("manage_users"))
    existing = Group.query.filter_by(name=new_name).first()
    if existing and existing.id != group.id:
        flash("Group name already exists.", "danger")
        return redirect(url_for("manage_users"))

    group.name = new_name
    db.session.commit()
    flash("Group updated.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_groups/delete/<int:group_id>", methods=["POST"])
@login_required
@admin_required
def delete_group(group_id):
    group = db.session.get(Group, group_id)
    if not group:
        flash("Group not found.", "danger")
        return redirect(url_for("manage_users"))
    if group.name == "Administrators":
        flash("Cannot delete Administrators group.", "danger")
    elif group.users:
        flash("Cannot delete group with assigned users.", "warning")
    else:
        db.session.delete(group)
        db.session.commit()
        flash(f"Group {group.name} deleted.", "success")
    return redirect(url_for("manage_users"))

@app.route("/sigma/refresh", methods=["POST"])
@login_required
def sigma_refresh():
    if not _require_csrf():
        return _safe_redirect(request.referrer)
    sigma_engine.reload_rules()
    flash("Sigma rules reloaded from local and remote directories.", "success")
    return _safe_redirect(request.referrer)

@app.route("/sigma/sync", methods=["POST"])
@login_required
def sigma_sync():
    if not _require_csrf():
        return _safe_redirect(request.referrer)
    urls_raw = request.form.get("sigma_urls", "").strip()
    env_urls = os.getenv("FORENSIS_SIGMA_URLS", "").strip()
    urls = []

    if urls_raw:
        urls.extend([u.strip() for u in re.split(r"[\n,]+", urls_raw) if u.strip()])
    elif env_urls:
        urls.extend([u.strip() for u in re.split(r"[\n,]+", env_urls) if u.strip()])

    if not urls:
        flash("No Sigma URLs provided.", "warning")
        return _safe_redirect(request.referrer)

    imported_count = sigma_engine.sync_from_urls(urls)
    sigma_engine.reload_rules()
    if imported_count:
        flash(f"Sigma rules synchronized. Imported {imported_count} valid rule file(s).", "success")
    else:
        flash("No valid Sigma rule file imported from provided URLs.", "warning")
    return _safe_redirect(request.referrer)

@celery.task(name="app.process_logs_task")
def process_logs_task(log_text, log_type, filename, user_id):
    results = analyze_logs(log_text, log_type=log_type)
    events = results.get("events", [])
    ship_events(events, "logs")
    history = AnalysisHistory(type="logs", user_id=user_id, results_json=json.dumps(results, default=str), filename=filename)
    db.session.add(history)
    db.session.commit()
    return history.id

@celery.task(name="app.process_network_task")
def process_network_task(path, filename, user_id):
    try:
        results = analyze_pcap(path)
        events = results.get("events", [])
        ship_events(events, "network")
        history = AnalysisHistory(type="network", user_id=user_id, results_json=json.dumps(results, default=str), filename=filename)
        db.session.add(history)
        db.session.commit()
        return history.id
    finally:
        _safe_unlink(path)

@celery.task(name="app.process_memory_task")
def process_memory_task(path, stored_filename, input_name, user_id):
    try:
        raw_output = _read_memory_input(path, stored_filename)
        parsed_output = analyze_generic_output(raw_output, input_name=input_name)
        events = parsed_output.get("events", [])
        results = {
            "mode": "triage",
            "summary": parsed_output.get("summary"),
            "events": events,
            "parsed_output": parsed_output,
            "input_name": input_name,
        }
        ship_events(events, "memory")
        history = AnalysisHistory(type="memory_triage", user_id=user_id, results_json=json.dumps(results, default=str), filename=input_name)
        db.session.add(history)
        db.session.commit()
        return history.id
    finally:
        _safe_unlink(path)

@app.route("/task/status/<task_id>")
@login_required
def task_status(task_id):
    task = celery.AsyncResult(task_id)
    if task.state == 'PENDING':
        return render_template("loading.html", task_id=task_id, status="Pending...")
    elif task.state != 'FAILURE':
        if task.ready():
            return redirect(url_for('view_history', id=task.result))
        return render_template("loading.html", task_id=task_id, status="Processing...")
    else:
        flash("An error occurred during analysis.", "danger")
        return redirect(url_for("dashboard"))

@app.route("/log-analyzer", methods=["GET", "POST"])
@login_required
def log_analyzer():
    if request.method == "POST":
        log_type = request.form.get("log_type") or "generic"
        log_text = request.form.get("log_text", "").strip()
        file = request.files.get("log_file")
        filename = None
        if file and file.filename:
            if not allowed_file(file.filename, ALLOWED_LOG_EXT):
                flash("Unsupported extension.", "danger")
                return _safe_redirect(request.url, "log_analyzer")
            filename, path, _ = _build_upload_path(file.filename)
            file.save(path)
            if not is_safe_content(path, "log"):
                _safe_unlink(path)
                flash("Invalid content.", "danger")
                return _safe_redirect(request.url, "log_analyzer")
            try:
                with open(path, "r", errors="ignore") as f:
                    log_text = f.read()
            finally:
                _safe_unlink(path)
        if not log_text:
            flash("Provide log data.", "warning")
            return _safe_redirect(request.url, "log_analyzer")
        task = process_logs_task.delay(log_text, log_type, filename, current_user.id)
        return redirect(url_for('task_status', task_id=task.id))
    return render_template("log_analyzer.html", results=None)

@app.route("/network-analyzer", methods=["GET", "POST"])
@login_required
def network_analyzer():
    if request.method == "POST":
        file = request.files.get("pcap_file")
        if not file or not file.filename:
            flash("Upload a PCAP file.", "warning")
            return _safe_redirect(request.url, "network_analyzer")
        if not allowed_file(file.filename, ALLOWED_PCAP_EXT):
            flash("Unsupported PCAP extension.", "danger")
            return _safe_redirect(request.url, "network_analyzer")
        filename, path, _ = _build_upload_path(file.filename)
        file.save(path)
        if not is_safe_content(path, "pcap"):
            _safe_unlink(path)
            flash("Invalid PCAP.", "danger")
            return _safe_redirect(request.url, "network_analyzer")
        task = process_network_task.delay(path, filename, current_user.id)
        return redirect(url_for('task_status', task_id=task.id))
    return render_template("network_analyzer.html", results=None)

@app.route("/memory-helper", methods=["GET", "POST"])
@app.route("/helper", methods=["GET", "POST"])
@login_required
def memory_helper():
    playbook = None
    helper_sheets = _helper_cheatsheets()
    active_tab = (request.args.get("tab") or "generate").strip().lower()
    if active_tab not in {"generate", "cheatsheets"}:
        active_tab = "generate"

    if request.method == "POST":
        mode = request.form.get("mode", "playbook")
        if mode != "playbook":
            return redirect(url_for("memory_triage"))

        active_tab = "generate"
        category = request.form.get("category") or "memory"
        profile = request.form.get("profile") or "windows.generic"
        playbook = get_playbook(category, profile)
        if not playbook:
            flash("Playbook profile not found.", "danger")
            return _safe_redirect(request.url, "memory_helper")

        events = playbook.get("events", [])
        results = {
            "mode": "playbook",
            "category": category,
            "summary": None,
            "events": events,
            "playbook": playbook,
        }
        LAST_RESULTS["memory"] = results
        ship_events(events, "memory")
        save_history("memory_playbook", results)

    return render_template(
        "memory_helper.html",
        playbook=playbook,
        helper_sheets=helper_sheets,
        active_tab=active_tab,
    )


@app.route("/memory-triage", methods=["GET", "POST"])
@login_required
def memory_triage():
    parsed_output = None
    if request.method == "POST":
        raw_output = request.form.get("raw_output", "").strip()
        file = request.files.get("memory_file")
        filename = None
        stored_filename = None
        path = None

        if file and file.filename:
            if not allowed_file(file.filename, ALLOWED_MEMORY_EXT):
                flash("Unsupported memory output extension.", "danger")
                return _safe_redirect(request.url, "memory_triage")

            filename, path, stored_filename = _build_upload_path(file.filename)
            file.save(path)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            max_size = MEMORY_TEXT_MAX_BYTES
            if ext in {"vmem", "mem"}:
                max_size = MEMORY_IMAGE_MAX_BYTES
            elif ext == "zip":
                max_size = MEMORY_ARCHIVE_MAX_BYTES

            if os.path.getsize(path) > max_size:
                _safe_unlink(path)
                flash("Uploaded file is too large.", "danger")
                return _safe_redirect(request.url, "memory_triage")

            if not is_safe_content(path, "memory_output"):
                _safe_unlink(path)
                flash("Invalid memory output format.", "danger")
                return _safe_redirect(request.url, "memory_triage")
        else:
            if raw_output:
                if len(raw_output.encode("utf-8")) > MEMORY_TEXT_MAX_BYTES:
                    flash("Input text is too large.", "danger")
                    return _safe_redirect(request.url, "memory_triage")
                filename = "pasted_memory_output.txt"
                _, path, stored_filename = _build_upload_path(filename)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(raw_output)

        if not path or not stored_filename or not filename:
            flash("No data.", "warning")
            return _safe_redirect(request.url, "memory_triage")

        task = process_memory_task.delay(path, stored_filename, filename, current_user.id)
        return redirect(url_for("task_status", task_id=task.id))

    return render_template(
        "memory_triage.html",
        parsed_output=parsed_output,
    )

@app.route("/history")
@login_required
def history():
    query = AnalysisHistory.query.order_by(AnalysisHistory.timestamp.desc())
    if current_user.role != "admin":
        query = query.filter_by(user_id=current_user.id)
    analyses = query.all()
    return render_template("history.html", analyses=analyses)

@app.route("/history/view/<int:id>")
@login_required
def view_history(id):
    analysis = db.session.get(AnalysisHistory, id)
    if not analysis:
        flash("Not found.", "danger")
        return redirect(url_for('history'))
    if current_user.role != "admin" and analysis.user_id != current_user.id:
        flash("Permission denied.", "danger")
        return redirect(url_for("history"))
    results = analysis.get_results()
    if analysis.type == "logs":
         LAST_RESULTS["logs"] = results
         return render_template("log_analyzer.html", results=results, sigma_matches=sigma_engine.correlate_events(results.get("events", [])), historical=True)
    elif analysis.type == "network":
         LAST_RESULTS["network"] = results
         return render_template("network_analyzer.html", results=results, sigma_matches=sigma_engine.correlate_events(results.get("events", [])), historical=True)
    elif "memory" in analysis.type:
         LAST_RESULTS["memory"] = results
         if analysis.type == "memory_playbook":
             playbook = results.get("playbook") or results
             return render_template(
                 "memory_helper.html",
                 playbook=playbook,
                 helper_sheets=_helper_cheatsheets(),
                 active_tab="generate",
                 historical=True,
             )
         if analysis.type == "memory_triage":
             parsed_output = results.get("parsed_output") or results
             sigma_matches = sigma_engine.correlate_events(results.get("events", []))
             return render_template(
                 "memory_triage.html",
                 parsed_output=parsed_output,
                 sigma_matches=sigma_matches,
                 historical=True,
             )
         parsed_output = results.get("parsed_output")
         if parsed_output is None and results.get("summary") is not None:
             parsed_output = results
         sigma_matches = sigma_engine.correlate_events(results.get("events", []))
         if parsed_output is not None:
             return render_template(
                 "memory_triage.html",
                 parsed_output=parsed_output,
                 sigma_matches=sigma_matches,
                 historical=True,
             )
         return redirect(url_for("history"))
    return redirect(url_for('history'))

@app.route("/history/delete/<int:id>", methods=["POST"])
@login_required
def delete_history(id):
    if not _require_csrf():
        return redirect(url_for("history"))
    analysis = db.session.get(AnalysisHistory, id)
    if analysis and (current_user.role == "admin" or analysis.user_id == current_user.id):
        db.session.delete(analysis)
        db.session.commit()
        flash("History deleted.", "success")
    elif analysis:
        flash("Permission denied.", "danger")
    return redirect(url_for('history'))

@app.route("/reset_data", methods=["POST"])
@login_required
@admin_required
def reset_data():
    if not _require_csrf():
        return _safe_redirect(request.referrer, "dashboard")
    AnalysisHistory.query.delete()
    db.session.commit()
    flash("History reset.", "success")
    return redirect(url_for('dashboard'))

def save_history(type, results, filename=None):
    history = AnalysisHistory(type=type, user_id=current_user.id, results_json=json.dumps(results, default=str), filename=filename)
    db.session.add(history)
    db.session.commit()

def _export_events_json(results, filename_default: str):
    if not results:
        return None
    data = {
        "summary": results.get("summary"),
        "events": results.get("events", []),
        "anomalies": results.get("anomalies", []),
    }
    text = json.dumps(data, indent=2, default=str)
    resp = make_response(text)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename_default}"
    return resp

def _export_events_csv(events, fieldnames, filename_default: str):
    if not events:
        return None
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for ev in events:
        row = {k: ev.get(k, "") for k in fieldnames}
        writer.writerow(row)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename_default}"
    return resp

@app.route("/export/logs/<fmt>")
@login_required
def export_logs(fmt: str):
    results = LAST_RESULTS.get("logs")
    if not results:
        flash("No log analysis results to export yet.", "warning")
        return redirect(url_for("log_analyzer"))

    if fmt == "json":
        resp = _export_events_json(results, "forensis_logs.json")
        if resp:
            return resp
    elif fmt == "csv":
        events = results.get("events", [])
        fieldnames = [
            "source",
            "timestamp",
            "ip",
            "host",
            "process",
            "method",
            "path",
            "status",
            "size",
            "message",
            "raw",
        ]
        resp = _export_events_csv(events, fieldnames, "forensis_logs.csv")
        if resp:
            return resp

    flash("Unsupported export format.", "danger")
    return redirect(url_for("log_analyzer"))

@app.route("/export/network/<fmt>")
@login_required
def export_network(fmt: str):
    results = LAST_RESULTS.get("network")
    if not results:
        flash("No network analysis results to export yet.", "warning")
        return redirect(url_for("network_analyzer"))

    if fmt == "json":
        resp = _export_events_json(results, "forensis_network.json")
        if resp:
            return resp
    elif fmt == "csv":
        events = results.get("events", [])
        fieldnames = [
            "source",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "proto",
            "packets",
            "bytes",
            "duration",
            "first_seen",
            "last_seen",
            "avg_payload",
        ]
        resp = _export_events_csv(events, fieldnames, "forensis_network.csv")
        if resp:
            return resp

    flash("Unsupported export format.", "danger")
    return redirect(url_for("network_analyzer"))

@app.route("/export/memory/<fmt>")
@login_required
def export_memory(fmt: str):
    results = LAST_RESULTS.get("memory")
    if not results:
        flash("No memory analysis results to export yet.", "warning")
        return redirect(url_for("memory_triage"))

    events = results.get("events", [])
    if fmt == "json":
        data = {
            "mode": results.get("mode"),
            "summary": results.get("summary"),
            "events": events,
        }
        text = json.dumps(data, indent=2, default=str)
        resp = make_response(text)
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = "attachment; filename=forensis_memory.json"
        return resp
    if fmt == "csv":
        fieldnames = sorted({k for ev in events for k in ev.keys()}) or [
            "source",
            "indicator",
            "message",
            "category",
            "tool",
            "profile",
        ]
        resp = _export_events_csv(events, fieldnames, "forensis_memory.csv")
        if resp:
            return resp

    flash("Unsupported export format.", "danger")
    target = "memory_triage" if results.get("mode") == "triage" else "memory_helper"
    return redirect(url_for(target))

@app.route("/export/report")
@login_required
def export_report_bundle():
    buf = io.BytesIO()
    now = datetime.utcnow().isoformat() + "Z"
    config = {
        "generated_at_utc": now,
        "app": "Forensis",
        "env": {
            "FORENSIS_ELASTIC_URL": os.getenv("FORENSIS_ELASTIC_URL", ""),
            "FORENSIS_ELASTIC_INDEX": os.getenv("FORENSIS_ELASTIC_INDEX", ""),
            "FORENSIS_LOKI_URL": os.getenv("FORENSIS_LOKI_URL", ""),
            "FORENSIS_LOKI_LABELS": os.getenv("FORENSIS_LOKI_LABELS", ""),
            "FORENSIS_SIGMA_URLS": os.getenv("FORENSIS_SIGMA_URLS", ""),
        },
    }

    logs = LAST_RESULTS.get("logs")
    network = LAST_RESULTS.get("network")
    memory = LAST_RESULTS.get("memory")

    rules_meta = []
    for r in sigma_engine.rules:
        rules_meta.append(
            {
                "id": getattr(r, "id", None),
                "title": getattr(r, "title", None),
                "level": getattr(r, "level", None),
                "description": getattr(r, "description", None),
                "logsource": getattr(r, "logsource", None),
            }
        )

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config/env.json", json.dumps(config, indent=2, default=str))
        zf.writestr("sigma/rules.json", json.dumps(rules_meta, indent=2, default=str))
        if logs:
            zf.writestr("results/logs.json", json.dumps(logs, indent=2, default=str))
        if network:
            zf.writestr("results/network.json", json.dumps(network, indent=2, default=str))
        if memory:
            zf.writestr("results/memory.json", json.dumps(memory, indent=2, default=str))

        summary = {
            "generated_at_utc": now,
            "has_logs": bool(logs),
            "has_network": bool(network),
            "has_memory": bool(memory),
            "rule_count": len(rules_meta),
        }
        zf.writestr("summary.json", json.dumps(summary, indent=2, default=str))
        zf.writestr(
            "README_report.txt",
            "Forensis Report Bundle\n\n"
            "This archive contains:\n"
            "- config/env.json\n"
            "- sigma/rules.json\n"
            "- results/*.json\n"
            "- summary.json\n",
        )

    buf.seek(0)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = "attachment; filename=forensis_report_bundle.zip"
    return resp

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        admin_user = os.getenv("FORENSIS_ADMIN_USER", "admin")
        if not User.query.filter_by(username=admin_user).first():
            admin_pass = os.getenv("FORENSIS_ADMIN_PASSWORD", "forensis123")
            hashed_pw = bcrypt.generate_password_hash(admin_pass).decode("utf-8")
            default_group = Group.query.filter_by(name="Administrators").first()
            if not default_group:
                default_group = Group(name="Administrators")
                db.session.add(default_group)
                db.session.commit()
            new_admin = User(
                username=admin_user,
                password_hash=hashed_pw,
                role="admin",
                group_id=default_group.id,
            )
            db.session.add(new_admin)
            db.session.commit()
    app.run(host="0.0.0.0", port=5000, debug=False)
