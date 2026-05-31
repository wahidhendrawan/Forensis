import os
import io
import csv
import json
import zipfile
import re
import base64
import secrets
import time
import pyotp
import qrcode
import magic
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from urllib.parse import urlparse, urljoin
from sqlalchemy import text

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
try:
    from alembic import command as alembic_command
    from alembic.config import Config as AlembicConfig
except Exception:  # pragma: no cover - optional in early bootstrap
    alembic_command = None  # type: ignore
    AlembicConfig = None  # type: ignore

from forensis.models import (
    db,
    User,
    Group,
    AnalysisHistory,
    SystemSetting,
    Case,
    Artifact,
    AnalysisJob,
)
from forensis.analyzers.log_analyzer import analyze_logs
from forensis.analyzers.network_analyzer import analyze_pcap
from forensis.analyzers.playbook_engine import get_playbook, analyze_generic_output
from forensis.analyzers.sigma_engine import SigmaEngine
from forensis.analyzers.yara_engine import YaraEngine
from forensis.analyzers.threat_intel import ThreatIntelEngine
from forensis.analyzers.entity_profile import EntityProfileEngine
from forensis.analyzers.detection_pipeline import enrich_analysis_results
from forensis.analyzers.correlation_engine import correlate_recent_analyses
from forensis.integrations.elk_loki import ship_events
from forensis.services.rule_service import (
    resolve_sigma_matches,
    compact_network_results,
    extract_result_summary,
)
from forensis.services.job_service import (
    get_or_create_active_case,
    register_artifact,
    create_analysis_job,
    bind_job_task,
    update_job_status,
    get_job_by_task_id,
    persist_dfir_outputs,
)
from forensis.services.event_search_service import (
    search_events_opensearch,
    search_events_history_fallback,
)
from forensis.services.analytics_service import (
    clickhouse_overview,
    history_overview_fallback,
)

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB_PATH = os.path.join(BASE_DIR, "instance", "forensis.db")
YARA_RULES_DIR = os.path.join(BASE_DIR, "yara_rules")
THREAT_INTEL_DIR = os.path.join(BASE_DIR, "threat_intel")
ENTITY_CONFIG_DIR = os.path.join(BASE_DIR, "config")


def _env_int(name: str, default: int, min_value: int = None, max_value: int = None) -> int:
    raw = os.getenv(name, "").strip()
    try:
        value = int(raw) if raw else int(default)
    except (TypeError, ValueError):
        value = int(default)
    if min_value is not None and value < min_value:
        value = min_value
    if max_value is not None and value > max_value:
        value = max_value
    return value


def _to_int(value: str, default: int, min_value: int, max_value: int) -> int:
    try:
        parsed = int((value or "").strip())
    except Exception:
        parsed = int(default)
    if parsed < min_value:
        parsed = min_value
    if parsed > max_value:
        parsed = max_value
    return parsed

ALLOWED_LOG_EXT = {"log", "txt", "csv", "json"}
ALLOWED_PCAP_EXT = {"pcap", "pcapng"}
ALLOWED_MEMORY_EXT = {"txt", "log", "json", "jsonl", "ndjson", "csv", "tsv", "xml", "yaml", "yml", "zip", "vmem", "mem", "raw", "dmp", "img", "bin"}
VALID_USER_ROLES = {"admin", "analyst"}
MEMORY_ARCHIVE_MAX_BYTES = 50 * 1024 * 1024
MEMORY_FILE_MAX_BYTES = 8 * 1024 * 1024
MEMORY_TEXT_MAX_BYTES = 50 * 1024 * 1024
MEMORY_IMAGE_MAX_BYTES = 256 * 1024 * 1024
MEMORY_IMAGE_SCAN_BYTES = 64 * 1024 * 1024
MEMORY_STRINGS_MIN_LEN = 6
MEMORY_STRINGS_MAX_LINES = 20000
PCAP_MAX_UPLOAD_BYTES = _env_int("FORENSIS_PCAP_MAX_UPLOAD_BYTES", 300 * 1024 * 1024, min_value=5 * 1024 * 1024, max_value=2 * 1024 * 1024 * 1024)
OTX_API_KEY_SETTING = "otx_api_key"
OTX_API_KEY_MIN_LEN = 16
OTX_API_KEY_MAX_LEN = 256
OTX_API_KEY_REGEX = re.compile(r"^[A-Za-z0-9_\-]{16,256}$")
SIGMA_MAX_EVENTS_DEFAULT = _env_int("FORENSIS_SIGMA_MAX_EVENTS", 900, min_value=100, max_value=5000)
SIGMA_MAX_MATCHES_DEFAULT = _env_int("FORENSIS_SIGMA_MAX_MATCHES", 1500, min_value=50, max_value=10000)
SIGMA_MAX_EVENTS_LOGS = _env_int("FORENSIS_SIGMA_MAX_EVENTS_LOGS", 900, min_value=100, max_value=5000)
SIGMA_MAX_EVENTS_NETWORK = _env_int("FORENSIS_SIGMA_MAX_EVENTS_NETWORK", 250, min_value=50, max_value=2000)
SIGMA_MAX_EVENTS_MEMORY = _env_int("FORENSIS_SIGMA_MAX_EVENTS_MEMORY", 700, min_value=100, max_value=5000)
NETWORK_EVENTS_STORE_LIMIT = _env_int("FORENSIS_NETWORK_EVENTS_STORE_LIMIT", 900, min_value=200, max_value=5000)
NETWORK_ANOMALIES_STORE_LIMIT = _env_int("FORENSIS_NETWORK_ANOMALIES_STORE_LIMIT", 500, min_value=100, max_value=5000)
ASYNC_SIGMA_POSTPROCESS = os.getenv("FORENSIS_ASYNC_SIGMA_POSTPROCESS", "1").strip().lower() in {"1", "true", "yes", "on"}
DB_POOL_SIZE = _env_int("FORENSIS_DB_POOL_SIZE", 20, min_value=1, max_value=200)
DB_POOL_MAX_OVERFLOW = _env_int("FORENSIS_DB_POOL_MAX_OVERFLOW", 40, min_value=0, max_value=400)
DB_POOL_TIMEOUT = _env_int("FORENSIS_DB_POOL_TIMEOUT", 30, min_value=1, max_value=300)
DB_POOL_RECYCLE = _env_int("FORENSIS_DB_POOL_RECYCLE", 1800, min_value=60, max_value=86400)
DISPLAY_TIMEZONE_NAME = os.getenv("FORENSIS_DISPLAY_TZ", "Asia/Jakarta").strip() or "Asia/Jakarta"
try:
    DISPLAY_TIMEZONE = ZoneInfo(DISPLAY_TIMEZONE_NAME)
except Exception:
    DISPLAY_TIMEZONE_NAME = "UTC"
    DISPLAY_TIMEZONE = timezone.utc

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FORENSIS_SECRET_KEY", "change-me-in-production")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
db_uri = os.getenv('FORENSIS_DB_URI', f'sqlite:///{DB_PATH}')
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
if db_uri.startswith("sqlite"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"check_same_thread": False},
    }
else:
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": DB_POOL_RECYCLE,
        "pool_size": DB_POOL_SIZE,
        "max_overflow": DB_POOL_MAX_OVERFLOW,
        "pool_timeout": DB_POOL_TIMEOUT,
        "pool_use_lifo": True,
    }
app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')

def make_celery(app):
    celery = Celery(app.import_name)
    celery.conf.update(
        broker_url=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND'],
        timezone=DISPLAY_TIMEZONE_NAME,
        enable_utc=False,
    )
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    return celery

celery = make_celery(app)


def _as_display_time(value):
    if not isinstance(value, datetime):
        return value
    dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(DISPLAY_TIMEZONE)


def format_local_datetime(value, pattern: str = "%Y-%m-%d %H:%M:%S"):
    if not isinstance(value, datetime):
        return "-"
    try:
        dt = _as_display_time(value)
        return dt.strftime(pattern)
    except Exception:
        return value.strftime(pattern)

@app.context_processor
def inject_now():
    return {
        "now_year": datetime.now(DISPLAY_TIMEZONE).year,
        "csrf_token": _get_csrf_token(),
        "display_tz_name": DISPLAY_TIMEZONE_NAME,
        "fmt_local_dt": format_local_datetime,
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

RUNTIME_INDEX_STATEMENTS = [
    "CREATE INDEX IF NOT EXISTS ix_analysis_history_type_ts ON analysis_history (type, timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_analysis_history_user_ts ON analysis_history (user_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_analysis_job_state_updated ON analysis_job (state, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_analysis_job_case_state ON analysis_job (case_id, state)",
    "CREATE INDEX IF NOT EXISTS ix_artifact_case_created ON artifact (case_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_finding_case_severity_created ON finding (case_id, severity, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_rule_match_case_engine_created ON rule_match (case_id, rule_engine, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_timeline_case_ts ON timeline_event (case_id, created_at)",
]


def _ensure_runtime_indexes():
    for stmt in RUNTIME_INDEX_STATEMENTS:
        try:
            db.session.execute(text(stmt))
        except Exception:
            db.session.rollback()
            continue
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def _get_stored_otx_api_key() -> str:
    try:
        row = SystemSetting.query.filter_by(key=OTX_API_KEY_SETTING).first()
    except Exception:
        return ""
    if not row or not row.value:
        return ""
    return str(row.value).strip()


def _get_effective_otx_api_key() -> str:
    env_key = os.getenv("FORENSIS_OTX_API_KEY", "").strip()
    if env_key:
        return env_key
    return _get_stored_otx_api_key()


def _mask_secret(value: str, left: int = 4, right: int = 4) -> str:
    if not value:
        return ""
    text = str(value)
    if len(text) <= (left + right):
        return "*" * len(text)
    middle = "*" * max(4, len(text) - (left + right))
    return f"{text[:left]}{middle}{text[-right:]}"


def _set_system_setting(key: str, value: str):
    row = SystemSetting.query.filter_by(key=key).first()
    if row is None:
        row = SystemSetting(key=key, value=value)
        db.session.add(row)
    else:
        row.value = value
    db.session.commit()


def _delete_system_setting(key: str):
    row = SystemSetting.query.filter_by(key=key).first()
    if row:
        db.session.delete(row)
        db.session.commit()

sigma_engine = SigmaEngine(os.path.join(BASE_DIR, "sigma_rules"))
yara_engine = YaraEngine(YARA_RULES_DIR)
entity_profile_engine = EntityProfileEngine(ENTITY_CONFIG_DIR)
threat_intel_engine = ThreatIntelEngine(
    THREAT_INTEL_DIR,
    allowlist_engine=entity_profile_engine,
    otx_api_key_getter=_get_effective_otx_api_key,
)


def _resolve_sigma(results: dict, analysis_type: str, force_recompute: bool = False):
    return resolve_sigma_matches(
        results,
        analysis_type,
        sigma_engine,
        default_max_events=SIGMA_MAX_EVENTS_DEFAULT,
        max_matches=SIGMA_MAX_MATCHES_DEFAULT,
        max_events_logs=SIGMA_MAX_EVENTS_LOGS,
        max_events_network=SIGMA_MAX_EVENTS_NETWORK,
        max_events_memory=SIGMA_MAX_EVENTS_MEMORY,
        force_recompute=force_recompute,
    )


def _compact_network(results: dict):
    return compact_network_results(
        results,
        events_limit=NETWORK_EVENTS_STORE_LIMIT,
        anomalies_limit=NETWORK_ANOMALIES_STORE_LIMIT,
    )

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
            return mime in {
                "application/vnd.tcpdump.pcap",
                "application/x-pcapng",
                "application/x-pcap",
                "application/octet-stream",
            }
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
            {"cmd": "vol -f MEM.raw windows.handles", "desc": "Inspect suspicious process handles (LSASS/token access)"},
            {"cmd": "vol -f MEM.raw windows.registry.hivelist", "desc": "Locate registry hives for persistence checks"},
        ],
        "Linux Forensics": [
            {"cmd": "last -f /var/log/wtmp", "desc": "Show login history"},
            {"cmd": "find / -mmin -60", "desc": "Find files changed in last 60 mins"},
            {"cmd": "ss -tulpn", "desc": "List listening sockets and owning process"},
            {"cmd": "journalctl --since \"-2 hours\"", "desc": "Review recent service and auth logs quickly"},
            {"cmd": "ausearch -m USER_AUTH,USER_LOGIN -ts recent", "desc": "Query audit login events for compromise traces"},
        ],
        "Windows Forensics": [
            {"cmd": "wevtutil qe Security /f:text", "desc": "Query Security Event Logs"},
            {"cmd": "Get-WinEvent -LogName Security -MaxEvents 50", "desc": "Read latest security events"},
            {"cmd": "net sessions", "desc": "List active SMB sessions"},
            {"cmd": "Get-ScheduledTask | ? {$_.State -eq 'Ready'}", "desc": "Inspect scheduled task persistence surface"},
            {"cmd": "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "desc": "Check autorun keys for startup persistence"},
        ],
        "Network Analysis": [
            {"cmd": "tcpdump -nn -c 100", "desc": "Capture first 100 packets"},
            {"cmd": "tshark -z io,phs -r capture.pcap", "desc": "Protocol hierarchy summary"},
            {"cmd": "zeek -r capture.pcap", "desc": "Generate Zeek artifacts for triage"},
            {"cmd": "tshark -r capture.pcap -Y \"dns\" -T fields -e frame.time -e ip.src -e dns.qry.name", "desc": "Extract DNS timeline for beaconing/DGA clues"},
            {"cmd": "suricata -r capture.pcap -S custom.rules -l ./suricata_out", "desc": "Replay PCAP against signature rules quickly"},
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
    memory_image_ext = {"vmem", "mem", "raw", "dmp", "img", "bin"}
    if ext in memory_image_ext:
        return _read_memory_image_strings(path)

    if ext != "zip":
        with open(path, "r", errors="ignore") as f:
            return f.read()

    chunks = []
    allowed_inner_ext = {"txt", "log", "json", "jsonl", "ndjson", "csv", "tsv", "xml", "yaml", "yml", "vmem", "mem", "raw", "dmp", "img", "bin"}
    with zipfile.ZipFile(path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            inner_name = info.filename
            inner_ext = inner_name.rsplit(".", 1)[-1].lower() if "." in inner_name else ""
            max_allowed = MEMORY_IMAGE_MAX_BYTES if inner_ext in memory_image_ext else MEMORY_FILE_MAX_BYTES
            if info.file_size > max_allowed:
                continue
            if inner_ext not in allowed_inner_ext:
                continue
            data = zf.read(info)

            if inner_ext in memory_image_ext:
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
        if not _require_csrf():
            return _safe_redirect(request.referrer, "manage_users")
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
        "recent_alerts": [],
        "cross_source": {"findings": [], "count": 0, "severity_counts": {}},
    }
    recent_analyses = AnalysisHistory.query.order_by(AnalysisHistory.timestamp.desc()).limit(40).all()
    alerts = []
    for a in recent_analyses:
        res = a.get_results()
        if res and res.get("anomalies"):
             for anomaly in res["anomalies"][:3]:
                 alerts.append({"timestamp": a.timestamp, "type": a.type, "message": anomaly.get("reason", "Unknown anomaly")})
    dashboard_data["recent_alerts"] = alerts
    dashboard_data["cross_source"] = correlate_recent_analyses(
        recent_analyses,
        window_minutes=int(os.getenv("FORENSIS_CORRELATION_WINDOW_MINUTES", "60")),
    )
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
    env_otx_key = os.getenv("FORENSIS_OTX_API_KEY", "").strip()
    stored_otx_key = _get_stored_otx_api_key() if is_admin else ""
    effective_otx_key = env_otx_key or stored_otx_key
    return render_template(
        "manage_users.html",
        users=users,
        groups=groups,
        is_admin=is_admin,
        otx_enabled=bool(effective_otx_key),
        otx_key_masked=_mask_secret(effective_otx_key),
        otx_env_override=bool(env_otx_key),
        otx_stored_key_masked=_mask_secret(stored_otx_key),
    )


@app.route("/manage_integrations/otx", methods=["POST"])
@login_required
@admin_required
def update_otx_integration():
    if not _require_csrf():
        return redirect(url_for("manage_users"))

    action = request.form.get("action", "save").strip().lower()
    if action == "clear":
        _delete_system_setting(OTX_API_KEY_SETTING)
        threat_intel_engine.invalidate_cache_prefix("otx:")
        flash("OTX API key removed from dashboard settings.", "success")
        return redirect(url_for("manage_users"))

    api_key = request.form.get("otx_api_key", "").strip()
    if not api_key:
        flash("OTX API key cannot be empty.", "warning")
        return redirect(url_for("manage_users"))
    if len(api_key) < OTX_API_KEY_MIN_LEN or len(api_key) > OTX_API_KEY_MAX_LEN:
        flash("Invalid OTX API key length.", "danger")
        return redirect(url_for("manage_users"))
    if not OTX_API_KEY_REGEX.fullmatch(api_key):
        flash("OTX API key format is invalid.", "danger")
        return redirect(url_for("manage_users"))

    _set_system_setting(OTX_API_KEY_SETTING, api_key)
    threat_intel_engine.invalidate_cache_prefix("otx:")
    if os.getenv("FORENSIS_OTX_API_KEY", "").strip():
        flash("OTX API key saved, but currently overridden by FORENSIS_OTX_API_KEY environment variable.", "info")
    else:
        flash("OTX API key saved successfully.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage_users")
@login_required
def manage_users_legacy():
    return redirect(url_for("manage_users"))

@app.route("/users/mfa/disable", methods=["POST"])
@login_required
def disable_mfa():
    if not _require_csrf():
        return _safe_redirect(request.referrer, "manage_users")
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    if not _require_csrf():
        return redirect(url_for("manage_users"))
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
    yara_engine.reload_rules()
    entity_profile_engine.reload()
    threat_intel_engine.reload()
    flash("Detection engines reloaded (Sigma, YARA, Threat Intel, Entity Profile).", "success")
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
def process_logs_task(log_text, log_type, filename, user_id, job_id=None):
    started = time.monotonic()
    if job_id:
        update_job_status(job_id, state="running", stage="parse", progress=10, mark_started=True)
    try:
        results = analyze_logs(log_text, log_type=log_type)
        if job_id:
            update_job_status(job_id, state="running", stage="enrich", progress=45)
        results = enrich_analysis_results(
            results,
            "logs",
            yara_engine=yara_engine,
            threat_intel_engine=threat_intel_engine,
            entity_profile_engine=entity_profile_engine,
            raw_blob=log_text,
        )
        events = results.get("events", [])
        ship_events(events, "logs")

        run_async_sigma = bool(job_id) and ASYNC_SIGMA_POSTPROCESS
        results["sigma_status"] = "queued" if run_async_sigma else "ready"
        if run_async_sigma:
            results["sigma_matches"] = []

        history = AnalysisHistory(type="logs", user_id=user_id, filename=filename)
        history.set_results(results)
        db.session.add(history)
        db.session.commit()

        if run_async_sigma:
            if job_id:
                update_job_status(
                    job_id,
                    state="partial",
                    stage="post_rule_match",
                    progress=90,
                    history_id=history.id,
                    summary=extract_result_summary(results),
                )
                persist_dfir_outputs(job_id, results, sigma_matches=[])
                postprocess_sigma_task.apply_async(args=(history.id, "logs", job_id), queue="rules")
        else:
            matches = _resolve_sigma(results, "logs")
            results["sigma_status"] = "ready"
            history.set_results(results)
            db.session.commit()
            if job_id:
                update_job_status(
                    job_id,
                    state="succeeded",
                    stage="complete",
                    progress=100,
                    history_id=history.id,
                    summary=extract_result_summary(results),
                    mark_finished=True,
                )
                persist_dfir_outputs(job_id, results, sigma_matches=matches)

        app.logger.info(
            "process_logs_task completed in %.3fs (events=%d anomalies=%d sigma_status=%s)",
            time.monotonic() - started,
            len(events),
            len(results.get("anomalies") or []),
            results.get("sigma_status", "ready"),
        )
        return history.id
    except Exception as exc:
        if job_id:
            update_job_status(job_id, state="failed", stage="failed", progress=100, error_message=str(exc), mark_finished=True)
        raise

@celery.task(name="app.process_network_task")
def process_network_task(path, filename, user_id, job_id=None):
    started = time.monotonic()
    if job_id:
        update_job_status(job_id, state="running", stage="parse", progress=10, mark_started=True)
    try:
        results = analyze_pcap(path)
        if job_id:
            update_job_status(job_id, state="running", stage="enrich", progress=45)
        results = enrich_analysis_results(
            results,
            "network",
            yara_engine=yara_engine,
            threat_intel_engine=threat_intel_engine,
            entity_profile_engine=entity_profile_engine,
        )
        results = _compact_network(results)
        events = results.get("events", [])
        ship_events(events, "network")
        run_async_sigma = bool(job_id) and ASYNC_SIGMA_POSTPROCESS
        results["sigma_status"] = "queued" if run_async_sigma else "ready"
        if run_async_sigma:
            results["sigma_matches"] = []

        history = AnalysisHistory(type="network", user_id=user_id, filename=filename)
        history.set_results(results)
        db.session.add(history)
        db.session.commit()

        if run_async_sigma:
            if job_id:
                update_job_status(
                    job_id,
                    state="partial",
                    stage="post_rule_match",
                    progress=90,
                    history_id=history.id,
                    summary=extract_result_summary(results),
                )
                persist_dfir_outputs(job_id, results, sigma_matches=[])
                postprocess_sigma_task.apply_async(args=(history.id, "network", job_id), queue="rules")
        else:
            matches = _resolve_sigma(results, "network")
            results["sigma_status"] = "ready"
            history.set_results(results)
            db.session.commit()
            if job_id:
                update_job_status(
                    job_id,
                    state="succeeded",
                    stage="complete",
                    progress=100,
                    history_id=history.id,
                    summary=extract_result_summary(results),
                    mark_finished=True,
                )
                persist_dfir_outputs(job_id, results, sigma_matches=matches)

        app.logger.info(
            "process_network_task completed in %.3fs (events_stored=%d events_total=%d anomalies=%d sigma_status=%s)",
            time.monotonic() - started,
            len(events),
            int((results.get("summary") or {}).get("event_count_total") or len(events)),
            len(results.get("anomalies") or []),
            results.get("sigma_status", "ready"),
        )
        return history.id
    except Exception as exc:
        if job_id:
            update_job_status(job_id, state="failed", stage="failed", progress=100, error_message=str(exc), mark_finished=True)
        raise
    finally:
        _safe_unlink(path)

@celery.task(name="app.process_memory_task")
def process_memory_task(path, stored_filename, input_name, user_id, job_id=None):
    started = time.monotonic()
    if job_id:
        update_job_status(job_id, state="running", stage="parse", progress=10, mark_started=True)
    try:
        raw_output = _read_memory_input(path, stored_filename)
        parsed_output = analyze_generic_output(raw_output, input_name=input_name)
        if job_id:
            update_job_status(job_id, state="running", stage="enrich", progress=45)
        parsed_output = enrich_analysis_results(
            parsed_output,
            "memory",
            yara_engine=yara_engine,
            threat_intel_engine=threat_intel_engine,
            entity_profile_engine=entity_profile_engine,
            raw_blob=raw_output,
        )
        events = parsed_output.get("events", [])
        results = {
            "mode": "triage",
            "summary": parsed_output.get("summary"),
            "events": events,
            "anomalies": parsed_output.get("anomalies", []),
            "parsed_output": parsed_output,
            "input_name": input_name,
        }
        ship_events(events, "memory")

        run_async_sigma = bool(job_id) and ASYNC_SIGMA_POSTPROCESS
        results["sigma_status"] = "queued" if run_async_sigma else "ready"
        if run_async_sigma:
            results["sigma_matches"] = []

        history = AnalysisHistory(type="memory_triage", user_id=user_id, filename=input_name)
        history.set_results(results)
        db.session.add(history)
        db.session.commit()

        if run_async_sigma:
            if job_id:
                update_job_status(
                    job_id,
                    state="partial",
                    stage="post_rule_match",
                    progress=90,
                    history_id=history.id,
                    summary=extract_result_summary(results),
                )
                persist_dfir_outputs(job_id, results, sigma_matches=[])
                postprocess_sigma_task.apply_async(args=(history.id, "memory", job_id), queue="rules")
        else:
            matches = _resolve_sigma(results, "memory")
            results["sigma_status"] = "ready"
            history.set_results(results)
            db.session.commit()
            if job_id:
                update_job_status(
                    job_id,
                    state="succeeded",
                    stage="complete",
                    progress=100,
                    history_id=history.id,
                    summary=extract_result_summary(results),
                    mark_finished=True,
                )
                persist_dfir_outputs(job_id, results, sigma_matches=matches)

        app.logger.info(
            "process_memory_task completed in %.3fs (events=%d anomalies=%d sigma_status=%s)",
            time.monotonic() - started,
            len(events),
            len(results.get("anomalies") or []),
            results.get("sigma_status", "ready"),
        )
        return history.id
    except Exception as exc:
        if job_id:
            update_job_status(job_id, state="failed", stage="failed", progress=100, error_message=str(exc), mark_finished=True)
        raise
    finally:
        _safe_unlink(path)


@celery.task(name="app.postprocess_sigma_task")
def postprocess_sigma_task(history_id, analysis_type, job_id=None):
    analysis = db.session.get(AnalysisHistory, int(history_id))
    if not analysis:
        if job_id:
            update_job_status(job_id, state="failed", stage="failed", progress=100, error_message="History not found for sigma postprocess", mark_finished=True)
        return 0

    if job_id:
        update_job_status(job_id, state="running", stage="rule_match", progress=94)

    try:
        results = analysis.get_results() or {}
        matches = _resolve_sigma(results, analysis_type, force_recompute=True)
        results["sigma_status"] = "ready"
        analysis.set_results(results)
        db.session.commit()

        if job_id:
            update_job_status(
                job_id,
                state="succeeded",
                stage="complete",
                progress=100,
                summary=extract_result_summary(results),
                mark_finished=True,
            )
            persist_dfir_outputs(job_id, results, sigma_matches=matches)
        return len(matches)
    except Exception as exc:
        db.session.rollback()
        if job_id:
            update_job_status(job_id, state="failed", stage="failed", progress=100, error_message=str(exc), mark_finished=True)
        raise

@app.route("/task/status/<task_id>")
@login_required
def task_status(task_id):
    job = get_job_by_task_id(task_id)
    if job:
        if job.history_id and job.state in {"succeeded", "partial"}:
            if job.state == "partial":
                flash("Core analysis completed. Rule correlation is finishing in background.", "info")
            return redirect(url_for("view_history", id=job.history_id))
        if job.state == "failed":
            flash(job.error_message or "An error occurred during analysis.", "danger")
            return redirect(url_for("dashboard"))

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


@app.route("/api/jobs/<task_id>/status")
@login_required
def api_job_status(task_id):
    job = get_job_by_task_id(task_id)
    if job:
        payload = job.as_status()
        payload["ready"] = bool(job.history_id) and job.state in {"succeeded", "partial"}
        payload["failed"] = job.state == "failed"
        payload["redirect_url"] = url_for("view_history", id=job.history_id) if payload["ready"] else None
        return jsonify(payload)

    task = celery.AsyncResult(task_id)
    payload = {
        "task_id": task_id,
        "state": str(task.state).lower(),
        "stage": str(task.state).lower(),
        "progress": 0,
        "ready": False,
        "failed": task.state == "FAILURE",
        "redirect_url": None,
        "error_message": "",
    }
    if task.state == "PENDING":
        payload["progress"] = 5
    elif task.state in {"STARTED", "RETRY"}:
        payload["progress"] = 40
    elif task.state == "SUCCESS":
        payload["ready"] = True
        payload["progress"] = 100
        payload["redirect_url"] = url_for("view_history", id=task.result)
    elif task.state == "FAILURE":
        payload["progress"] = 100
        payload["error_message"] = "Background task failed."
    return jsonify(payload)


@app.route("/api/cases")
@login_required
def api_cases():
    limit = _env_int("FORENSIS_API_CASES_LIMIT", 100, min_value=1, max_value=500)
    query = Case.query.order_by(Case.updated_at.desc())
    if current_user.role != "admin":
        query = query.filter_by(owner_user_id=current_user.id)
    cases = query.limit(limit).all()
    payload = []
    for c in cases:
        payload.append(
            {
                "id": c.id,
                "case_key": c.case_key,
                "title": c.title,
                "status": c.status,
                "severity": c.severity,
                "owner_user_id": c.owner_user_id,
                "schema_version": c.schema_version,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                "artifact_count": len(c.artifacts),
                "job_count": len(c.jobs),
                "finding_count": len(c.findings),
            }
        )
    return jsonify({"items": payload, "count": len(payload)})


@app.route("/api/jobs")
@login_required
def api_jobs():
    limit = _env_int("FORENSIS_API_JOBS_LIMIT", 200, min_value=1, max_value=1000)
    query = AnalysisJob.query.order_by(AnalysisJob.id.desc())
    state = (request.args.get("state") or "").strip().lower()
    job_type = (request.args.get("job_type") or "").strip().lower()
    case_id_raw = (request.args.get("case_id") or "").strip()

    if state:
        query = query.filter_by(state=state)
    if job_type:
        query = query.filter_by(job_type=job_type)
    if case_id_raw.isdigit():
        query = query.filter_by(case_id=int(case_id_raw))

    if current_user.role != "admin":
        query = query.filter_by(submitted_by_user_id=current_user.id)

    items = [job.as_status() for job in query.limit(limit).all()]
    return jsonify({"items": items, "count": len(items)})


@app.route("/api/jobs/<int:job_id>")
@login_required
def api_job_detail(job_id):
    job = db.session.get(AnalysisJob, int(job_id))
    if not job:
        return jsonify({"error": "not_found"}), 404
    if current_user.role != "admin" and job.submitted_by_user_id != current_user.id:
        return jsonify({"error": "forbidden"}), 403

    artifact = db.session.get(Artifact, job.artifact_id) if job.artifact_id else None
    case = db.session.get(Case, job.case_id) if job.case_id else None

    payload = job.as_status()
    payload["summary"] = job.get_result_summary()
    payload["case"] = {
        "id": case.id,
        "case_key": case.case_key,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
    } if case else None
    payload["artifact"] = {
        "id": artifact.id,
        "artifact_type": artifact.artifact_type,
        "filename": artifact.filename,
        "storage_backend": artifact.storage_backend,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
    } if artifact else None
    return jsonify(payload)


@app.route("/api/search/events")
@login_required
def api_search_events():
    query_text = (request.args.get("q") or "").strip()
    source_type = (request.args.get("source_type") or "").strip().lower()
    since_minutes = _to_int(request.args.get("since_minutes", "120"), default=120, min_value=5, max_value=10080)
    limit = _to_int(request.args.get("limit", "100"), default=100, min_value=1, max_value=500)
    prefer_backend = (request.args.get("backend") or "").strip().lower()

    result = {"backend": "", "items": [], "count": 0}
    use_history_only = prefer_backend == "history"

    if not use_history_only:
        os_result = search_events_opensearch(
            query=query_text,
            source_type=source_type,
            since_minutes=since_minutes,
            limit=limit,
        )
        if os_result.get("count", 0) > 0 or os_result.get("backend") == "opensearch":
            result = os_result

    if result.get("count", 0) <= 0:
        result = search_events_history_fallback(
            current_user=current_user,
            query=query_text,
            source_type=source_type,
            since_minutes=since_minutes,
            limit=limit,
        )

    return jsonify(
        {
            "backend": result.get("backend"),
            "count": int(result.get("count", 0)),
            "items": result.get("items", []),
            "since_minutes": since_minutes,
            "limit": limit,
        }
    )


@app.route("/api/analytics/overview")
@login_required
def api_analytics_overview():
    since_minutes = _to_int(request.args.get("since_minutes", "1440"), default=1440, min_value=5, max_value=43200)
    preferred = (request.args.get("backend") or "").strip().lower()

    if preferred == "history":
        data = history_overview_fallback(current_user=current_user, since_minutes=since_minutes)
    else:
        data = clickhouse_overview(since_minutes=since_minutes)
        if not data.get("enabled") or data.get("errors"):
            data = history_overview_fallback(current_user=current_user, since_minutes=since_minutes)

    data["since_minutes"] = since_minutes
    return jsonify(data)

@app.route("/log-analyzer", methods=["GET", "POST"])
@login_required
def log_analyzer():
    if request.method == "POST":
        if not _require_csrf():
            return _safe_redirect(request.url, "log_analyzer")
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
        case = get_or_create_active_case(current_user.id, "logs", filename or "pasted_logs.txt")
        artifact = register_artifact(
            case_id=case.id,
            uploaded_by_user_id=current_user.id,
            artifact_type="logs",
            filename=filename or "pasted_logs.txt",
            storage_backend="inline",
            metadata={
                "log_type": log_type,
                "ingest_mode": "upload" if filename else "paste",
                "input_size_bytes": len(log_text.encode("utf-8", errors="ignore")),
            },
        )
        job = create_analysis_job(
            job_type="logs",
            submitted_by_user_id=current_user.id,
            case_id=case.id,
            artifact_id=artifact.id,
            queue_name="logs",
        )
        task = process_logs_task.apply_async(args=(log_text, log_type, filename, current_user.id, job.id), queue="logs")
        bind_job_task(job.id, task.id)
        return redirect(url_for('task_status', task_id=task.id))
    return render_template("log_analyzer.html", results=None)

@app.route("/network-analyzer", methods=["GET", "POST"])
@login_required
def network_analyzer():
    if request.method == "POST":
        if not _require_csrf():
            return _safe_redirect(request.url, "network_analyzer")
        file = request.files.get("pcap_file")
        if not file or not file.filename:
            flash("Upload a PCAP file.", "warning")
            return _safe_redirect(request.url, "network_analyzer")
        if not allowed_file(file.filename, ALLOWED_PCAP_EXT):
            flash("Unsupported PCAP extension.", "danger")
            return _safe_redirect(request.url, "network_analyzer")
        filename, path, _ = _build_upload_path(file.filename)
        file.save(path)
        if os.path.getsize(path) > PCAP_MAX_UPLOAD_BYTES:
            _safe_unlink(path)
            flash(f"PCAP file is too large (max {PCAP_MAX_UPLOAD_BYTES // (1024 * 1024)} MB).", "danger")
            return _safe_redirect(request.url, "network_analyzer")
        if not is_safe_content(path, "pcap"):
            _safe_unlink(path)
            flash("Invalid PCAP.", "danger")
            return _safe_redirect(request.url, "network_analyzer")
        case = get_or_create_active_case(current_user.id, "network", filename)
        artifact = register_artifact(
            case_id=case.id,
            uploaded_by_user_id=current_user.id,
            artifact_type="network",
            filename=filename,
            storage_path=path,
            storage_backend="local",
            metadata={"ingest_mode": "upload", "format": filename.rsplit(".", 1)[-1].lower()},
        )
        job = create_analysis_job(
            job_type="network",
            submitted_by_user_id=current_user.id,
            case_id=case.id,
            artifact_id=artifact.id,
            queue_name="network",
        )
        task = process_network_task.apply_async(args=(path, filename, current_user.id, job.id), queue="network")
        bind_job_task(job.id, task.id)
        return redirect(url_for('task_status', task_id=task.id))
    return render_template("network_analyzer.html", results=None)

@app.route("/memory-helper", methods=["GET", "POST"])
@app.route("/helper", methods=["GET", "POST"])
@login_required
def memory_helper():
    playbook = None
    helper_sheets = _helper_cheatsheets()

    if request.method == "POST":
        if not _require_csrf():
            return _safe_redirect(request.url, "memory_helper")
        mode = request.form.get("mode", "playbook")
        if mode != "playbook":
            return redirect(url_for("memory_triage"))

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
    )


@app.route("/memory-triage", methods=["GET", "POST"])
@login_required
def memory_triage():
    parsed_output = None
    if request.method == "POST":
        if not _require_csrf():
            return _safe_redirect(request.url, "memory_triage")
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
            if ext in {"vmem", "mem", "raw", "dmp", "img", "bin"}:
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

        case = get_or_create_active_case(current_user.id, "memory", filename)
        artifact = register_artifact(
            case_id=case.id,
            uploaded_by_user_id=current_user.id,
            artifact_type="memory",
            filename=filename,
            storage_path=path,
            storage_backend="local",
            metadata={"ingest_mode": "upload" if file and file.filename else "paste"},
        )
        job = create_analysis_job(
            job_type="memory",
            submitted_by_user_id=current_user.id,
            case_id=case.id,
            artifact_id=artifact.id,
            queue_name="memory",
        )
        task = process_memory_task.apply_async(args=(path, stored_filename, filename, current_user.id, job.id), queue="memory")
        bind_job_task(job.id, task.id)
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
    if not isinstance(results, dict):
        flash("Invalid analysis data.", "danger")
        return redirect(url_for("history"))

    had_sigma_cache = isinstance(results.get("sigma_matches"), list)
    compacted_network = False
    if analysis.type == "network":
        events_before = len(results.get("events") or [])
        if events_before > NETWORK_EVENTS_STORE_LIMIT:
            _compact_network(results)
            compacted_network = True
    sigma_matches = _resolve_sigma(results, analysis.type)
    if ((not had_sigma_cache and isinstance(results.get("sigma_matches"), list)) or compacted_network):
        try:
            analysis.set_results(results)
            db.session.commit()
        except Exception:
            db.session.rollback()

    if analysis.type == "logs":
         LAST_RESULTS["logs"] = results
         return render_template("log_analyzer.html", results=results, sigma_matches=sigma_matches, historical=True)
    elif analysis.type == "network":
         LAST_RESULTS["network"] = results
         return render_template("network_analyzer.html", results=results, sigma_matches=sigma_matches, historical=True)
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
             return render_template(
                 "memory_triage.html",
                 parsed_output=parsed_output,
                 sigma_matches=sigma_matches,
                 historical=True,
             )
         parsed_output = results.get("parsed_output")
         if parsed_output is None and results.get("summary") is not None:
             parsed_output = results
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
    history = AnalysisHistory(type=type, user_id=current_user.id, filename=filename)
    history.set_results(results)
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
            "FORENSIS_OPENSEARCH_URL": os.getenv("FORENSIS_OPENSEARCH_URL", ""),
            "FORENSIS_OPENSEARCH_INDEX": os.getenv("FORENSIS_OPENSEARCH_INDEX", ""),
            "FORENSIS_LOKI_URL": os.getenv("FORENSIS_LOKI_URL", ""),
            "FORENSIS_LOKI_LABELS": os.getenv("FORENSIS_LOKI_LABELS", ""),
            "FORENSIS_CLICKHOUSE_URL": os.getenv("FORENSIS_CLICKHOUSE_URL", ""),
            "FORENSIS_CLICKHOUSE_DB": os.getenv("FORENSIS_CLICKHOUSE_DB", ""),
            "FORENSIS_CLICKHOUSE_TABLE": os.getenv("FORENSIS_CLICKHOUSE_TABLE", ""),
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

def _bootstrap_database():
    use_alembic = os.getenv("FORENSIS_USE_ALEMBIC", "1").strip().lower() in {"1", "true", "yes", "on"}
    if use_alembic and alembic_command and AlembicConfig:
        try:
            alembic_ini = os.path.join(BASE_DIR, "alembic.ini")
            cfg = AlembicConfig(alembic_ini)
            cfg.set_main_option("script_location", os.path.join(BASE_DIR, "migrations"))
            cfg.set_main_option("sqlalchemy.url", app.config.get("SQLALCHEMY_DATABASE_URI", db_uri))
            alembic_command.upgrade(cfg, "head")
        except Exception as exc:
            app.logger.warning("Alembic upgrade failed, attempting legacy stamp. reason=%s", exc)
            try:
                alembic_command.stamp(cfg, "head")
                alembic_command.upgrade(cfg, "head")
            except Exception as stamp_exc:
                app.logger.warning("Alembic stamp failed; fallback to create_all. reason=%s", stamp_exc)
                db.create_all()
    else:
        db.create_all()
    _ensure_runtime_indexes()
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


with app.app_context():
    run_bootstrap = os.getenv("FORENSIS_BOOTSTRAP_DB", "1").strip().lower() in {"1", "true", "yes", "on"}
    if run_bootstrap:
        _bootstrap_database()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
