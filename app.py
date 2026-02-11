import os
import io
import csv
import json
import zipfile
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    make_response,
    session,
)
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

from forensis.models import db, User, Group, AnalysisHistory
from forensis.analyzers.log_analyzer import analyze_logs
from forensis.analyzers.network_analyzer import analyze_pcap
from forensis.analyzers.memory_helper import generate_playbook, analyze_memory_output
from forensis.analyzers.sigma_engine import SigmaEngine
from forensis.integrations.elk_loki import ship_events

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB_PATH = os.path.join(BASE_DIR, "instance", "forensis.db")

ALLOWED_LOG_EXT = {"log", "txt", "csv", "json"}
ALLOWED_PCAP_EXT = {"pcap", "pcapng"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FORENSIS_SECRET_KEY", "change-me-in-production")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('FORENSIS_DB_URI', f'sqlite:///{DB_PATH}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# In-memory storage for last analysis results (per type) for export & dashboard
LAST_RESULTS = {
    "logs": None,
    "network": None,
    "memory": None,
}

sigma_engine = SigmaEngine(os.path.join(BASE_DIR, "sigma_rules"))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename, allowed_ext):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_ext

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Access denied: Admins only.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    # Interactive dashboard aggregating latest analysis results for charts.
    logs = LAST_RESULTS.get("logs") or {}
    network = LAST_RESULTS.get("network") or {}
    memory = LAST_RESULTS.get("memory") or {}

    dashboard_data = {
        "logs": {
            "total": logs.get("summary", {}).get("parsed_events", 0),
            "anomalies": logs.get("summary", {}).get("anomaly_count", 0),
            "top_sources": logs.get("summary", {}).get("top_sources", []),
            "top_status": logs.get("summary", {}).get("top_status", []),
        },
        "network": {
            "flows": network.get("summary", {}).get("flow_count", 0),
            "anomalies": network.get("summary", {}).get("anomaly_count", 0),
        },
        "memory": {
            "mode": memory.get("mode"),
            "suspicious": (memory.get("summary") or {}).get("suspicious_hits", 0)
            if memory.get("mode") == "triage"
            else None,
        },
    }

    return render_template("dashboard.html", dashboard_data=dashboard_data)

@app.route("/manage_users", methods=["GET", "POST"])
@login_required
@admin_required
def manage_users():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        role = request.form.get("role")
        group_id = request.form.get("group_id")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        else:
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password_hash=hashed_pw, role=role, group_id=group_id)
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {username} added successfully.", "success")
        return redirect(url_for('manage_users'))

    users = User.query.all()
    groups = Group.query.all()
    return render_template("manage_users.html", users=users, groups=groups)

@app.route("/manage_users/delete/<int:user_id>")
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin' or user.id == current_user.id:
        flash("Cannot delete default admin or yourself.", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted.", "success")
    return redirect(url_for('manage_users'))

@app.route("/manage_groups", methods=["POST"])
@login_required
@admin_required
def add_group():
    name = request.form.get("name").strip()
    if Group.query.filter_by(name=name).first():
        flash("Group already exists.", "danger")
    else:
        new_group = Group(name=name)
        db.session.add(new_group)
        db.session.commit()
        flash(f"Group {name} added.", "success")
    return redirect(url_for('manage_users'))


@app.route("/sigma/refresh", methods=["POST"])
@login_required
def sigma_refresh():
    sigma_engine.reload_rules()
    flash("Sigma rules reloaded from local and remote directories.", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/sigma/sync", methods=["POST"])
@login_required
def sigma_sync():
    urls_raw = request.form.get("sigma_urls", "").strip()
    env_urls = os.getenv("FORENSIS_SIGMA_URLS", "").strip()
    urls = []

    if urls_raw:
        urls.extend([u.strip() for u in urls_raw.split(",") if u.strip()])
    elif env_urls:
        urls.extend([u.strip() for u in env_urls.split(",") if u.strip()])

    if not urls:
        flash("No Sigma URLs provided.", "warning")
        return redirect(request.referrer or url_for("dashboard"))

    sigma_engine.sync_from_urls(urls)
    sigma_engine.reload_rules()
    flash(f"Sigma rules synchronized from {len(urls)} URL(s).", "success")
    return redirect(request.referrer or url_for("dashboard"))

def save_history(type, results, filename=None):
    history = AnalysisHistory(
        type=type,
        user_id=current_user.id,
        results_json=json.dumps(results, default=str),
        filename=filename
    )
    db.session.add(history)
    db.session.commit()

@app.route("/log-analyzer", methods=["GET", "POST"])
@login_required
def log_analyzer():
    results = None
    sigma_matches = None
    if request.method == "POST":
        log_type = request.form.get("log_type") or "generic"
        log_text = request.form.get("log_text", "").strip()
        file = request.files.get("log_file")
        filename = None

        if file and file.filename:
            # allowed_file check is a bit generic, we might want to relax it for CSV/JSON or extend ALLOWED_LOG_EXT
            if not allowed_file(file.filename, ALLOWED_LOG_EXT):
                flash("Unsupported log file extension.", "danger")
                return redirect(request.url)
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)
            with open(path, "r", errors="ignore") as f:
                log_text = f.read()

        if not log_text:
            flash("Please paste log data or upload a log file.", "warning")
            return redirect(request.url)

        results = analyze_logs(log_text, log_type=log_type)
        events = results.get("events", [])
        sigma_matches = sigma_engine.correlate_events(events)

        # Store last results for export/dashboard and push to ELK/Loki
        LAST_RESULTS["logs"] = results
        ship_events(events, "logs")
        save_history("logs", results, filename)

    return render_template(
        "log_analyzer.html",
        results=results,
        sigma_matches=sigma_matches,
    )


@app.route("/network-analyzer", methods=["GET", "POST"])
@login_required
def network_analyzer():
    results = None
    sigma_matches = None
    if request.method == "POST":
        file = request.files.get("pcap_file")
        if not file or not file.filename:
            flash("Please upload a PCAP file.", "warning")
            return redirect(request.url)
        if not allowed_file(file.filename, ALLOWED_PCAP_EXT):
            flash("Unsupported PCAP file extension.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(path)

        results = analyze_pcap(path)
        events = results.get("events", [])
        sigma_matches = sigma_engine.correlate_events(events)

        LAST_RESULTS["network"] = results
        ship_events(events, "network")
        save_history("network", results, filename)

    return render_template(
        "network_analyzer.html",
        results=results,
        sigma_matches=sigma_matches,
    )


@app.route("/memory-helper", methods=["GET", "POST"])
@login_required
def memory_helper():
    playbook = None
    parsed_output = None
    sigma_matches = None

    if request.method == "POST":
        mode = request.form.get("mode", "playbook")
        if mode == "playbook":
            profile = request.form.get("profile") or "windows.generic"
            focus = request.form.getlist("focus") or ["processes", "network"]
            playbook = generate_playbook(profile, focus)
            events = playbook.get("events", [])
            sigma_matches = sigma_engine.correlate_events(events)
            results = {
                "mode": "playbook",
                "events": events,
                "summary": None,
            }
            LAST_RESULTS["memory"] = results
            ship_events(events, "memory")
            save_history("memory_playbook", results)
        else:
            raw_output = request.form.get("raw_output", "").strip()
            file = request.files.get("memory_file")
            filename = None

            if file and file.filename:
                 filename = secure_filename(file.filename)
                 # Assuming text based output
                 path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                 file.save(path)
                 with open(path, "r", errors="ignore") as f:
                     raw_output = f.read()

            if not raw_output:
                flash("Please paste memory analysis output or upload a file.", "warning")
                return redirect(request.url)

            parsed_output = analyze_memory_output(raw_output)
            events = parsed_output.get("events", [])
            sigma_matches = sigma_engine.correlate_events(events)
            results = {
                "mode": "triage",
                "events": events,
                "summary": parsed_output.get("summary"),
            }
            LAST_RESULTS["memory"] = results
            ship_events(events, "memory")
            save_history("memory_triage", results, filename)

    return render_template(
        "memory_helper.html",
        playbook=playbook,
        parsed_output=parsed_output,
        sigma_matches=sigma_matches,
    )

@app.route("/history")
@login_required
def history():
    analyses = AnalysisHistory.query.order_by(AnalysisHistory.timestamp.desc()).all()
    return render_template("history.html", analyses=analyses)

@app.route("/history/view/<int:id>")
@login_required
def view_history(id):
    analysis = AnalysisHistory.query.get_or_404(id)
    results = analysis.get_results()

    # Render appropriate template based on type
    if analysis.type == "logs":
         return render_template("log_analyzer.html", results=results, sigma_matches=sigma_engine.correlate_events(results.get("events", [])), historical=True)
    elif analysis.type == "network":
         return render_template("network_analyzer.html", results=results, sigma_matches=sigma_engine.correlate_events(results.get("events", [])), historical=True)
    elif "memory" in analysis.type:
         playbook = results if analysis.type == "memory_playbook" else None
         parsed_output = results if analysis.type == "memory_triage" else None
         # Fix format for template if needed
         if analysis.type == "memory_playbook":
             parsed_output = None
         elif analysis.type == "memory_triage":
             playbook = None

         return render_template("memory_helper.html", playbook=playbook, parsed_output=parsed_output, sigma_matches=sigma_engine.correlate_events(results.get("events", [])), historical=True)

    flash("Unknown analysis type", "danger")
    return redirect(url_for('history'))

@app.route("/reset_data")
@login_required
@admin_required
def reset_data():
    try:
        # Delete all history
        AnalysisHistory.query.delete()
        db.session.commit()
        flash("All analysis history has been reset.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error resetting data: {e}", "danger")
    return redirect(url_for('dashboard'))

# -------- Export helpers --------

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
        flash("No memory helper results to export yet.", "warning")
        return redirect(url_for("memory_helper"))

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
    elif fmt == "csv":
        # generic flatten for memory events
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
    return redirect(url_for("memory_helper"))


@app.route("/export/report")
@login_required
def export_report_bundle():
    """Export configuration + last analysis results as a single ZIP bundle."""
    buf = io.BytesIO()
    now = datetime.utcnow().isoformat() + "Z"

    # Collect env config
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

    # Collect results
    logs = LAST_RESULTS.get("logs")
    network = LAST_RESULTS.get("network")
    memory = LAST_RESULTS.get("memory")

    # Collect Sigma rule metadata
    rules_meta = []
    try:
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
    except Exception:
        pass

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "config/env.json",
            json.dumps(config, indent=2, default=str),
        )
        zf.writestr(
            "sigma/rules.json",
            json.dumps(rules_meta, indent=2, default=str),
        )
        if logs:
            zf.writestr(
                "results/logs.json",
                json.dumps(logs, indent=2, default=str),
            )
        if network:
            zf.writestr(
                "results/network.json",
                json.dumps(network, indent=2, default=str),
            )
        if memory:
            zf.writestr(
                "results/memory.json",
                json.dumps(memory, indent=2, default=str),
            )
        summary = {
            "generated_at_utc": now,
            "has_logs": bool(logs),
            "has_network": bool(network),
            "has_memory": bool(memory),
            "rule_count": len(rules_meta),
        }
        zf.writestr(
            "summary.json",
            json.dumps(summary, indent=2, default=str),
        )
        zf.writestr(
            "README_report.txt",
            "Forensis Report Bundle\n\n"
            "This archive contains:\n"
            "- config/env.json : environment-related configuration\n"
            "- sigma/rules.json : loaded Sigma rule metadata\n"
            "- results/*.json : last analysis results (if available)\n"
            "- summary.json : quick overview\n",
        )

    buf.seek(0)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = "attachment; filename=forensis_report_bundle.zip"
    return resp


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Ensure default admin exists
        admin_user = os.getenv("FORENSIS_ADMIN_USER", "admin")
        if not User.query.filter_by(username=admin_user).first():
            print(f"Creating default admin user: {admin_user}")
            admin_pass = os.getenv("FORENSIS_ADMIN_PASSWORD", "forensis123")
            hashed_pw = bcrypt.generate_password_hash(admin_pass).decode('utf-8')

            # Create default group
            default_group = Group.query.filter_by(name='Administrators').first()
            if not default_group:
                default_group = Group(name='Administrators')
                db.session.add(default_group)
                db.session.commit()

            new_admin = User(username=admin_user, password_hash=hashed_pw, role='admin', group_id=default_group.id)
            db.session.add(new_admin)
            db.session.commit()

    app.run(host="0.0.0.0", port=5000, debug=True)
