"""REST API v1 blueprint for Forensis SPA frontend."""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session
from flask_login import login_user, logout_user, login_required, current_user

from forensis.models import (
    db,
    User,
    AnalysisHistory,
    SystemSetting,
)
from forensis.analyzers.correlation_engine import correlate_recent_analyses
from forensis.services.analytics_service import clickhouse_overview, history_overview_fallback

api = Blueprint("api_v1", __name__, url_prefix="/api/v1")


# ── Auth ────────────────────────────────────────────────────────────

@api.route("/auth/me")
@login_required
def auth_me():
    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "mfa_enabled": current_user.mfa_enabled,
    })


@api.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    otp = (data.get("otp") or "").strip()

    user = User.query.filter_by(username=username).first()
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    if user.mfa_enabled:
        import pyotp
        totp = pyotp.TOTP(user.mfa_secret)
        if not otp or not totp.verify(otp):
            return jsonify({"error": "MFA required", "mfa_required": True}), 403

    login_user(user)
    return jsonify({
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
    })


@api.route("/auth/logout", methods=["POST"])
@login_required
def auth_logout():
    logout_user()
    return jsonify({"status": "ok"})


# ── Dashboard ───────────────────────────────────────────────────────

@api.route("/dashboard")
@login_required
def dashboard():
    logs_count = AnalysisHistory.query.filter_by(type="logs").count()
    network_count = AnalysisHistory.query.filter_by(type="network").count()
    memory_count = AnalysisHistory.query.filter(AnalysisHistory.type.like("memory%")).count()

    recent_analyses = AnalysisHistory.query.order_by(
        AnalysisHistory.timestamp.desc()
    ).limit(40).all()

    alerts = []
    for a in recent_analyses:
        res = a.get_results()
        if res and res.get("anomalies"):
            for anomaly in res["anomalies"][:3]:
                alerts.append({
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                    "type": a.type,
                    "message": anomaly.get("reason", "Unknown"),
                })

    correlation = correlate_recent_analyses(recent_analyses)

    latest_log = AnalysisHistory.query.filter_by(type="logs").order_by(
        AnalysisHistory.timestamp.desc()
    ).first()

    return jsonify({
        "counts": {
            "logs": logs_count,
            "network": network_count,
            "memory": memory_count,
        },
        "recent_alerts": alerts[:20],
        "correlation": {
            "findings": len(correlation.get("findings", [])),
            "severity_counts": correlation.get("severity_counts", {}),
        },
        "latest_log": {
            "id": latest_log.id,
            "filename": latest_log.filename,
            "timestamp": latest_log.timestamp.isoformat() if latest_log and latest_log.timestamp else None,
        } if latest_log else None,
    })


# ── History ─────────────────────────────────────────────────────────

@api.route("/history")
@login_required
def history():
    limit = request.args.get("limit", 50, type=int)
    query = AnalysisHistory.query.order_by(AnalysisHistory.timestamp.desc())
    if current_user.role != "admin":
        query = query.filter_by(user_id=current_user.id)
    analyses = query.limit(min(limit, 200)).all()

    items = []
    for a in analyses:
        items.append({
            "id": a.id,
            "type": a.type,
            "filename": a.filename,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "user_id": a.user_id,
        })

    return jsonify({"items": items, "count": len(items)})


# ── Analytics ───────────────────────────────────────────────────────

@api.route("/analytics/overview")
@login_required
def analytics_overview():
    since_minutes = request.args.get("since_minutes", 1440, type=int)
    data = clickhouse_overview(since_minutes=since_minutes)
    if not data.get("enabled") or data.get("errors"):
        data = history_overview_fallback(current_user=current_user, since_minutes=since_minutes)
    data["since_minutes"] = since_minutes
    return jsonify(data)


# ── Health ──────────────────────────────────────────────────────────

@api.route("/health")
def health():
    from forensis.analyzers.sigma_engine import SigmaEngine
    import os
    return jsonify({
        "status": "ok",
        "db": "connected",
        "rules": len(SigmaEngine._rules_cache) if hasattr(SigmaEngine, "_rules_cache") else "?",
        "version": "2.0.0",
    })
