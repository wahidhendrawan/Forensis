"""REST API v1 blueprint for Forensis SPA frontend."""

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required, login_user, logout_user

from forensis.analyzers.correlation_engine import correlate_recent_analyses
from forensis.audit import audit_log
from forensis.models import AnalysisHistory, User
from forensis.services.analytics_service import clickhouse_overview, history_overview_fallback

api = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _auth_payload(user):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "roles": user.get_roles(),
        "tenant_id": user.tenant_id,
        "mfa_enabled": user.mfa_enabled,
    }


def _tenant_history_query():
    query = AnalysisHistory.query
    if not current_user.has_role("super_admin"):
        query = query.filter(AnalysisHistory.tenant_id == current_user.tenant_id)
    return query


@api.route("/auth/me")
@login_required
def auth_me():
    return jsonify(_auth_payload(current_user))


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
        audit_log(
            "auth.login",
            "failed",
            actor_sub=username or "anonymous",
            tenant_id=user.tenant_id if user else None,
            metadata={"reason": "invalid_credentials"},
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if user.mfa_enabled:
        import pyotp

        if not otp or not pyotp.TOTP(user.mfa_secret).verify(otp):
            audit_log(
                "auth.login",
                "failed",
                actor_sub=user.username,
                actor_email=user.email,
                tenant_id=user.tenant_id,
                metadata={"reason": "mfa_required_or_invalid"},
            )
            return jsonify({"error": "MFA required", "mfa_required": True}), 403

    login_user(user)
    audit_log("auth.login", "succeeded", actor_sub=user.username, actor_email=user.email, tenant_id=user.tenant_id)
    return jsonify(_auth_payload(user))


@api.route("/auth/logout", methods=["POST"])
@login_required
def auth_logout():
    audit_log("auth.logout", "succeeded")
    logout_user()
    return jsonify({"status": "ok"})


@api.route("/dashboard")
@login_required
def dashboard():
    query = _tenant_history_query()
    logs_count = query.filter(AnalysisHistory.type == "logs").count()
    network_count = query.filter(AnalysisHistory.type == "network").count()
    memory_count = query.filter(AnalysisHistory.type.like("memory%")).count()

    recent_analyses = query.order_by(AnalysisHistory.timestamp.desc()).limit(40).all()
    alerts = []
    for analysis in recent_analyses:
        results = analysis.get_results()
        for anomaly in (results.get("anomalies") or [])[:3] if isinstance(results, dict) else []:
            alerts.append(
                {
                    "timestamp": analysis.timestamp.isoformat() if analysis.timestamp else None,
                    "type": analysis.type,
                    "message": anomaly.get("reason", "Unknown"),
                }
            )

    latest_log = query.filter(AnalysisHistory.type == "logs").order_by(AnalysisHistory.timestamp.desc()).first()
    correlation = correlate_recent_analyses(recent_analyses)
    return jsonify(
        {
            "counts": {"logs": logs_count, "network": network_count, "memory": memory_count},
            "recent_alerts": alerts[:20],
            "correlation": {
                "findings": len(correlation.get("findings", [])),
                "severity_counts": correlation.get("severity_counts", {}),
            },
            "latest_log": {
                "id": latest_log.id,
                "filename": latest_log.filename,
                "timestamp": latest_log.timestamp.isoformat() if latest_log.timestamp else None,
            } if latest_log else None,
        }
    )


@api.route("/history")
@login_required
def history():
    limit = max(1, min(request.args.get("limit", 50, type=int) or 50, 200))
    query = _tenant_history_query().order_by(AnalysisHistory.timestamp.desc())
    if not current_user.has_role("admin", "super_admin"):
        query = query.filter(AnalysisHistory.user_id == current_user.id)

    items = [
        {
            "id": analysis.id,
            "type": analysis.type,
            "filename": analysis.filename,
            "timestamp": analysis.timestamp.isoformat() if analysis.timestamp else None,
            "user_id": analysis.user_id,
            "tenant_id": analysis.tenant_id,
        }
        for analysis in query.limit(limit).all()
    ]
    return jsonify({"items": items, "count": len(items)})


@api.route("/analytics/overview")
@login_required
def analytics_overview():
    since_minutes = max(5, min(request.args.get("since_minutes", 1440, type=int) or 1440, 43200))
    tenant_id = None if current_user.has_role("super_admin") else current_user.tenant_id
    data = clickhouse_overview(since_minutes=since_minutes, tenant_id=tenant_id)
    if not data.get("enabled") or data.get("errors"):
        data = history_overview_fallback(current_user=current_user, since_minutes=since_minutes)
    data["since_minutes"] = since_minutes
    return jsonify(data)


@api.route("/health")
def health():
    from forensis.analyzers.sigma_engine import SigmaEngine

    return jsonify(
        {
            "status": "ok",
            "db": "connected",
            "rules": len(SigmaEngine._rules_cache) if hasattr(SigmaEngine, "_rules_cache") else "?",
            "version": "2.0.0",
        }
    )
