import logging
from typing import Any, Dict, Optional

from flask import has_request_context, request
from flask_login import current_user

from .models import AuditLog, DEFAULT_TENANT_ID, db

logger = logging.getLogger(__name__)

_SENSITIVE_MARKERS = (
    "password",
    "passwd",
    "secret",
    "otp",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
)
_MAX_STRING_LENGTH = 2000


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower().replace("-", "_")
    return any(marker in normalized for marker in _SENSITIVE_MARKERS)


def _sanitize(value: Any, key: Any = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _sanitize(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:_MAX_STRING_LENGTH]


def audit_log(
    action: str,
    status: str,
    *,
    actor_sub: Optional[str] = None,
    actor_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """Persist a sanitized audit event without breaking the caller on failure."""
    try:
        ip_address = None
        user_agent = None
        if has_request_context():
            ip_address = (request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip() or request.remote_addr)
            user_agent = request.user_agent.string[:2000]
            if current_user.is_authenticated:
                actor_sub = actor_sub or current_user.username
                actor_email = actor_email or getattr(current_user, "email", None)
                tenant_id = tenant_id or getattr(current_user, "tenant_id", None)

        entry = AuditLog(
            actor_sub=str(actor_sub or "anonymous")[:255],
            actor_email=str(actor_email)[:255] if actor_email else None,
            tenant_id=str(tenant_id or DEFAULT_TENANT_ID)[:64],
            action=str(action or "unknown")[:100],
            resource_type=str(resource_type)[:50] if resource_type else None,
            resource_id=str(resource_id)[:255] if resource_id is not None else None,
            status=str(status or "unknown")[:20],
            ip_address=str(ip_address)[:45] if ip_address else None,
            user_agent=user_agent,
            metadata_json=_sanitize(metadata or {}),
        )
        db.session.add(entry)
        db.session.commit()
        return True
    except Exception:
        logger.exception("Failed to persist audit event action=%s", action)
        try:
            db.session.rollback()
        except Exception:
            logger.exception("Failed to roll back audit transaction")
        return False
