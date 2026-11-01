"""Failed-login throttle per client IP, shared across gunicorn workers through Redis."""

import os
import time

import redis
from flask import request

MAX_FAILURES = int(os.getenv("FORENSIS_LOGIN_MAX_FAILURES", "10"))
WINDOW_SECONDS = int(os.getenv("FORENSIS_LOGIN_WINDOW_SECONDS", "300"))
REDIS_URL = os.getenv(
    "FORENSIS_RATELIMIT_REDIS_URL",
    os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
).strip()

# shortcut: per-process fallback when Redis is not configured or down, so the limit is per worker then.
_local = {}
_client = None


def _redis():
    global _client
    if _client is None and REDIS_URL.startswith(("redis://", "rediss://")):
        _client = redis.Redis.from_url(
            REDIS_URL, socket_connect_timeout=1, socket_timeout=1
        )
    return _client


def _key() -> str:
    return f"forensis:login_failures:{request.remote_addr or 'unknown'}"


def is_throttled() -> bool:
    key = _key()
    try:
        if _redis():
            return int(_redis().get(key) or 0) >= MAX_FAILURES
    except redis.RedisError:
        pass
    count, expires = _local.get(key, (0, 0.0))
    return count >= MAX_FAILURES and expires > time.time()


def record_failure():
    key = _key()
    try:
        if _redis():
            # MULTI: start the window only if no counter exists, then count; INCR keeps the TTL.
            pipe = _redis().pipeline()
            pipe.set(key, 0, ex=WINDOW_SECONDS, nx=True)
            pipe.incr(key)
            pipe.execute()
            return
    except redis.RedisError:
        pass
    now = time.time()
    if len(_local) > 10000:
        for stale in [k for k, (_, exp) in _local.items() if exp <= now]:
            del _local[stale]
    count, expires = _local.get(key, (0, 0.0))
    if expires <= now:
        count, expires = 0, now + WINDOW_SECONDS
    _local[key] = (count + 1, expires)
