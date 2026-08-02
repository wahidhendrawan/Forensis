"""
Pytest fixtures for Forensis test suite.
Sets up Flask test client, temporary database, and test users.
"""
import os
import sys
import tempfile
import types
from types import SimpleNamespace

import pytest
from flask_bcrypt import Bcrypt

# Set test environment before importing the module-level Flask application.
os.environ["FORENSIS_DB_URI"] = "sqlite:///:memory:"
os.environ["FORENSIS_BOOTSTRAP_DB"] = "0"

# python-magic requires a host libmagic installation. MIME detection is not under
# test here, so provide a deterministic substitute when the native library is absent.
try:
    import magic  # noqa: F401
except ImportError:
    sys.modules.pop("magic", None)
    magic_stub = types.ModuleType("magic")
    magic_stub.from_file = lambda _path, mime=False: (
        "application/octet-stream" if mime else "data"
    )
    sys.modules["magic"] = magic_stub

# SigmaEngine attempts a baseline download while app.py is imported. Unit tests use
# the repository's local rules and must not depend on network availability.
import requests

_real_requests_get = requests.get
requests.get = lambda *_args, **_kwargs: SimpleNamespace(
    status_code=503, content=b"", text=""
)
try:
    from app import app as _app
finally:
    requests.get = _real_requests_get

from forensis.models import db, User, Group


@pytest.fixture(scope="session")
def app():
    """Create and configure Flask app for testing."""
    _app.config["TESTING"] = True
    _app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    _app.config["WTF_CSRF_ENABLED"] = False
    _app.config["SECRET_KEY"] = "test-secret-key"
    return _app


@pytest.fixture
def client(app):
    """Create Flask test client."""
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def runner(app):
    """Create CLI test runner."""
    return app.test_cli_runner()


@pytest.fixture
def admin_user(app):
    """Create a test admin user. Returns username string to avoid detached-state issues."""
    with app.app_context():
        bcrypt = Bcrypt(app)
        admin_group = Group(name="Administrators")
        db.session.add(admin_group)
        db.session.commit()
        
        user = User(
            username="admin_test",
            password_hash=bcrypt.generate_password_hash("password123").decode("utf-8"),
            role="admin",
            group_id=admin_group.id,
            mfa_enabled=False,
        )
        db.session.add(user)
        db.session.commit()
        return "admin_test"


@pytest.fixture
def analyst_user(app):
    """Create a test analyst user. Returns username string to avoid detached-state issues."""
    with app.app_context():
        bcrypt = Bcrypt(app)
        analyst_group = Group(name="Analysts")
        db.session.add(analyst_group)
        db.session.commit()
        
        user = User(
            username="analyst_test",
            password_hash=bcrypt.generate_password_hash("analyst_pass").decode("utf-8"),
            role="analyst",
            group_id=analyst_group.id,
            mfa_enabled=False,
        )
        db.session.add(user)
        db.session.commit()
        return "analyst_test"


@pytest.fixture
def admin_client(client, admin_user):
    """Test client logged in as admin."""
    # Perform actual login to properly set up Flask-Login session
    client.post(
        "/login",
        data={"username": admin_user, "password": "password123"},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def analyst_client(client, analyst_user):
    """Test client logged in as analyst."""
    # Perform actual login to properly set up Flask-Login session
    client.post(
        "/login",
        data={"username": analyst_user, "password": "analyst_pass"},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def temp_upload_dir(app):
    """Create temporary directory for file uploads."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original = app.config.get("UPLOAD_FOLDER")
        app.config["UPLOAD_FOLDER"] = tmpdir
        yield tmpdir
        app.config["UPLOAD_FOLDER"] = original
