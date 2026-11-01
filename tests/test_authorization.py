"""
Test suite for authorization and access control.
Covers admin-only routes, cross-user history isolation, and role gating.
"""
import io
import zipfile

import pytest
from forensis.models import User, Group, AnalysisHistory, db


class TestAdminOnlyRoutes:
    """Admin-only routes should reject non-admin users."""

    def test_create_user_requires_admin(self, app, client, analyst_user):
        """Analyst users cannot create new users."""
        with app.app_context():
            user = User.query.filter_by(username=analyst_user).one()
            with client.session_transaction() as sess:
                sess["user_id"] = user.id

        resp = client.post(
            "/manage_users/create",
            data={"username": "newuser", "password": "newpass1234", "role": "analyst"},
            follow_redirects=True,
        )
        # Non-admin gets redirected to dashboard with access denied
        assert resp.status_code == 200
        # Verify user was NOT created
        with client.application.app_context():
            new_user = User.query.filter_by(username="newuser").first()
            assert new_user is None

    def test_delete_user_requires_admin(self, app, client, analyst_user, admin_user):
        """Analyst users cannot delete other users."""
        with app.app_context():
            analyst = User.query.filter_by(username=analyst_user).one()
            admin = User.query.filter_by(username=admin_user).one()
            admin_id = admin.id
            with client.session_transaction() as sess:
                sess["user_id"] = analyst.id

        resp = client.post(
            f"/manage_users/delete/{admin_id}", follow_redirects=True
        )
        assert resp.status_code == 200
        with client.application.app_context():
            still_exists = User.query.filter_by(username="admin_test").first()
            assert still_exists is not None

    def test_add_group_requires_admin(self, app, client, analyst_user):
        """Only admins can add groups."""
        with app.app_context():
            user = User.query.filter_by(username=analyst_user).one()
            with client.session_transaction() as sess:
                sess["user_id"] = user.id

        resp = client.post(
            "/manage_groups/create", data={"name": "SneakyGroup"}, follow_redirects=True
        )
        assert resp.status_code == 200
        with client.application.app_context():
            grp = Group.query.filter_by(name="SneakyGroup").first()
            assert grp is None

    def test_reset_data_requires_admin(self, app, client, analyst_user):
        """Only admins can reset analysis data."""
        with app.app_context():
            user = User.query.filter_by(username=analyst_user).one()
            with client.session_transaction() as sess:
                sess["user_id"] = user.id
        resp = client.post("/reset_data", follow_redirects=True)
        assert resp.status_code == 200

    def test_otx_integration_requires_admin(self, app, client, analyst_user):
        """Only admins can update OTX integration."""
        with app.app_context():
            user = User.query.filter_by(username=analyst_user).one()
            with client.session_transaction() as sess:
                sess["user_id"] = user.id
        resp = client.post(
            "/manage_integrations/otx",
            data={"action": "save", "otx_api_key": "A" * 32},
            follow_redirects=True,
        )
        assert resp.status_code == 200


class TestHistoryIsolation:
    """Non-admin users should not see other users' history via API."""

    def test_api_history_admin_sees_all(self, app, admin_client, admin_user):
        """Admin should see all users' analyses."""
        with app.app_context():
            admin = User.query.filter_by(username=admin_user).one()
            # Create histories for two different user IDs
            h1 = AnalysisHistory(type="logs", user_id=admin.id, filename="admin.log")
            h1.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(h1)

            other_user = User(
                username="other",
                password_hash="x",
                role="analyst",
                mfa_enabled=False,
            )
            db.session.add(other_user)
            db.session.commit()

            h2 = AnalysisHistory(type="logs", user_id=other_user.id, filename="other.log")
            h2.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(h2)
            db.session.commit()

        resp = admin_client.get("/api/v1/history")
        assert resp.status_code == 200
        data = resp.get_json()
        filenames = [item["filename"] for item in data["items"]]
        assert "admin.log" in filenames
        assert "other.log" in filenames

    def test_api_history_analyst_only_own(self, app, client, analyst_user):
        """Analyst should only see their own analyses via API."""
        # Log in as analyst first
        client.post(
            "/login",
            data={"username": analyst_user, "password": "analyst_pass"},
            follow_redirects=True,
        )

        with app.app_context():
            analyst = User.query.filter_by(username=analyst_user).one()
            analyst_id = analyst.id

            other = User(
                username="another_analyst",
                password_hash="x",
                role="analyst",
                mfa_enabled=False,
            )
            db.session.add(other)
            db.session.commit()

            h1 = AnalysisHistory(
                type="logs", user_id=analyst_id, filename="mine.log"
            )
            h1.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(h1)

            h2 = AnalysisHistory(
                type="logs", user_id=other.id, filename="theirs.log"
            )
            h2.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(h2)
            db.session.commit()

        resp = client.get("/api/v1/history")
        assert resp.status_code == 200
        data = resp.get_json()
        filenames = [item["filename"] for item in data["items"]]
        assert "mine.log" in filenames
        assert "theirs.log" not in filenames

    def test_view_history_denies_other_users_record(self, app, client, analyst_user):
        """Analyst should not view another user's analysis detail."""
        # Log in as analyst first
        client.post(
            "/login",
            data={"username": analyst_user, "password": "analyst_pass"},
            follow_redirects=True,
        )

        with app.app_context():
            other = User(
                username="third_party",
                password_hash="x",
                role="analyst",
                mfa_enabled=False,
            )
            db.session.add(other)
            db.session.commit()
            target = AnalysisHistory(
                type="logs", user_id=other.id, filename="secret.log"
            )
            target.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(target)
            db.session.commit()
            target_id = target.id

        resp = client.get(f"/history/view/{target_id}", follow_redirects=False)
        # Non-admin viewing someone else's record must be redirected to /history
        assert resp.status_code in (302, 303)
        assert "/history" in resp.headers.get("Location", "")


class TestAPIAuthentication:
    """API v1 auth endpoints and protection."""

    def test_api_auth_me_requires_login(self, client):
        """/api/v1/auth/me should require login (Flask-Login redirects)."""
        resp = client.get("/api/v1/auth/me")
        # Flask-Login redirects unauthenticated users to login page
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_api_auth_me_returns_user(self, admin_client):
        """/api/v1/auth/me returns authenticated user info."""
        resp = admin_client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["username"] == "admin_test"
        assert data["role"] == "admin"

    def test_api_login_bad_credentials(self, client):
        """API login rejects invalid credentials."""
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "wrong"},
        )
        assert resp.status_code == 401

    def test_api_dashboard_requires_login(self, client):
        """API dashboard endpoint should require login (Flask-Login redirects)."""
        resp = client.get("/api/v1/dashboard")
        # Flask-Login redirects unauthenticated users
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_api_health_is_public(self, client):
        """/api/v1/health should be public."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"


def _add_user(app, username, role, tenant_id, password="pw-123456"):
    from flask_bcrypt import Bcrypt

    with app.app_context():
        user = User(
            username=username,
            password_hash=Bcrypt(app).generate_password_hash(password).decode("utf-8"),
            tenant_id=tenant_id,
            mfa_enabled=False,
        )
        user.set_roles([role])
        db.session.add(user)
        db.session.commit()
        return user.id


def _login(client, username, password="pw-123456"):
    client.post("/login", data={"username": username, "password": password})
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "tok"


def _add_history(app, user_id, tenant_id, marker, type_="logs"):
    with app.app_context():
        h = AnalysisHistory(type=type_, user_id=user_id, tenant_id=tenant_id, filename=f"{marker}.log")
        h.set_results({"summary": {"marker": marker}, "events": [{"message": marker}], "anomalies": []})
        db.session.add(h)
        db.session.commit()
        return h.id


class TestTenantScopedAdminActions:
    """Tenant admins must not affect other tenants."""

    def test_reset_data_purges_only_own_tenant(self, app, client):
        admin_id = _add_user(app, "admin_a", "admin", "tenant_a")
        own = _add_history(app, admin_id, "tenant_a", "own")
        other = _add_history(app, admin_id, "tenant_b", "other")
        _login(client, "admin_a")

        client.post("/reset_data", data={"csrf_token": "tok"})

        with app.app_context():
            assert db.session.get(AnalysisHistory, own) is None
            assert db.session.get(AnalysisHistory, other) is not None

    def test_super_admin_reset_purges_all_tenants(self, app, client):
        root_id = _add_user(app, "root", "super_admin", "tenant_a")
        _add_history(app, root_id, "tenant_a", "a")
        _add_history(app, root_id, "tenant_b", "b")
        _login(client, "root")

        client.post("/reset_data", data={"csrf_token": "tok"})

        with app.app_context():
            assert AnalysisHistory.query.count() == 0

    def test_reset_user_mfa_cross_tenant_denied(self, app, client):
        _add_user(app, "admin_a", "admin", "tenant_a")
        victim_id = _add_user(app, "victim_b", "analyst", "tenant_b")
        with app.app_context():
            victim = db.session.get(User, victim_id)
            victim.mfa_enabled, victim.mfa_secret = True, "JBSWY3DPEHPK3PXP"
            db.session.commit()
        _login(client, "admin_a")

        client.post(f"/manage_users/mfa/reset/{victim_id}", data={"csrf_token": "tok"})

        with app.app_context():
            assert db.session.get(User, victim_id).mfa_enabled is True

    def test_reset_user_mfa_same_tenant_allowed(self, app, client):
        _add_user(app, "admin_a", "admin", "tenant_a")
        target_id = _add_user(app, "analyst_a", "analyst", "tenant_a")
        with app.app_context():
            target = db.session.get(User, target_id)
            target.mfa_enabled, target.mfa_secret = True, "JBSWY3DPEHPK3PXP"
            db.session.commit()
        _login(client, "admin_a")

        client.post(f"/manage_users/mfa/reset/{target_id}", data={"csrf_token": "tok"})

        with app.app_context():
            assert db.session.get(User, target_id).mfa_enabled is False


class TestExportScoping:
    """Exports are loaded by history id with the history views' tenant/owner scope."""

    def test_owner_exports_own_analysis(self, app, client):
        uid = _add_user(app, "analyst_a", "analyst", "tenant_a")
        hid = _add_history(app, uid, "tenant_a", "mine-123")
        _login(client, "analyst_a")

        for fmt in ("json", "csv"):
            resp = client.get(f"/export/logs/{hid}/{fmt}")
            assert resp.status_code == 200
            assert b"mine-123" in resp.data

    def test_export_other_tenant_denied(self, app, client):
        _add_user(app, "admin_a", "admin", "tenant_a")
        victim_id = _add_user(app, "analyst_b", "analyst", "tenant_b")
        hid = _add_history(app, victim_id, "tenant_b", "secret-b")
        _login(client, "admin_a")

        resp = client.get(f"/export/logs/{hid}/json")
        assert resp.status_code == 302
        assert b"secret-b" not in resp.data

    def test_export_other_analyst_same_tenant_denied(self, app, client):
        _add_user(app, "analyst_a", "analyst", "tenant_a")
        other_id = _add_user(app, "analyst_a2", "analyst", "tenant_a")
        hid = _add_history(app, other_id, "tenant_a", "secret-a2", type_="memory_triage")
        _login(client, "analyst_a")

        resp = client.get(f"/export/memory/{hid}/json")
        assert resp.status_code == 302
        assert b"secret-a2" not in resp.data

    def test_viewing_history_does_not_leak_into_other_users_export(self, app, client):
        """The old process-global LAST_RESULTS handed one user's last view to everyone."""
        victim_id = _add_user(app, "admin_b", "admin", "tenant_b")
        hid = _add_history(app, victim_id, "tenant_b", "secret-b")
        _add_user(app, "admin_a", "admin", "tenant_a")

        _login(client, "admin_b")
        assert client.get(f"/history/view/{hid}").status_code == 200
        client.get("/logout")
        _login(client, "admin_a")

        resp = client.get("/export/report")
        assert resp.status_code == 200
        with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
            assert "results/logs.json" not in zf.namelist()
            assert all(b"secret-b" not in zf.read(n) for n in zf.namelist())

    def test_report_bundle_has_own_results_and_no_backend_urls(self, app, client, monkeypatch):
        monkeypatch.setenv("FORENSIS_OPENSEARCH_URL", "http://internal-opensearch:9200")
        uid = _add_user(app, "admin_a", "admin", "tenant_a")
        _add_history(app, uid, "tenant_a", "own-a")
        _login(client, "admin_a")

        resp = client.get("/export/report")
        with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
            names = zf.namelist()
            blob = b"".join(zf.read(n) for n in names)
        assert "config/env.json" not in names
        assert b"own-a" in blob
        assert b"internal-opensearch" not in blob


class TestSigmaManagementAdminOnly:
    """Remote Sigma import changes rules for every tenant, so analysts may not trigger it."""

    def test_analyst_cannot_sync_or_reload_rules(self, app, client, monkeypatch):
        import app as app_module

        calls = []
        monkeypatch.setattr(app_module.sigma_engine, "sync_from_urls", lambda urls: calls.append(urls) or 0)
        monkeypatch.setattr(app_module.sigma_engine, "reload_rules", lambda: calls.append("reload"))
        _add_user(app, "analyst_a", "analyst", "tenant_a")
        _login(client, "analyst_a")

        client.post("/sigma/sync", data={"csrf_token": "tok", "sigma_urls": "https://example.org/r.yml"})
        client.post("/sigma/refresh", data={"csrf_token": "tok"})

        assert calls == []
