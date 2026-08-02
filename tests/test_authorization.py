"""
Test suite for authorization and access control.
Covers admin-only routes, cross-user history isolation, and role gating.
"""
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
