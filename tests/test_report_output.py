"""
Test suite for report/output rendering.
Verifies HTML output correctly escapes user-controlled fields (no injection).
"""
import pytest
from forensis.models import AnalysisHistory, User, db


class TestHistoryOutputEscaping:
    """Analysis history page must escape user-controlled data."""

    def test_history_filename_is_escaped(self, app, admin_client, admin_user):
        """A filename containing HTML/script tags must not render unescaped."""
        malicious_filename = '<script>alert("xss")</script>.log'
        with app.app_context():
            admin = User.query.filter_by(username=admin_user).one()
            history = AnalysisHistory(
                type="logs", user_id=admin.id, filename=malicious_filename
            )
            history.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(history)
            db.session.commit()

        resp = admin_client.get("/history")
        assert resp.status_code == 200
        # Raw script tag must not appear unescaped in the response
        assert b'<script>alert("xss")</script>' not in resp.data
        # Jinja auto-escaping should render the escaped entities instead
        assert b"&lt;script&gt;" in resp.data


class TestLogAnalyzerOutputEscaping:
    """Log analyzer results view must escape event content."""

    def test_anomaly_reason_and_event_data_escaped(self, app, admin_client, admin_user):
        """Anomaly/event fields containing HTML must be escaped in output."""
        with app.app_context():
            results = {
                "summary": {
                    "total_lines": 1,
                    "parsed_events": 1,
                    "anomaly_count": 1,
                    "top_sources": [],
                    "top_status": [],
                    "threat_score": 10,
                    "malicious_pattern_hits": 1,
                    "severity_counts": {"high": 1},
                },
                "events": [
                    {
                        "source": "apache",
                        "raw": '<img src=x onerror=alert(1)>',
                        "message": '<b>bold-injected</b>',
                        "timestamp": "2026-05-30T12:00:00",
                    }
                ],
                "anomalies": [
                    {
                        "reason": '<script>document.location="http://evil.example"</script>',
                        "severity": "high",
                        "category": "injection",
                        "indicator": "xss_payload",
                        "event": {
                            "raw": '<svg onload=alert(1)>',
                            "message": "payload",
                            "source": "apache",
                        },
                    }
                ],
            }
            admin = User.query.filter_by(username=admin_user).one()
            history = AnalysisHistory(
                type="logs", user_id=admin.id, filename="attack.log"
            )
            history.set_results(results)
            db.session.add(history)
            db.session.commit()
            history_id = history.id

        resp = admin_client.get(f"/history/view/{history_id}")
        assert resp.status_code == 200

        # None of the raw injection payloads should appear unescaped
        assert b'<script>document.location' not in resp.data
        assert b"<img src=x onerror=alert(1)>" not in resp.data
        assert b"<svg onload=alert(1)>" not in resp.data
        assert b"<b>bold-injected</b>" not in resp.data

        # Escaped versions should be present instead
        assert b"&lt;script&gt;" in resp.data or b"&lt;svg" in resp.data


class TestExportReportBundle:
    """Export endpoints should require authentication and produce valid output."""

    def test_export_report_requires_login(self, client):
        """Export report bundle should require authentication."""
        resp = client.get("/export/report", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_export_report_returns_zip(self, admin_client):
        """Authenticated export should return a zip archive."""
        resp = admin_client.get("/export/report")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/zip"
        assert resp.data[:2] == b"PK"  # ZIP file magic bytes


class TestCSRFProtection:
    """State-changing POST routes must validate CSRF tokens."""

    def test_create_user_without_csrf_rejected(self, admin_client):
        """POST without csrf_token should be rejected (flash + redirect)."""
        resp = admin_client.post(
            "/manage_users/create",
            data={"username": "csrftest", "password": "password1234", "role": "analyst"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with admin_client.application.app_context():
            from forensis.models import User
            assert User.query.filter_by(username="csrftest").first() is None

    def test_delete_history_without_csrf_rejected(self, app, admin_client, admin_user):
        """Deleting history without CSRF token should not delete the record."""
        with app.app_context():
            admin = User.query.filter_by(username=admin_user).one()
            history = AnalysisHistory(
                type="logs", user_id=admin.id, filename="keepme.log"
            )
            history.set_results({"summary": {}, "events": [], "anomalies": []})
            db.session.add(history)
            db.session.commit()
            history_id = history.id

        resp = admin_client.post(f"/history/delete/{history_id}", follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            still_there = db.session.get(AnalysisHistory, history_id)
            assert still_there is not None
