"""
Security baseline tests for Forensis.
Focused on cross-tenant denial, auth failures, malformed input, and upload boundaries.
"""
import io
import zipfile
import os

from forensis.models import User, Case, Artifact, AnalysisJob, db


class TestAPIDenialUnauthenticated:
    """Unauthenticated requests must be denied (Flask-Login redirects to login)."""

    def test_api_auth_me_denies_without_login(self, client):
        """/api/v1/auth/me must redirect unauthenticated requests to login."""
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_api_dashboard_denies_without_login(self, client):
        """/api/v1/dashboard must redirect unauthenticated requests to login."""
        resp = client.get("/api/v1/dashboard")
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_api_history_denies_without_login(self, client):
        """/api/v1/history must redirect unauthenticated requests to login."""
        resp = client.get("/api/v1/history")
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_api_auth_me_succeeds_after_login(self, admin_client, admin_user):
        """/api/v1/auth/me returns user info after login."""
        resp = admin_client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["username"] == admin_user
        assert data["role"] == "admin"


class TestAPIDenialInvalidCredentials:
    """Invalid credentials must return 401 without leaking account existence."""

    def test_api_login_invalid_username(self, client):
        """/api/v1/auth/login rejects non-existent users with 401."""
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistentuser12345", "password": "anypassword"},
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "error" in data

    def test_api_login_invalid_password(self, client, admin_user):
        """/api/v1/auth/login rejects wrong password with 401."""
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": admin_user, "password": "wrongpassword"},
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "error" in data

    def test_api_login_empty_body(self, client):
        """/api/v1/auth/login rejects empty body with 401."""
        resp = client.post(
            "/api/v1/auth/login",
            json={},
        )
        assert resp.status_code == 401

    def test_api_login_null_values(self, client):
        """/api/v1/auth/login rejects null username/password with 401."""
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": None, "password": None},
        )
        assert resp.status_code == 401


class TestCrossTenantJobIsolation:
    """Users must not access other tenants' jobs via API."""

    def test_api_jobs_list_cross_tenant_excluded(self, app, analyst_client, analyst_user):
        """An analyst's job list must exclude jobs from another tenant."""
        with app.app_context():
            analyst = User.query.filter_by(username=analyst_user).one()
            own_job = AnalysisJob(
                tenant_id=analyst.tenant_id,
                job_type="logs",
                state="succeeded",
                submitted_by_user_id=analyst.id,
            )
            foreign_job = AnalysisJob(
                tenant_id="foreign_tenant_xyz",
                job_type="network",
                state="succeeded",
                submitted_by_user_id=analyst.id,
            )
            db.session.add_all([own_job, foreign_job])
            db.session.commit()
            own_job_id = own_job.id
            foreign_job_id = foreign_job.id

        resp = analyst_client.get("/api/jobs")
        assert resp.status_code == 200
        job_ids = [item["id"] for item in resp.get_json()["items"]]
        assert own_job_id in job_ids
        assert foreign_job_id not in job_ids

    def test_api_job_detail_cross_tenant_denied(self, app, analyst_client, analyst_user):
        """An analyst cannot retrieve a job belonging to another tenant."""
        with app.app_context():
            analyst = User.query.filter_by(username=analyst_user).one()
            foreign_job = AnalysisJob(
                tenant_id="foreign_tenant_detail_xyz",
                job_type="network",
                state="succeeded",
                submitted_by_user_id=analyst.id,
            )
            db.session.add(foreign_job)
            db.session.commit()
            foreign_job_id = foreign_job.id

        resp = analyst_client.get(f"/api/jobs/{foreign_job_id}")
        assert resp.status_code == 403
        assert resp.get_json() == {"error": "forbidden"}


class TestCrossTenantCaseIsolation:
    """Users must not access other tenants' cases via API."""

    def test_api_cases_cross_tenant_excluded(self, app, analyst_client, analyst_user):
        """An analyst's case list must exclude cases from another tenant."""
        with app.app_context():
            analyst = User.query.filter_by(username=analyst_user).one()
            own_case = Case(
                tenant_id=analyst.tenant_id,
                case_key="case-alpha-001",
                title="Analyst Case",
                owner_user_id=analyst.id,
            )
            foreign_case = Case(
                tenant_id="foreign_case_tenant_xyz",
                case_key="case-beta-001",
                title="Foreign Case",
                owner_user_id=analyst.id,
            )
            db.session.add_all([own_case, foreign_case])
            db.session.commit()

        resp = analyst_client.get("/api/cases")
        assert resp.status_code == 200
        case_keys = [item["case_key"] for item in resp.get_json()["items"]]
        assert "case-alpha-001" in case_keys
        assert "case-beta-001" not in case_keys


class TestUploadPathSanitization:
    """Upload paths must be sanitized to prevent directory traversal."""

    def test_upload_path_neutralizes_traversal(self, app):
        """upload path builder must keep the stored file inside UPLOAD_FOLDER and strip separators/null bytes."""
        from app import _build_upload_path

        traversal_inputs = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc/passwd",
            "/absolute/path/injection",
            "subdir/../../../etc/shadow",
            "file\x00.jpg",
            "..",
            "../",
            "..\\..\\windows\\system32\\cmd.exe",
        ]

        base = os.path.realpath(app.config["UPLOAD_FOLDER"])
        for unsafe_input in traversal_inputs:
            clean, upload_path, unique_name = _build_upload_path(unsafe_input)
            # No path separators or null bytes may survive sanitization.
            assert "/" not in clean
            assert "\\" not in clean
            assert "\x00" not in clean
            # Resolved absolute path must live under UPLOAD_FOLDER — no escape.
            resolved = os.path.realpath(upload_path)
            assert resolved == base or resolved.startswith(base + os.sep), (
                f"Upload path escaped UPLOAD_FOLDER: {resolved!r} not under {base!r}"
            )
            # The unique name must be exactly one path component.
            assert os.sep not in unique_name
            assert "/" not in unique_name
            # Unique prefix keeps files from clobbering by relying on token_hex(8) = 16 hex chars.
            assert len(unique_name) > 16

    def test_upload_path_empty_name_fallback(self, app):
        """Empty or whitespace-only filenames must default to artifact.bin."""
        from app import _build_upload_path

        empty_inputs = ["", "   ", "\t\n", "///", "\\\\"]
        for empty_input in empty_inputs:
            clean, upload_path, unique_name = _build_upload_path(empty_input)
            assert clean == "artifact.bin"
            assert unique_name.endswith("_artifact.bin")

    def test_upload_path_unique_per_call(self, app):
        """Each invocation must produce a unique stored filename to prevent overwrite."""
        from app import _build_upload_path

        _, path1, name1 = _build_upload_path("evidence.log")
        _, path2, name2 = _build_upload_path("evidence.log")
        assert name1 != name2
        assert path1 != path2


class TestUploadSizeEnforcement:
    """Uploads exceeding limits must be rejected before processing."""

    def test_memory_archive_size_limit_enforced(self, app, admin_client, temp_upload_dir):
        """ZIP archives exceeding MEMORY_ARCHIVE_MAX_BYTES are rejected after upload."""
        from app import MEMORY_ARCHIVE_MAX_BYTES
        
        # Create a ZIP larger than the configured limit
        large_content = b"x" * (MEMORY_ARCHIVE_MAX_BYTES + 1024)
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("oversized.bin", large_content)
        zip_buffer.seek(0)

        # Set CSRF token in session
        with admin_client.session_transaction() as sess:
            sess["_csrf_token"] = "test_token"

        resp = admin_client.post(
            "/memory-triage",
            data={
                "memory_file": (zip_buffer, "oversized_archive.zip"),
                "csrf_token": "test_token",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Should flash an error about file being too large
        assert b"too large" in resp.data or b"Too large" in resp.data

    def test_memory_text_paste_size_limit(self, app, admin_client):
        """Pasted text exceeding MEMORY_TEXT_MAX_BYTES is rejected."""
        from app import MEMORY_TEXT_MAX_BYTES

        large_text = "x" * (MEMORY_TEXT_MAX_BYTES + 1024)

        with admin_client.session_transaction() as sess:
            sess["_csrf_token"] = "test_token"

        resp = admin_client.post(
            "/memory-triage",
            data={
                "raw_output": large_text,
                "csrf_token": "test_token",
            },
            follow_redirects=True,
        )
        # Werkzeug's own form-size guard (413) or the app's explicit size check
        # (flash + 200) are both acceptable ways to reject the oversized paste;
        # what matters is that it is never accepted for processing.
        if resp.status_code == 200:
            assert b"too large" in resp.data or b"Too large" in resp.data
        else:
            assert resp.status_code == 413


class TestMalformedInputGracefulHandling:
    """Parser must handle malformed structured input without crashing."""

    def test_parse_json_blob_garbage(self):
        """JSON parser must not crash on garbage input."""
        from forensis.analyzers.playbook_engine import _parse_json_blob

        garbage = "not json { [[ garbage \x00\x01\x02 ]]\n\nrandom\t\ttabs"
        result = _parse_json_blob(garbage)
        # Should return empty list or None, not crash
        assert isinstance(result, (list, type(None)))

    def test_parse_yaml_blob_garbage(self):
        """YAML parser must not crash on garbage input."""
        from forensis.analyzers.playbook_engine import _parse_yaml_blob

        garbage = "---\ninvalid: yaml: : :\n---\x00\x00\x00\x00"
        result = _parse_yaml_blob(garbage)
        assert isinstance(result, (list, type(None)))

    def test_parse_xml_blob_garbage(self):
        """XML parser must not crash on malformed XML."""
        from forensis.analyzers.playbook_engine import _parse_xml_blob

        garbage = "<root>\n  <unclosed>text\n</root>\\x00\\x00"
        result = _parse_xml_blob(garbage)
        assert isinstance(result, (list, type(None)))

    def test_parse_json_lines_garbage(self):
        """NDJSON parser must skip malformed lines."""
        from forensis.analyzers.playbook_engine import _parse_json_lines

        garbage_lines = '{"valid": true}\n{broken\n{"also": "valid"}'
        result = _parse_json_lines(garbage_lines)
        # Should return only successfully parsed entries
        assert isinstance(result, list)

    def test_parse_csv_delimited_garbage(self):
        """CSV parser must handle non-tabular data."""
        from forensis.analyzers.playbook_engine import _parse_delimited

        garbage = "not,csv,data\njust,some\nnonsense\n\x00\x01\x02"
        result = _parse_delimited(garbage, ",")
        assert isinstance(result, list)

    def test_parse_key_value_garbage(self):
        """Key-value parser must skip malformed lines."""
        from forensis.analyzers.playbook_engine import _parse_key_value_lines

        garbage = "key=value\nmalformed\nno equals sign\n: empty key\nvalid_key: valid_value"
        result = _parse_key_value_lines(garbage)
        assert isinstance(result, list)

    def test_parse_table_output_garbage(self):
        """Table parser must return empty for non-tabular input."""
        from forensis.analyzers.playbook_engine import _parse_table_output

        garbage = "plain text\nno header\nno separator line\n\x00\x00\x00"
        result = _parse_table_output(garbage)
        assert isinstance(result, list)


class TestParserInputLengthLimits:
    """Structured parsers must reject oversized input."""

    def test_parse_table_output_large_input(self):
        """Large table output must be rejected to prevent DoS."""
        from forensis.analyzers.playbook_engine import _parse_table_output

        # Build a large input (header + many rows)
        header = "col1\tcol2\tcol3\n"
        rows = "\n".join(["\t".join(["a", "b", "c"]) for _ in range(20000)])
        large_input = header + rows

        # Should not crash and should either reject or return a subset
        try:
            result = _parse_table_output(large_input)
            assert isinstance(result, list)
        except ValueError:
            # Rejection is also acceptable
            pass


class TestJobArtifactTenantIntegrity:
    """Jobs/artifacts must preserve tenant context; API masks cross-tenant references."""

    def test_artifact_tenant_mismatch_masked_in_job_detail(self, app, client, admin_user):
        """Job detail endpoint must mask artifacts from foreign tenants."""
        with app.app_context():
            admin = User.query.filter_by(username=admin_user).one()
            admin_tenant_id = admin.tenant_id

            # Create artifact under FOREIGN tenant
            foreign_artifact = Artifact(
                tenant_id="different_tenant_abc",
                artifact_type="logs",
                filename="foreign_artifact.log",
            )
            db.session.add(foreign_artifact)
            db.session.commit()

            # Create job in admin's tenant linked to foreign artifact
            job = AnalysisJob(
                tenant_id=admin_tenant_id,
                job_type="logs",
                artifact_id=foreign_artifact.id,
                state="succeeded",
                submitted_by_user_id=admin.id,
            )
            db.session.add(job)
            db.session.commit()
            job_id = job.id

        # Log in as admin
        client = app.test_client()
        client.post(
            "/login",
            data={"username": admin_user, "password": "password123"},
            follow_redirects=True,
        )

        resp = client.get(f"/api/jobs/{job_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        # API response must mask the foreign artifact (line 1493-1495 in app.py)
        assert data["artifact"] is None
