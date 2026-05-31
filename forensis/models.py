from datetime import datetime
import json

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

JOB_STATES = {"queued", "running", "succeeded", "failed", "partial"}
JOB_STAGES = {
    "queued",
    "artifact_received",
    "parse",
    "enrich",
    "rule_match",
    "scoring",
    "persist",
    "post_rule_match",
    "complete",
    "failed",
}


class JsonTextMixin:
    @staticmethod
    def _loads(text_value, fallback):
        if not text_value:
            return fallback
        try:
            return json.loads(text_value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return fallback

    @staticmethod
    def _dumps(value):
        try:
            return json.dumps(value, default=str)
        except Exception:
            return json.dumps({})


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="analyst")
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=True)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)

    group = db.relationship("Group", backref="users")

    def __repr__(self):
        return f"<User {self.username}>"


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"<Group {self.name}>"


class AnalysisHistory(JsonTextMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    results_json = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(255), nullable=True)

    user = db.relationship("User", backref="analyses")

    def get_results(self):
        return self._loads(self.results_json, {})

    def set_results(self, value):
        self.results_json = self._dumps(value)


class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<SystemSetting {self.key}>"


class Case(JsonTextMixin, db.Model):
    __tablename__ = "dfir_case"

    id = db.Column(db.Integer, primary_key=True)
    case_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="open", index=True)
    severity = db.Column(db.String(16), nullable=False, default="medium", index=True)
    owner_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    schema_version = db.Column(db.String(32), nullable=False, default="forensis-ecs-0.1")
    metadata_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = db.relationship("User", foreign_keys=[owner_user_id], backref="cases_owned")

    def get_metadata(self):
        return self._loads(self.metadata_json, {})

    def set_metadata(self, value):
        self.metadata_json = self._dumps(value)

    def __repr__(self):
        return f"<Case {self.case_key}>"


class Artifact(JsonTextMixin, db.Model):
    __tablename__ = "artifact"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("dfir_case.id"), nullable=True, index=True)
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    artifact_type = db.Column(db.String(32), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    storage_backend = db.Column(db.String(32), nullable=False, default="local")
    storage_path = db.Column(db.String(1024), nullable=True)
    mime_type = db.Column(db.String(255), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=True)
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    metadata_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    case = db.relationship("Case", backref="artifacts")
    uploaded_by = db.relationship("User", foreign_keys=[uploaded_by_user_id], backref="artifacts_uploaded")

    def get_metadata(self):
        return self._loads(self.metadata_json, {})

    def set_metadata(self, value):
        self.metadata_json = self._dumps(value)


class AnalysisJob(JsonTextMixin, db.Model):
    __tablename__ = "analysis_job"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("dfir_case.id"), nullable=True, index=True)
    artifact_id = db.Column(db.Integer, db.ForeignKey("artifact.id"), nullable=True, index=True)
    history_id = db.Column(db.Integer, db.ForeignKey("analysis_history.id"), nullable=True, index=True)
    submitted_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    job_type = db.Column(db.String(32), nullable=False, index=True)
    queue_name = db.Column(db.String(64), nullable=False, default="default")
    state = db.Column(db.String(16), nullable=False, default="queued", index=True)
    stage = db.Column(db.String(32), nullable=False, default="queued", index=True)
    progress = db.Column(db.Integer, nullable=False, default=0)
    task_id = db.Column(db.String(128), unique=True, nullable=True, index=True)
    error_message = db.Column(db.Text, nullable=True)
    result_summary_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    case = db.relationship("Case", backref="jobs")
    artifact = db.relationship("Artifact", backref="jobs")
    history = db.relationship("AnalysisHistory", backref="jobs")
    submitted_by = db.relationship("User", foreign_keys=[submitted_by_user_id], backref="analysis_jobs")

    def get_result_summary(self):
        return self._loads(self.result_summary_json, {})

    def set_result_summary(self, value):
        self.result_summary_json = self._dumps(value)

    def as_status(self):
        return {
            "id": self.id,
            "task_id": self.task_id,
            "job_type": self.job_type,
            "state": self.state,
            "stage": self.stage,
            "progress": int(self.progress or 0),
            "history_id": self.history_id,
            "error_message": self.error_message or "",
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


class Finding(JsonTextMixin, db.Model):
    __tablename__ = "finding"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("dfir_case.id"), nullable=True, index=True)
    analysis_job_id = db.Column(db.Integer, db.ForeignKey("analysis_job.id"), nullable=True, index=True)
    source_type = db.Column(db.String(32), nullable=False, index=True)
    category = db.Column(db.String(64), nullable=True, index=True)
    severity = db.Column(db.String(16), nullable=False, default="low", index=True)
    indicator = db.Column(db.String(255), nullable=True, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    score = db.Column(db.Integer, nullable=False, default=0)
    event_ref = db.Column(db.String(255), nullable=True)
    raw_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    case = db.relationship("Case", backref="findings")
    job = db.relationship("AnalysisJob", backref="findings")

    def get_raw(self):
        return self._loads(self.raw_json, {})

    def set_raw(self, value):
        self.raw_json = self._dumps(value)


class RuleMatch(JsonTextMixin, db.Model):
    __tablename__ = "rule_match"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("dfir_case.id"), nullable=True, index=True)
    analysis_job_id = db.Column(db.Integer, db.ForeignKey("analysis_job.id"), nullable=True, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id"), nullable=True, index=True)
    rule_engine = db.Column(db.String(32), nullable=False, default="sigma", index=True)
    rule_id = db.Column(db.String(255), nullable=True, index=True)
    rule_title = db.Column(db.String(255), nullable=False)
    rule_level = db.Column(db.String(32), nullable=True)
    event_index = db.Column(db.Integer, nullable=True)
    match_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    case = db.relationship("Case", backref="rule_matches")
    job = db.relationship("AnalysisJob", backref="rule_matches")
    finding = db.relationship("Finding", backref="rule_matches")

    def get_match(self):
        return self._loads(self.match_json, {})

    def set_match(self, value):
        self.match_json = self._dumps(value)


class TimelineEvent(JsonTextMixin, db.Model):
    __tablename__ = "timeline_event"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("dfir_case.id"), nullable=True, index=True)
    analysis_job_id = db.Column(db.Integer, db.ForeignKey("analysis_job.id"), nullable=True, index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    source = db.Column(db.String(64), nullable=True, index=True)
    title = db.Column(db.String(255), nullable=False)
    event_ts = db.Column(db.DateTime, nullable=True, index=True)
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    case = db.relationship("Case", backref="timeline_events")
    job = db.relationship("AnalysisJob", backref="timeline_events")

    def get_details(self):
        return self._loads(self.details_json, {})

    def set_details(self, value):
        self.details_json = self._dumps(value)
