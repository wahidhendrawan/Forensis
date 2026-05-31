from datetime import datetime
import hashlib
import os
import secrets
from typing import Dict, Optional

from forensis.models import (
    db,
    AnalysisJob,
    Artifact,
    Case,
    Finding,
    JOB_STAGES,
    JOB_STATES,
    RuleMatch,
    TimelineEvent,
)


DEFAULT_SCHEMA_VERSION = "forensis-ecs-0.1"
MAX_FINDINGS_PER_JOB = 1500
MAX_RULE_MATCHES_PER_JOB = 3000


def _clamp_progress(progress: Optional[int]) -> int:
    if progress is None:
        return 0
    try:
        value = int(progress)
    except (TypeError, ValueError):
        value = 0
    if value < 0:
        return 0
    if value > 100:
        return 100
    return value


def _build_case_key(prefix: str = "CASE") -> str:
    now = datetime.utcnow().strftime("%Y%m%d")
    suffix = secrets.token_hex(3).upper()
    return f"{prefix}-{now}-{suffix}"


def get_or_create_active_case(user_id: int, analysis_type: str, filename: str = "") -> Case:
    day_tag = datetime.utcnow().strftime("%Y-%m-%d")
    title = f"Auto {str(analysis_type or '').upper()} Investigation {day_tag}"
    existing = (
        Case.query.filter_by(owner_user_id=user_id, status="open")
        .filter(Case.title == title)
        .order_by(Case.id.desc())
        .first()
    )
    if existing:
        return existing

    case = Case(
        case_key=_build_case_key(),
        title=title,
        description=f"Auto-created by artifact submission ({filename or 'manual input'}).",
        status="open",
        severity="medium",
        owner_user_id=user_id,
        schema_version=DEFAULT_SCHEMA_VERSION,
    )
    case.set_metadata({"analysis_type": analysis_type, "source": "auto_submission"})
    db.session.add(case)
    db.session.commit()
    return case


def register_artifact(
    *,
    case_id: Optional[int],
    uploaded_by_user_id: Optional[int],
    artifact_type: str,
    filename: str,
    storage_path: Optional[str] = None,
    mime_type: Optional[str] = None,
    storage_backend: str = "local",
    metadata: Optional[Dict] = None,
) -> Artifact:
    size_bytes = None
    sha256 = None
    if storage_path and os.path.isfile(storage_path):
        try:
            size_bytes = os.path.getsize(storage_path)
        except OSError:
            size_bytes = None
        try:
            hasher = hashlib.sha256()
            with open(storage_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
            sha256 = hasher.hexdigest()
        except OSError:
            sha256 = None

    artifact = Artifact(
        case_id=case_id,
        uploaded_by_user_id=uploaded_by_user_id,
        artifact_type=artifact_type,
        filename=filename or "artifact.bin",
        storage_backend=storage_backend,
        storage_path=storage_path,
        mime_type=mime_type,
        size_bytes=size_bytes,
        sha256=sha256,
    )
    artifact.set_metadata(metadata or {})
    db.session.add(artifact)
    db.session.commit()
    return artifact


def create_analysis_job(
    *,
    job_type: str,
    submitted_by_user_id: Optional[int],
    case_id: Optional[int] = None,
    artifact_id: Optional[int] = None,
    queue_name: str = "default",
    state: str = "queued",
    stage: str = "queued",
    progress: int = 0,
) -> AnalysisJob:
    if state not in JOB_STATES:
        state = "queued"
    if stage not in JOB_STAGES:
        stage = "queued"
    job = AnalysisJob(
        case_id=case_id,
        artifact_id=artifact_id,
        submitted_by_user_id=submitted_by_user_id,
        job_type=str(job_type or "generic"),
        queue_name=queue_name or "default",
        state=state,
        stage=stage,
        progress=_clamp_progress(progress),
    )
    db.session.add(job)
    db.session.commit()
    return job


def bind_job_task(job_id: int, task_id: str):
    job = db.session.get(AnalysisJob, int(job_id))
    if not job:
        return None
    job.task_id = str(task_id or "")
    if job.state == "queued":
        job.state = "running"
        job.started_at = datetime.utcnow()
    if job.stage == "queued":
        job.stage = "artifact_received"
    if job.progress < 5:
        job.progress = 5
    db.session.commit()
    return job


def update_job_status(
    job_id: int,
    *,
    state: Optional[str] = None,
    stage: Optional[str] = None,
    progress: Optional[int] = None,
    error_message: Optional[str] = None,
    history_id: Optional[int] = None,
    summary: Optional[Dict] = None,
    mark_started: bool = False,
    mark_finished: bool = False,
):
    job = db.session.get(AnalysisJob, int(job_id))
    if not job:
        return None
    if state:
        job.state = state if state in JOB_STATES else job.state
    if stage:
        job.stage = stage if stage in JOB_STAGES else job.stage
    if progress is not None:
        job.progress = _clamp_progress(progress)
    if error_message is not None:
        job.error_message = str(error_message)[:4000] if error_message else None
    if history_id is not None:
        job.history_id = history_id
    if summary is not None:
        job.set_result_summary(summary)
    now = datetime.utcnow()
    if mark_started and not job.started_at:
        job.started_at = now
    if mark_finished:
        job.finished_at = now
    db.session.commit()
    return job


def get_job_by_task_id(task_id: str):
    if not task_id:
        return None
    return AnalysisJob.query.filter_by(task_id=str(task_id)).order_by(AnalysisJob.id.desc()).first()


def persist_dfir_outputs(job_id: int, results: Dict, sigma_matches=None):
    job = db.session.get(AnalysisJob, int(job_id))
    if not job:
        return {"findings": 0, "rule_matches": 0, "timeline_events": 0}

    Finding.query.filter_by(analysis_job_id=job.id).delete(synchronize_session=False)
    RuleMatch.query.filter_by(analysis_job_id=job.id).delete(synchronize_session=False)
    TimelineEvent.query.filter_by(analysis_job_id=job.id).delete(synchronize_session=False)

    case_id = job.case_id
    source_type = str(job.job_type or "generic")
    findings_written = 0
    rule_matches_written = 0
    timeline_written = 0

    anomalies = (results or {}).get("anomalies") or []
    for anomaly in anomalies[:MAX_FINDINGS_PER_JOB]:
        if not isinstance(anomaly, dict):
            continue
        finding = Finding(
            case_id=case_id,
            analysis_job_id=job.id,
            source_type=source_type,
            category=str(anomaly.get("category") or "detection"),
            severity=str(anomaly.get("severity") or "medium"),
            indicator=str(anomaly.get("indicator") or ""),
            title=str(anomaly.get("reason") or "Detection Finding")[:255],
            description=str(anomaly.get("reason") or ""),
            score=0,
            event_ref=str((anomaly.get("event") or {}).get("source") or ""),
        )
        finding.set_raw(anomaly)
        db.session.add(finding)
        findings_written += 1

    normalized_matches = sigma_matches if isinstance(sigma_matches, list) else ((results or {}).get("sigma_matches") or [])
    for match in normalized_matches[:MAX_RULE_MATCHES_PER_JOB]:
        if not isinstance(match, dict):
            continue
        rm = RuleMatch(
            case_id=case_id,
            analysis_job_id=job.id,
            rule_engine="sigma",
            rule_id=str(match.get("rule_id") or ""),
            rule_title=str(match.get("rule_title") or "Sigma Rule Match")[:255],
            rule_level=str(match.get("rule_level") or ""),
            event_index=match.get("event_index"),
        )
        rm.set_match(match)
        db.session.add(rm)
        rule_matches_written += 1

    summary = (results or {}).get("summary") or {}
    title = f"{source_type.upper()} analysis {str(job.state).upper()}".strip()
    timeline = TimelineEvent(
        case_id=case_id,
        analysis_job_id=job.id,
        event_type=f"{source_type}.analysis.complete",
        source=source_type,
        title=title[:255],
    )
    timeline.set_details(
        {
            "summary": summary,
            "history_id": job.history_id,
            "findings_written": findings_written,
            "rule_matches_written": rule_matches_written,
        }
    )
    db.session.add(timeline)
    timeline_written += 1

    db.session.commit()
    return {
        "findings": findings_written,
        "rule_matches": rule_matches_written,
        "timeline_events": timeline_written,
    }
