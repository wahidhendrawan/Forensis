# Forensis

Forensis is an open-source web platform for threat analysis and digital forensics operations.
It provides a unified workflow for log analysis, network packet inspection, memory triage,
multi-engine detection correlation, and secure user administration.

## DFIR Service Architecture

Forensis now uses a service-oriented internal architecture (modular monolith baseline) that maps directly to production microservice boundaries:

- **api-service** responsibilities:
  - auth, users, case registry, artifact registry, job submission, job status APIs.
  - endpoints: `/api/cases`, `/api/jobs`, `/api/jobs/<id>`, `/api/jobs/<task_id>/status`.
- **analysis-workers** responsibilities:
  - dedicated Celery workers for `logs`, `network`, and `memory` analysis jobs.
  - queue-separated workers (`logs`, `network`, `memory`, `rules`) ready for queue-depth autoscaling.
  - staged pipeline: `queued -> parse -> enrich -> persist -> post_rule_match -> complete/failed`.
- **rule-service** responsibilities:
  - Sigma/YARA enrichment orchestration and correlation limits.
  - asynchronous Sigma post-processing for large datasets.
- **ui-service** responsibilities:
  - frontend pages consume job status and show real-time progress during analysis.

The current repository keeps these services in one deployable unit for compatibility, while the domain/service boundaries are ready to be extracted into separate runtime services.

### Investigation Data Model

Core normalized entities (internal ECS-style schema version `forensis-ecs-0.1`):

- `Case`
- `Artifact`
- `AnalysisJob`
- `Finding`
- `RuleMatch`
- `TimelineEvent`

These entities are persisted and linked per investigation to support reliable cross-source correlation and case-level auditability.

### Recommended Production Database

- **Primary recommendation**: PostgreSQL 16+ (`postgresql+psycopg` driver).
- Why:
  - stronger concurrent write behavior than SQLite under multi-worker load,
  - better indexing, query planning, and operational tooling,
  - safer growth path for case/finding/timeline scale.
- SQLite remains supported for lightweight deployments and development.

### Migration Versioning

- Alembic is included for DB schema versioning.
- Migration sources:
  - `alembic.ini`
  - `migrations/`
- CI drift guard:
  - `scripts/check_migration_drift.py`
  - `.github/workflows/ci.yml`

## Key Capabilities

### 1. Log Parser and Analyzer
- Parse Apache, Syslog, CSV, JSON, Elastic-like, and Splunk-like log inputs.
- Detect anomalies from suspicious patterns and status behavior.
- Correlate parsed events with Sigma, YARA, Threat Intel, and baseline profiling.
- Display threat score, TI matches, YARA hits, and baseline drift in one view.
- Export results to JSON and CSV.

### 2. Network Traffic Analyzer
- Analyze PCAP and PCAPNG files.
- Build flow summaries (source, destination, ports, protocol, bytes, packets, duration).
- Highlight suspicious communication patterns.
- Run Sigma + YARA + Threat Intel + baseline correlation against network events.
- Include timeline fields (`first_seen`, `last_seen`) in flows and anomaly output.
- Apply packet/flow guardrails to keep large capture processing responsive.
- Export results to JSON and CSV.

### 3. Memory
- Dedicated triage page separate from Helper.
- Accept raw paste or uploads in: TXT, LOG, JSON, NDJSON/JSONL, CSV, TSV, XML, YAML, ZIP, VMEM, MEM, RAW, DMP, IMG, BIN.
- Parse mixed memory tool output and surface suspicious indicators with severity.
- Run enrichment for YARA/TI/baseline on parsed memory artifacts.
- Provide follow-up recommendations and export to JSON/CSV.

### 4. Helper
- Plan Generator for memory, network, and log investigation playbooks.
- Operational Cheatsheets for common DFIR commands.
- Optimized for fast triage handoff and repeatable analyst workflow.

### 5. Sigma Engine and Rule Management
- Built-in SigmaHQ baseline ruleset from repository `SigmaHQ/sigma`, pinned to commit `994da16651194500b607a3007186c29779e1f961` (`rules/` path).
- Automatic local baseline cache bootstrap on startup (no manual sync required for core rules).
- Local Sigma rule correlation for logs, network, and memory artifacts.
- Dashboard actions to sync Sigma rules from remote URLs.
- Rule reload support without restarting the full stack.

### 6. Fast Malicious Detection Stack (Beyond Sigma)
- **YARA Engine** for memory/log/network text artifacts (`yara_rules/`).
- **Threat Intel Enrichment** for IP/domain/hash with local feed + local cache + scoring (`threat_intel/ioc_feed.json`).
- **OTX Public IP Enrichment** for external reputation lookup on public IP indicators from log analysis (configured in Users & Administration).
- **Cross-Source Correlation** (log + network + memory) by time window and shared identity (IP/host).
- **Entity Baseline & Allowlist** per environment (`config/entity_baseline.json`, `config/entity_allowlist.json`).
- **Rule QA Pipeline** with benign/malicious datasets and automated regression checks (`scripts/rule_qa.py`).

### 7. Event Search and Analytics Storage
- **OpenSearch** sink for indexed event search at scale.
- **ClickHouse** sink for high-volume event analytics and timeline aggregations.
- Search API supports OpenSearch backend + database fallback.

### 8. Users and Administration
- Role-based access control (Admin and Analyst).
- User CRUD and group administration.
- Built-in MFA (TOTP) setup, disable, and reset flows.
- Dedicated Users and Security area for account governance.
- OTX API key management in admin panel with masked display and clear/rotate controls.
- CSRF protection for sensitive POST operations (administration and analyzer actions).

### 9. History and Reporting
- Persist analysis history for logs, network, memory playbooks, and memory triage.
- View, delete, and review previous sessions.
- Export report bundle from current in-memory result set.

## Stack
- Flask
- SQLAlchemy (PostgreSQL recommended, SQLite fallback)
- Flask-Login and Flask-Bcrypt
- PyOTP (MFA)
- Celery + Redis (async processing)
- YARA (via `yara-python`)
- Gunicorn (WSGI runtime)
- Alembic (schema migrations)
- Bootstrap 5 frontend

## Quick Start

### Docker (recommended)
1. Ensure Docker and Docker Compose are installed.
2. Create or edit `.env` in project root:

```env
FORENSIS_SECRET_KEY=replace_with_strong_secret
FORENSIS_ADMIN_USER=admin
FORENSIS_ADMIN_PASSWORD=forensis123
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0
# Optional SigmaHQ baseline controls
# FORENSIS_SIGMAHQ_REPO=SigmaHQ/sigma
# FORENSIS_SIGMAHQ_COMMIT=994da16651194500b607a3007186c29779e1f961
# FORENSIS_SIGMAHQ_RULES_SUBDIR=rules
# FORENSIS_SIGMAHQ_REFRESH=0
# Optional detection tuning
# FORENSIS_CORRELATION_WINDOW_MINUTES=60
# FORENSIS_TI_CACHE_TTL=43200
# FORENSIS_TI_CACHE_MAX_ENTRIES=50000
# FORENSIS_TI_MAX_HITS=500
# FORENSIS_OTX_TIMEOUT_SECONDS=4
# FORENSIS_OTX_MAX_LOOKUPS=30
# FORENSIS_OTX_MAX_SECONDS=12
# Async post-rule correlation for faster first result render
# FORENSIS_ASYNC_SIGMA_POSTPROCESS=1
# Optional Sigma correlation performance guardrails
# FORENSIS_SIGMA_MAX_EVENTS=900
# FORENSIS_SIGMA_MAX_EVENTS_NETWORK=250
# FORENSIS_SIGMA_MAX_EVENTS_LOGS=900
# FORENSIS_SIGMA_MAX_EVENTS_MEMORY=700
# FORENSIS_SIGMA_MAX_MATCHES=1500
# FORENSIS_NETWORK_EVENTS_STORE_LIMIT=900
# FORENSIS_NETWORK_ANOMALIES_STORE_LIMIT=500
# FORENSIS_PCAP_MAX_UPLOAD_BYTES=314572800
# FORENSIS_PCAP_MAX_PACKETS=350000
# FORENSIS_PCAP_MAX_TRACKED_FLOWS=250000
# Optional DB backend (example PostgreSQL)
# FORENSIS_DB_URI=postgresql+psycopg://forensis:forensis_change_me@postgres:5432/forensis
# Optional OpenSearch sink/search
# FORENSIS_OPENSEARCH_URL=http://opensearch:9200
# FORENSIS_OPENSEARCH_INDEX=forensis-events
# FORENSIS_OPENSEARCH_USERNAME=
# FORENSIS_OPENSEARCH_PASSWORD=
# FORENSIS_OPENSEARCH_VERIFY_TLS=false
# Optional ClickHouse sink/analytics
# FORENSIS_CLICKHOUSE_URL=http://clickhouse:8123
# FORENSIS_CLICKHOUSE_DB=forensis
# FORENSIS_CLICKHOUSE_TABLE=events
# FORENSIS_CLICKHOUSE_USERNAME=
# FORENSIS_CLICKHOUSE_PASSWORD=
# Optional SQLAlchemy pool tuning for PostgreSQL
# FORENSIS_DB_POOL_SIZE=20
# FORENSIS_DB_POOL_MAX_OVERFLOW=40
# FORENSIS_DB_POOL_TIMEOUT=30
# FORENSIS_DB_POOL_RECYCLE=1800
# Optional display timezone (default: Asia/Jakarta / GMT+7)
# FORENSIS_DISPLAY_TZ=Asia/Jakarta
```

3. Build and run:

```bash
docker compose up -d --build
```

4. Open:
- `http://localhost:5000`

Default credentials (if unchanged):
- Username: `admin`
- Password: `forensis123`

### Local run
1. Create virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Start app:

```bash
python app.py
```

3. Open:
- `http://127.0.0.1:5000`

## Main Routes
- `/` (redirects to `/login`)
- `/login`
- `/dashboard`
- `/log-analyzer`
- `/network-analyzer`
- `/memory-triage`
- `/helper`
- `/history`
- `/users`

Additional APIs:
- `/api/search/events`
- `/api/analytics/overview`

## Production Profile (Optional)

Enable optional production-oriented stack components:

```bash
docker compose --profile dfir-prod up -d --build
```

This profile enables:
- `minio` (object storage for artifact expansion)
- `rabbitmq` (alternate queue backend option)
- dedicated queue workers: `worker_logs`, `worker_network`, `worker_memory`, `worker_rules`
- `opensearch` + `opensearch_dashboards`

`postgres` runs in the default compose stack.

Enable ClickHouse analytics profile:

```bash
docker compose --profile dfir-analytics up -d --build
```

## SQLite to PostgreSQL Cutover

1. Start PostgreSQL target and set `FORENSIS_DB_URI` to PostgreSQL.
2. Start Forensis once so schema/tables are created.
3. Run migration script:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path instance/forensis.db \
  --postgres-uri postgresql+psycopg://forensis:forensis_change_me@localhost:5432/forensis
```

The migration script truncates destination tables, copies rows, and realigns PostgreSQL ID sequences to prevent duplicate primary-key inserts.

Alembic upgrade/drift check:

```bash
alembic upgrade head
python scripts/check_migration_drift.py
```

## Job Pipeline (Event-Driven)

For every uploaded artifact, Forensis creates:

1. `Case` (auto-open case if no active case for same analyst/day)
2. `Artifact` (hash + metadata)
3. `AnalysisJob` (state machine tracked)

Execution flow:

1. Upload artifact
2. Create queued job
3. Worker runs parse + enrich
4. Persist normalized results
5. Async Sigma correlation (configurable)
6. Finalize findings/rule matches/timeline and update job state

Job state machine:

- `queued`
- `running`
- `partial` (core result ready, post-rule correlation still running)
- `succeeded`
- `failed`

Job stage examples:

- `artifact_received`
- `parse`
- `enrich`
- `rule_match`
- `post_rule_match`
- `complete`

## Rule QA Regression

Run automated benign/malicious regression checks:

```bash
python scripts/rule_qa.py
```

Machine-readable output:

```bash
python scripts/rule_qa.py --json
```

Expectations file:
- `qa_datasets/regression_expectations.json`

## Queue-Depth Worker Autoscaling (KEDA)

Kubernetes manifests for separated queue workers and autoscaling:

- `deploy/k8s/workers-keda.yaml`
- `deploy/k8s/README.md`

## Project Structure

```text
Forensis/
├── app.py
├── forensis/
│   ├── models.py
│   ├── analyzers/
│   │   ├── log_analyzer.py
│   │   ├── network_analyzer.py
│   │   ├── playbook_engine.py
│   │   ├── sigma_engine.py
│   │   ├── yara_engine.py
│   │   ├── threat_intel.py
│   │   ├── entity_profile.py
│   │   ├── correlation_engine.py
│   │   └── detection_pipeline.py
│   ├── services/
│   │   ├── event_search_service.py
│   │   ├── analytics_service.py
│   │   ├── job_service.py
│   │   └── rule_service.py
│   └── integrations/
│       └── elk_loki.py
├── migrations/
│   └── versions/
├── deploy/
│   ├── clickhouse/
│   └── k8s/
├── .github/workflows/ci.yml
├── templates/
├── static/
├── sigma_rules/
├── yara_rules/
├── threat_intel/
├── config/
├── qa_datasets/
├── scripts/
│   ├── check_migration_drift.py
│   ├── migrate_sqlite_to_postgres.py
│   └── rule_qa.py
├── instance/
├── uploads/
├── Dockerfile
├── alembic.ini
├── docker-compose.yml
└── requirements.txt
```

## Security Notes
- Change default admin credentials immediately.
- Use a strong `FORENSIS_SECRET_KEY`.
- Enable MFA for privileged users.
- Keep TI feed, baseline allowlist, and custom YARA rules under version control.
- Review uploaded artifact handling and storage policy before production use.

## License
See [LICENSE](LICENSE).
