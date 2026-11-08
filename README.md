# Forensis 🔍

[![CI](https://github.com/wahidhendrawan/Forensis/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/Forensis/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wahidhendrawan/Forensis?sort=semver)](https://github.com/wahidhendrawan/Forensis/releases/latest)
[![License](https://img.shields.io/github/license/wahidhendrawan/Forensis)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/wahidhendrawan/Forensis/badge)](https://scorecard.dev/viewer/?uri=github.com/wahidhendrawan/Forensis)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Pages](https://img.shields.io/badge/docs-🌐-orange.svg)](https://wahidhendrawan.github.io/Forensis/)
[![Last Commit](https://img.shields.io/github/last-commit/wahidhendrawan/Forensis)](https://github.com/wahidhendrawan/Forensis/commits/main)
[![GitHub stars](https://img.shields.io/github/stars/wahidhendrawan/Forensis?style=social)](https://github.com/wahidhendrawan/Forensis/stargazers)

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
- Dashboard actions (admins only) to sync Sigma rules from remote URLs; every redirect hop is re-checked against private/link-local addresses and downloads are size-capped.
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
- Export JSON/CSV per analysis (`/export/<logs|network|memory>/<history_id>/<json|csv>`), scoped like the history views.
- Export report bundle with the latest analysis of each type you are allowed to see.

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
# Required by docker-compose.yml
FORENSIS_POSTGRES_PASSWORD=replace_with_strong_db_password
FORENSIS_MINIO_ROOT_PASSWORD=replace_with_strong_minio_password
# Optional: unset -> generated once and stored in instance/secret_key (0600)
FORENSIS_SECRET_KEY=replace_with_strong_secret
FORENSIS_ADMIN_USER=admin
# Optional: unset -> random password, printed once in the forensis container log
# FORENSIS_ADMIN_PASSWORD=
# Set to 1 when Forensis is served over HTTPS (marks the session cookie Secure)
# FORENSIS_SESSION_COOKIE_SECURE=0
# Failed-login throttle per client IP (shared through Redis, defaults to CELERY_BROKER_URL)
# FORENSIS_LOGIN_MAX_FAILURES=10
# FORENSIS_LOGIN_WINDOW_SECONDS=300
# FORENSIS_RATELIMIT_REDIS_URL=redis://redis:6379/0
# Upload limits (request body cap never goes below the largest per-type cap)
# FORENSIS_LOG_MAX_UPLOAD_BYTES=52428800
# FORENSIS_MAX_CONTENT_LENGTH=
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
# FORENSIS_SIGMA_MAX_EVENTS=3000
# FORENSIS_SIGMA_MAX_EVENTS_NETWORK=1000
# FORENSIS_SIGMA_MAX_EVENTS_LOGS=3000
# FORENSIS_SIGMA_MAX_EVENTS_MEMORY=3000
# FORENSIS_SIGMA_MAX_MATCHES=1500
# FORENSIS_NETWORK_EVENTS_STORE_LIMIT=900
# FORENSIS_NETWORK_ANOMALIES_STORE_LIMIT=500
# FORENSIS_PCAP_MAX_UPLOAD_BYTES=314572800
# FORENSIS_PCAP_MAX_PACKETS=350000
# FORENSIS_PCAP_MAX_TRACKED_FLOWS=250000
# Optional DB backend (example PostgreSQL)
# FORENSIS_DB_URI=postgresql+psycopg://forensis:<FORENSIS_POSTGRES_PASSWORD>@postgres:5432/forensis
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

3. The image runs as non-root uid `10001`. On Linux hosts, make the bind-mounted data directories writable for it:

```bash
mkdir -p uploads instance && sudo chown 10001:10001 uploads instance
```

4. Build and run:

```bash
docker compose up -d --build
```

5. Open:
- `http://localhost:5000`

Login as `FORENSIS_ADMIN_USER` (default `admin`). If `FORENSIS_ADMIN_PASSWORD` was not set, read the generated password once from the log:

```bash
docker compose logs forensis | grep "generated password"
```

For development with the source tree live-mounted into the containers, add the opt-in override:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

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

Run the tests:

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

Dependencies: edit `requirements.in`, then regenerate the pinned lockfile with `pip-compile --strip-extras --no-emit-index-url --output-file=requirements.txt requirements.in` (pip-tools, run on the Dockerfile's Python).

### Native engines (optional)

`forensis_core/` is a small Rust extension (PyO3 + maturin, no `unsafe`) with two engines. `analyze_pcap` parses PCAP/PCAPNG uploads and builds the network flow results with the GIL released; `forensis/analyzers/network_analyzer.py` uses it when it can be imported and otherwise runs the pure-Python dpkt implementation, which stays the reference: both return identical results (`tests/test_pcap_engine.py` checks parity and fuzzes malformed captures). `classify_events` does the per-event scanning of the log analyzer (text assembly, URL decoding, the malicious-pattern regexes) in batches with the GIL released; `forensis/analyzers/log_analyzer.py` keeps parsing and correlation in Python and `_classify_event` as the reference (`tests/test_log_engine.py` checks parity and fuzzes payloads). `correlate_sigma` matches compiled Sigma rules against flattened events with the GIL released; rules with regex, numeric or bracket-glob values stay on the Python matcher in `forensis/analyzers/sigma_engine.py`, which is the reference for all of them (`tests/test_sigma_native.py` checks parity with random rules and events). The worker log lines `PCAP engine: rust|python`, `Log engine: rust|python` and `Sigma engine: rust|python` show which one ran. The Docker image always builds it; locally it needs a Rust toolchain (https://rustup.rs):

```bash
pip install ./forensis_core   # builds and installs the wheel; rerun after changing the Rust code
```

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

Internal services (Redis, MinIO, RabbitMQ, OpenSearch, ClickHouse) are not published to the host; PostgreSQL (`5432`, for the cutover script below) and OpenSearch Dashboards (`5601`) are bound to `127.0.0.1` only.

**OpenSearch security:** the bundled single-node OpenSearch runs with `DISABLE_SECURITY_PLUGIN=true` (no authentication, no TLS) and is reachable only on the internal compose network. Do not publish port `9200`/`5601` beyond localhost. For shared or production use, enable the security plugin (set `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, configure TLS certificates) and point Forensis at it with `FORENSIS_OPENSEARCH_URL=https://...`, `FORENSIS_OPENSEARCH_USERNAME`, `FORENSIS_OPENSEARCH_PASSWORD` and `FORENSIS_OPENSEARCH_VERIFY_TLS`.

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
├── forensis_core/          # optional Rust PCAP engine (PyO3 + maturin)
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
├── docker-compose.dev.yml
├── requirements.in
└── requirements.txt
```

## Velociraptor Integration (Planned)

Forensis will support remote forensic acquisition via [Velociraptor](https://docs.velociraptor.app/):

- **Artifact collection**: Browse and collect Velociraptor artifacts directly from the Forensis UI.
- **Automated hunts**: Schedule recurring memory/log/network collection jobs from Velociraptor agents.
- **Evidence ingestion**: Ingest `.vql` results as Forensis artifacts, triggering the full detection pipeline.
- **API bridge**: Configure Velociraptor API URL + credentials in Forensis admin panel.

```env
# Planned — not yet active
# FORENSIS_VELOCIRAPTOR_URL=https://velociraptor.internal:8000
# FORENSIS_VELOCIRAPTOR_CLIENT_ID=forensis
# FORENSIS_VELOCIRAPTOR_CLIENT_SECRET=
```

## GRR Rapid Response (Planned)

[GRR](https://github.com/google/grr) integration for live remote forensic investigation:

- Agent listing and live flow execution from within Forensis.
- GRR hunt results ingested as structured timeline events.
- Cross-reference GRR findings with Sigma/YARA correlation engine.

## 📸 Screenshots

| Screen | Description |
|--------|-------------|
| Dashboard | Overview of active cases, job queue, and detection summary |
| Log Analyzer | Log parsing results with Sigma matches, threat scores, and enrichment |
| Network Analyzer | PCAP flow analysis with highlighted suspicious communication |
| Memory Triage | Memory dump analysis with YARA detection and indicator extraction |
| History | Past analysis sessions with export and review controls |

---

## Security Notes
- Set `FORENSIS_ADMIN_PASSWORD` or rotate the generated admin password after first login.
- Use a strong `FORENSIS_SECRET_KEY` (or keep the generated `instance/secret_key` private).
- Serve over HTTPS and set `FORENSIS_SESSION_COOKIE_SECURE=1`.
- Enable MFA for privileged users.
- Keep TI feed, baseline allowlist, and custom YARA rules under version control.
- Review uploaded artifact handling and storage policy before production use.

## License
See [LICENSE](LICENSE).
