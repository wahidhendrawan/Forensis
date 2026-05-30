# Forensis

Forensis is an open-source web platform for threat analysis and digital forensics operations.
It provides a unified workflow for log analysis, network packet inspection, memory triage,
Sigma correlation, and secure user administration.

## Key Capabilities

### 1. Log Parser and Analyzer
- Parse Apache, Syslog, CSV, JSON, Elastic-like, and Splunk-like log inputs.
- Detect anomalies from suspicious patterns and status behavior.
- Correlate parsed events with Sigma rules.
- Export results to JSON and CSV.

### 2. Network Traffic Analyzer
- Analyze PCAP and PCAPNG files.
- Build flow summaries (source, destination, ports, protocol, bytes, packets, duration).
- Highlight suspicious communication patterns.
- Run Sigma correlation against network events.
- Export results to JSON and CSV.

### 3. Memory
- Dedicated triage page separate from Helper.
- Accept raw paste or uploads in: TXT, LOG, JSON, NDJSON/JSONL, CSV, TSV, XML, YAML, ZIP, VMEM, MEM.
- Parse mixed memory tool output and surface suspicious indicators with severity.
- Provide follow-up recommendations and export to JSON/CSV.

### 4. Forensics Helper
- Plan Generator for memory, network, and log investigation playbooks.
- Operational Cheatsheets for common DFIR commands.
- Optimized for fast triage handoff and repeatable analyst workflow.

### 5. Sigma Engine and Rule Management
- Built-in SigmaHQ baseline ruleset from repository `SigmaHQ/sigma`, pinned to commit `994da16651194500b607a3007186c29779e1f961` (`rules/` path).
- Automatic local baseline cache bootstrap on startup (no manual sync required for core rules).
- Local Sigma rule correlation for logs, network, and memory artifacts.
- Dashboard actions to sync Sigma rules from remote URLs.
- Rule reload support without restarting the full stack.

### 6. Users and Administration
- Role-based access control (Admin and Analyst).
- User CRUD and group administration.
- Built-in MFA (TOTP) setup, disable, and reset flows.
- Dedicated Users and Security area for account governance.

### 7. History and Reporting
- Persist analysis history for logs, network, memory playbooks, and memory triage.
- View, delete, and review previous sessions.
- Export report bundle from current in-memory result set.

## Stack
- Flask
- SQLAlchemy (SQLite default)
- Flask-Login and Flask-Bcrypt
- PyOTP (MFA)
- Celery + Redis (async processing)
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
│   │   └── sigma_engine.py
│   └── integrations/
│       └── elk_loki.py
├── templates/
├── static/
├── sigma_rules/
├── instance/
├── uploads/
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Security Notes
- Change default admin credentials immediately.
- Use a strong `FORENSIS_SECRET_KEY`.
- Enable MFA for privileged users.
- Review uploaded artifact handling and storage policy before production use.

## License
See [LICENSE](LICENSE).
