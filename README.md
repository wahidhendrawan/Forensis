# Forensis - Forensics & Analysis

**Forensis** is a modern, lightweight web-based tool designed for **forensics and analysis** workflows — combining log parsing, network traffic analysis, memory triage, dashboards, and Sigma rule correlation for rapid threat hunting.

---

## 🔍 Features

### 1. Log Parser & Analyzer
Parse and analyze common log formats with anomaly detection and Sigma rule correlation.

- Supported log types:
  - **Generic / Unknown**
  - **Apache / Web Server**
  - **Syslog**
- Heuristic anomaly detection:
  - HTTP 4xx/5xx codes
  - Suspicious keywords (e.g. `failed password`, `mimikatz`, `sql injection`)
- Integrated Sigma rule correlation
- Export results:
  - `Export JSON`
  - `Export CSV`

---

### 2. Network Traffic Analyzer
Analyze **PCAP / PCAPNG** files and detect suspicious flows.

- Flow extraction:
  - `src`, `dst`, `sport`, `dport`, `proto`, `bytes`, `packets`, `duration`, `avg_payload`
- Detects:
  - C2 beaconing indicators (many small packets)
  - Suspicious remote access ports (22, 23, 3389, 4444, 8080)
  - Long-lived low-volume flows
- Sigma rule correlation
- Export results to JSON/CSV

---

### 3. Memory Forensics Helper
Assist with **memory analysis** and automate playbooks for tools like **Volatility3**.

- Two modes:
  - **Playbook Generator:** creates recommended commands by profile/focus area
  - **Triage Mode:** parses raw output for suspicious indicators
- Built-in suspicious keyword detection (`mimikatz`, `powershell`, `nc.exe`, etc.)
- Integrated Sigma correlation
- Export results to JSON/CSV

---

### 4. Sigma Correlation Engine (with Live Updates)
Lightweight YAML-based **Sigma rule engine** with optional live sync.

- Loads all `.yml` rules from `sigma_rules/` and `sigma_rules/_remote/`
- Performs substring-based detection on event fields
- Ships with example rules:
  - `web_suspicious_user_agent.yml`
  - `web_multiple_404_bruteforce.yml`
  - `network_beaconing_like_flow.yml`
  - `network_suspicious_remote_ports.yml`
  - `windows_suspicious_powershell.yml`
  - `windows_failed_logon_spray.yml`
  - `memory_mimikatz_indicator.yml`
- **Live Updates**:
  - Environment variable:  
    `FORENSIS_SIGMA_URLS="https://raw.githubusercontent.com/.../rule1.yml,https://.../rule2.yml"`  
  - Or use the **Dashboard** form to sync from URLs at runtime
  - Engine supports `reload` and `sync_from_urls` to pull rules into `sigma_rules/_remote`

---

### 5. Interactive Dashboard & Analytics Visualization
Forensis includes a **Dashboard** page with charts built using **Chart.js**.

- Aggregated metrics from the latest analyses:
  - Logs: total parsed vs anomalies, top sources, HTTP status distribution
  - Network: total flows vs suspicious flows
  - Memory: number of suspicious hits (from last triage)
- Visualizations:
  - Doughnut charts for normal vs anomalies
  - Bar chart for memory suspicious hits
- Sigma control panel:
  - **Reload Sigma (local)** button
  - **Sync Sigma from URLs** form

---

### 6. Dark Mode (Toggle)
- Dark mode is enabled by default using Bootstrap 5 `data-bs-theme="dark"`.
- Theme toggle in the navbar:
  - Switch between **Light** and **Dark** themes.
  - Preference is stored in `localStorage` (`forensis-theme`).

---

### 7. ELK & Loki Integration (Optional)
Forensis can automatically **send analyzed events** to external systems for central monitoring.

Set environment variables before running:

#### Elasticsearch
```bash
export FORENSIS_ELASTIC_URL="https://your-elasticsearch:9200"
export FORENSIS_ELASTIC_INDEX="forensis-events"
```

#### Loki
```bash
export FORENSIS_LOKI_URL="http://loki:3100"
export FORENSIS_LOKI_LABELS='app="forensis",env="lab"'
```

#### Live Sigma Sync
```bash
export FORENSIS_SIGMA_URLS="https://raw.githubusercontent.com/.../rule1.yml,https://.../rule2.yml"
```

Each event will be pushed as:
- Elasticsearch document: `POST {index}/_doc`
- Loki stream line: via `/loki/api/v1/push`

This feature fails silently if the backend is unreachable — the web UI will not break.

---

## 🧰 Installation (Local)

Requires **Python 3.10+**

```bash
git clone https://github.com/wahidhendrawan/Forensis.git
cd Forensis
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🐳 Docker Deployment

Build and run manually:

```bash
docker build -t forensis .
docker run --rm -p 5000:5000 --name forensis \\
  -e FORENSIS_ELASTIC_URL="http://elasticsearch:9200" \\
  -e FORENSIS_LOKI_URL="http://loki:3100" \\
  -e FORENSIS_SIGMA_URLS="https://raw.githubusercontent.com/.../rule1.yml" \\
  forensis
```

Or use **docker-compose**:

```bash
docker-compose up -d --build
```

This will start Forensis on **http://localhost:5000**.

---

## 🚀 Running the App (Non-Docker)

```bash
python app.py
```

Then open:

👉 http://127.0.0.1:5000

---

## 📂 Project Structure

```text
Forensis/
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── forensis/
│   ├── analyzers/
│   │   ├── log_analyzer.py
│   │   ├── network_analyzer.py
│   │   ├── memory_helper.py
│   │   └── sigma_engine.py
│   └── integrations/
│       └── elk_loki.py
├── sigma_rules/
│   ├── web_suspicious_user_agent.yml
│   ├── web_multiple_404_bruteforce.yml
│   ├── network_beaconing_like_flow.yml
│   ├── network_suspicious_remote_ports.yml
│   ├── windows_suspicious_powershell.yml
│   ├── windows_failed_logon_spray.yml
│   └── memory_mimikatz_indicator.yml
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── log_analyzer.html
│   ├── network_analyzer.html
│   └── memory_helper.html
└── static/
    ├── styles.css
    └── main.js
```

---

## 📤 Exporting Results

| Module | Export Format | Route |
|:-------|:-------------|:------|
| Logs | `/export/logs/json` or `/export/logs/csv` |
| Network | `/export/network/json` or `/export/network/csv` |
| Memory | `/export/memory/json` or `/export/memory/csv` |

Exports are generated from the **most recent analysis results** held in memory.

---

## 💡 Example Workflow

1. Open Forensis
2. Analyze logs, upload a `.pcap`, or paste memory output
3. Review detected anomalies
4. Correlate with Sigma rules
5. Export results to JSON or CSV
6. (Optional) Forward events to ELK or Loki
7. Use the **Dashboard** to visualize activity and manage Sigma rules

---

## 🧩 Requirements

- Flask ≥ 3.0.0  
- PyYAML ≥ 6.0  
- dpkt ≥ 1.9.8  
- requests ≥ 2.31.0  

---

## 🪶 License

Free to use and modify for **research, learning, or internal lab environments**.  
No warranty is provided — use responsibly.


---

## 🔐 Simple Auth (Role-like Access)

Forensis includes a very lightweight authentication layer suitable for lab / small team use.

- Login page: `/login`
- Default credentials (change in production):
  - `FORENSIS_ADMIN_USER=admin`
  - `FORENSIS_ADMIN_PASSWORD=forensis123`
- After login, you can access:
  - Dashboard
  - All analyzers
  - Export routes
  - Sigma management (sync / reload)
- Logout: `/logout`

These values should be overridden via environment variables in real deployments.

---

## 📦 Report Bundle Export (ZIP)

You can export configuration and last analysis results as a single **report bundle**:

- Route: `/export/report`
- Content of the ZIP:
  - `config/env.json` – sanitized environment-related config (ELK, Loki, Sigma URLs)
  - `sigma/rules.json` – currently loaded Sigma rule metadata (id, title, level, logsource)
  - `results/logs.json` – last log analysis (if available)
  - `results/network.json` – last PCAP analysis (if available)
  - `results/memory.json` – last memory helper result (if available)
  - `summary.json` – quick overview
  - `README_report.txt` – short description of bundle contents

A quick access button to download this bundle is available on the **Dashboard**.
