# Forensis - Forensics & Analysis

**Forensis** is a modern, enterprise-ready web platform designed for **forensics and threat analysis workflows**. It combines advanced log parsing, network traffic analysis, memory forensics triage, and Sigma rule correlation into a unified, secure dashboard.



---

## 🔍 Key Features

### 1. Log Parser & Analyzer
Parse and analyze diverse log formats with heuristic anomaly detection and automated Sigma rule correlation.

- **Supported Formats:**
  - **Apache / Web Server Logs**
  - **Syslog**
  - **CSV Files** (generic or custom exports)
  - **Elastic Stack** (JSON exports)
  - **Splunk** (JSON/CSV exports)
- **Detection:**
  - HTTP status anomalies (4xx/5xx spikes)
  - Suspicious keywords (`failed password`, `mimikatz`, `sql injection`, etc.)
  - Real-time Sigma rule matching

### 2. Network Traffic Analyzer
Analyze **PCAP / PCAPNG** files to identify suspicious flows and beaconing behavior.

- **Capabilities:**
  - Flow extraction: `src`, `dst`, `ports`, `proto`, `bytes`, `duration`, `avg_payload`
  - Detection of C2 beaconing patterns and suspicious remote access ports
  - **Sortable Results:** Interactively sort flows by size, packets, or payload
  - Sigma rule correlation for network events

### 3. Memory Forensics Helper
Assist with memory analysis workflows and automate command generation for **Volatility 3**.

- **Playbook Generator:** Creates recommended command chains based on selected profiles (Windows/Linux) and focus areas (Malware, Persistence).
- **Triage Mode:** Parses raw output logs to highlight suspicious processes and artifacts.
- **File Upload:** Upload raw memory analysis logs for instant parsing.

### 4. Enterprise-Grade Security & Management
Built for teams with secure access controls and audit capabilities.

- **Multi-Factor Authentication (MFA):** Secure user accounts with TOTP (Google Authenticator, Authy).
- **Role-Based Access Control (RBAC):**
  - **Admin:** Manage users, groups, and global settings.
  - **Analyst:** Perform analyses and view history.
- **User Management:** Create, delete, and group users via a dedicated interface.

### 5. Persistent History & Dashboard
Never lose your work. All analysis results are stored securely.

- **Analysis History:** Review past log, network, and memory analysis sessions.
- **Persistent Dashboard:** Visualize trends over time (not just the last session).
- **Metrics:** Track total events, anomalies, and threat alerts across the organization.
- **Admin Tools:** Granularly delete history records or perform a full system reset.

### 6. Sigma Correlation Engine
Lightweight YAML-based engine for detecting threats across all modules.

- **Predefined Rules:** Ships with rules for Web Shells, PowerShell abuse, Mimikatz, and Network Beaconing.
- **Live Sync:** Update rules dynamically from remote Git repositories (e.g., SigmaHQ).
- **Management:** Reload local rules or sync from URLs directly from the dashboard.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10+**
- **Docker & Docker Compose** (Recommended for production)

### 🐳 Docker Deployment (Recommended)

Forensis is pre-configured with Docker Compose for a production-ready setup including persistent storage.

1. **Configure Environment:**
   ```bash
   cp .env.example .env  # (Or create one based on documentation)
   # Edit .env to set your FORENSIS_SECRET_KEY and Admin credentials
Build and Run:

Bash
docker-compose up -d --build
Access: Open http://localhost:5000

Default Admin: admin / forensis123 (Change immediately!)

🧰 Local Installation (Manual)
Clone and Install:

Bash
git clone [https://github.com/wahidhendrawan/Forensis.git](https://github.com/wahidhendrawan/Forensis.git)
cd Forensis
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
Run:

Bash
python app.py
The database will be automatically initialized on the first run.

Access: Open http://127.0.0.1:5000

📂 Project Structure
Plaintext
Forensis/
├── app.py                  # Main application logic & routes
├── forensis/
│   ├── models.py           # Database models (User, History, Group)
│   ├── analyzers/          # Analysis engines (Log, Network, Memory, Sigma)
│   └── integrations/       # External exports (ELK, Loki)
├── sigma_rules/            # YAML detection rules
│   ├── web_error_spike.yml
│   ├── susp_powershell.yml
│   └── ...
├── templates/              # HTML Templates (Bootstrap 5)
│   ├── dashboard.html
│   ├── manage_users.html
│   ├── setup_mfa.html
│   └── ...
├── static/
│   ├── styles.css          # Dark/Light theme styles
│   └── main.js             # UI interactions
├── instance/               # SQLite database storage
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
🔐 Security Features
Authentication: Database-backed auth using Flask-Login and Bcrypt hashing.

MFA: Time-based One-Time Password (TOTP) support using pyotp.

Session Management: Secure session handling with administrative timeouts.

Input Validation: Strict file type validation and secure filename handling.

🎨 Customization
Themes: Toggle between Light and Dark modes instantly via the navbar.

Configuration: Manage settings via .env:

FORENSIS_SECRET_KEY

FORENSIS_ADMIN_USER / PASSWORD

FORENSIS_SIGMA_URLS

🪶 License
Free to use and modify for research, learning, or internal lab environments.

No warranty is provided — use responsibly.