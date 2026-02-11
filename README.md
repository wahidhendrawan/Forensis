# Forensis - Forensics & Analysis

**Forensis** is a modern, enterprise-ready web platform designed for **forensics and threat analysis workflows**. It combines advanced log parsing, network traffic analysis, memory forensics triage, and Sigma rule correlation into a unified, secure dashboard.

[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Flask](https://img.shields.io/badge/flask-2.3+-lightgrey)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-Free%20use-green)](#license)

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

---

## 🚀 Quick Start (Docker)

```bash
docker-compose up -d --build
```

Access the web interface at **http://localhost:5000**

> **Default admin credentials:**  
> **Username:** `admin`  
> **Password:** `forensis123`  
> ⚠️ **Change immediately after first login!**

---

## 📦 Manual Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/wahidhendrawan/Forensis.git
   cd Forensis
   ```

2. **Create and activate virtual environment**  
   ```bash
   python -m venv venv
   source venv/bin/activate      # Linux / macOS
   venv\Scripts\activate         # Windows
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**  
   ```bash
   python app.py
   ```
   The SQLite database is automatically initialized on first run.

5. **Access**  
   Open **http://127.0.0.1:5000**

---

## 📁 Project Structure

```plaintext
Forensis/
├── app.py                      # Main application logic & routes
├── forensis/
│   ├── models.py               # Database models (User, History, Group)
│   ├── analyzers/              # Analysis engines
│   │   ├── log_analyzer.py
│   │   ├── network_analyzer.py
│   │   ├── memory_analyzer.py
│   │   └── sigma_analyzer.py
│   └── integrations/           # External exports
│       ├── elk_exporter.py
│       └── loki_exporter.py
├── sigma_rules/                # YAML detection rules
│   ├── web_error_spike.yml
│   ├── susp_powershell.yml
│   └── ...
├── templates/                  # HTML templates (Bootstrap 5)
│   ├── dashboard.html
│   ├── manage_users.html
│   ├── setup_mfa.html
│   └── ...
├── static/
│   ├── styles.css              # Dark/Light theme styles
│   └── main.js                # UI interactions
├── instance/                   # SQLite database storage
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🔐 Security Features

- **Authentication** – Database‑backed with Flask‑Login and Bcrypt password hashing.  
- **Multi‑Factor Authentication (MFA)** – TOTP support using `pyotp`.  
- **Session Management** – Secure cookies with administrative timeouts.  
- **Input Validation** – Strict file type validation and secure filename handling.

---

## 🎨 Customization

### 🌓 Theme Toggle
Switch between **Light** and **Dark** modes instantly via the navigation bar.

### ⚙️ Configuration via `.env`
Create a `.env` file in the root directory to override defaults:

```env
FORENSIS_SECRET_KEY=your_secret_key
FORENSIS_ADMIN_USER=custom_admin
FORENSIS_ADMIN_PASSWORD=strong_password
FORENSIS_SIGMA_URLS=https://custom.sigma.repo/rules.zip
```

---

## 🪪 License

**Free to use and modify** for research, learning, or internal lab environments.  
No warranty is provided — use responsibly.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!  
Feel free to open an issue or submit a pull request.

---

## 📌 Acknowledgements

- [Sigma](https://github.com/SigmaHQ/sigma) – Generic signature format for SIEM systems  
- [Flask](https://flask.palletsprojects.com/) – Web framework  
- [Bootstrap 5](https://getbootstrap.com/) – UI components
