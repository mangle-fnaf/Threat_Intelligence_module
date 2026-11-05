# Threat Intelligence Module

A Python-based threat intelligence enrichment platform designed to identify, enrich, analyse and assess Indicators of Compromise (IOCs).

The application classifies user-supplied IOCs, enriches them using real-world threat intelligence sources, calculates risk scores, maps findings to MITRE ATT&CK techniques, generates threat intelligence reports and tracks analysis statistics through a dashboard.

---

## Features

### IOC Detection & Validation

Supports identification of:

- IPv4 Addresses
- Domains
- URLs
- MD5 Hashes
- SHA1 Hashes
- SHA256 Hashes

---

### VirusTotal Integration

Enriches indicators using VirusTotal intelligence.

Provides:

- Reputation Score
- Malicious Detections
- Suspicious Detections
- Harmless Detections

---

### AbuseIPDB Integration

Performs IP reputation analysis using AbuseIPDB.

Provides:

- Abuse Confidence Score
- Country Information
- Total Reports

---

### Risk Scoring Engine

Calculates overall IOC risk levels using intelligence gathered from multiple sources.

Severity Levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

---

### MITRE ATT&CK Mapping

Maps threat intelligence findings to relevant MITRE ATT&CK techniques.

Examples include:

- T1071 – Application Layer Protocol
- T1110 – Brute Force
- T1595 – Active Scanning

---

### Intelligence Report Generation

Generates HTML intelligence reports containing:

- IOC Information
- Threat Intelligence Findings
- Risk Assessment
- MITRE ATT&CK Mappings

---

### Dashboard & Statistics

Tracks key intelligence metrics including:

- Total IOCs Analysed
- High-Risk IOCs
- Average Risk Score

---

## Technologies Used

- Python
- Flask
- VirusTotal API
- AbuseIPDB API
- Requests
- Jinja2
- python-dotenv
- HTML

---

## Project Structure

```text
Threat_Intelligence_Module/
│
├── dashboard/
│   ├── __init__.py
│   └── statistics.py
│
├── integrations/
│   ├── abuseipdb.py
│   └── virustotal.py
│
├── mitre/
│   └── mapper.py
│
├── parsers/
│   └── ioc_parser.py
│
├── scoring/
│   └── risk_engine.py
│
├── templates/
│   ├── dashboard.html
│   ├── index.html
│   └── report.html
│
├── screenshots/
│
├── app.py
├── requirements.txt
└── README.md
```

---

## Threat Intelligence Workflow

```text
User IOC
    ↓
IOC Detection
    ↓
VirusTotal Enrichment
    ↓
AbuseIPDB Enrichment
    ↓
Risk Scoring Engine
    ↓
MITRE ATT&CK Mapping
    ↓
Report Generation
    ↓
Dashboard Statistics
```

---

## Screenshots

### IOC Detection

![IOC Detection](screenshots/commit1-ioc-detection.png)

### VirusTotal Integration

![VirusTotal Integration](screenshots/commit2-virustotal-enrichment.png)

### AbuseIPDB Integration

![AbuseIPDB Integration](screenshots/commit3-abuseipdb-integration.png)

### Risk Scoring Engine

![Risk Scoring Engine](screenshots/commit4-risk-scoring.png)

### MITRE ATT&CK Mapping

![MITRE Mapping](screenshots/commit5-mitre-mapping.png)

### Intelligence Report Generation

![Intelligence Report](screenshots/commit6-html-intelligence-report.png)

### Dashboard & Statistics

![Dashboard](screenshots/commit7-dashboard-statistics.png)

---

## Installation

### Clone The Repository

```bash
git clone https://github.com/mangle-fnaf/Threat_Intelligence_module.git
```

### Move Into The Project Directory

```bash
cd Threat_Intelligence_module
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file inside the project root:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### Run The Application

```bash
python app.py
```

### Open In Browser

```text
http://127.0.0.1:5000
```

---

## Security Notes

- API keys are stored securely using environment variables.
- Sensitive credentials are excluded from source control using `.gitignore`.
- No secrets are hardcoded into the application.

---

## Future Improvements

- Additional Threat Intelligence Providers
- IOC History Tracking
- PDF Report Export
- Interactive Dashboard Visualisations
- Threat Hunting Automation
- Integration Into ThreatHunter SIEM

---

## Author

Maliyka Liaqat
Developed as part of the ThreatHunter SIEM cybersecurity portfolio project.