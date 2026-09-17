# AutoTrace-CTI: Automated Forensic & Threat Intelligence Correlation Engine

AutoTrace-CTI is a lightweight Incident Response pipeline built in Python. It parses unstructured Threat Intelligence (CTI) reports, standardizes extracted Indicators of Compromise (IoCs) into STIX 2.1 JSON objects, maps them to MITRE ATT&CK Technique IDs, and correlates indicators against live host-level Windows artifacts (network sockets and process trees).

---

## Key Features

- **Multi-IoC Threat Ingestion:** Uses Regex/NLP to extract IPv4 addresses, domains, SHA-256 payload hashes, and Windows Registry persistence keys.
- **MITRE ATT&CK Mapping:** Automatically maps extracted threat indicators to corresponding ATT&CK Tactic & Technique IDs (e.g., T1071.001, T1547.001).
- **Live Forensic Correlation:** Interfaces with Windows host artifacts (`Get-NetTCPConnection` and `Get-Process`) to trace live process execution and open C2 sockets.
- **Interactive Graph Engine:** Renders directed threat execution graphs using NetworkX and PyVis.
- **Automated Incident Reporting:** Generates downloadable SOC Forensic Summary PDF reports using ReportLab.
- **FastAPI Web Dashboard:** Provides a local web interface for threat ingestion and visual graph exploration.

---

## Tech Stack

- **Backend Framework:** FastAPI, Uvicorn
- **Data Modeling:** `stix2` (STIX 2.1 Standard)
- **Graph Visualization:** NetworkX, PyVis
- **Forensic PDF Generation:** ReportLab
- **Language:** Python 3.10+
- **Host Collector:** PowerShell

---

## Installation & Setup

```bash
# Clone the repository
git clone [https://github.com/your-username/AutoTrace-CTI.git](https://github.com/your-username/AutoTrace-CTI.git)
cd AutoTrace-CTI

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt