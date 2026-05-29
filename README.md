# AI-Powered Network Security Monitoring & Topology Audit System

Automated network security monitoring platform — continuous Nmap scanning, local Python risk engine, CVE correlation via NVD API, ARP-verified topology mapping, incident detection, SQLite history, Flask dashboard with auth, and Gemini AI audit reports.

## What It Does

- Scans network every 5 minutes using Nmap — discovers devices, open ports, OS, service versions
- Local Python risk engine scores every device (0-100) independently before AI involvement
- CVE lookup via NVD API for detected service versions — surfaces known vulnerabilities
- ARP table parsing + MAC vendor lookup — real topology, not assumed
- Detects new devices, offline devices, new ports opened vs baseline
- Checks latency, DNS misconfigurations, duplicate IPs
- Gemini AI generates professional audit report with MITRE ATT&CK T1046 mapping
- Flask dashboard with SHA-256 login — device inventory, topology map, incident history
- PDF audit report via ReportLab
- Discord webhook alerts on every scan cycle

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core automation |
| Nmap + python-nmap | Network discovery and port scanning |
| NetworkX + Matplotlib | Topology graph building and visualisation |
| NVD API | Real-time CVE lookup |
| Google Gemini 2.5 Flash | AI-powered audit summarisation |
| SQLite | Historical scan storage |
| Flask | Web dashboard with authentication |
| ReportLab | PDF report generation |
| Discord Webhooks | Real-time alerting |

## Screenshots

### Dashboard Home
![Dashboard](screenshots/dashboard-home.png)

### Device Inventory
![Devices](screenshots/dashboard-devices.png)

### Network Topology Map
![Topology](screenshots/dashboard-topology.png)

### Gemini AI Analysis
![Gemini](screenshots/gemini-analysis.png)

### PDF Audit Report
![PDF](screenshots/pdf-report-page1.png)

### SQLite Scan History
![SQLite](screenshots/sqlite-history.png)

## Run

sudo python3 network_mapper.py

Dashboard: http://localhost:5000

## Disclaimer

For educational and defensive security purposes only. Run only on networks you own or have explicit permission to scan.

## Author

Praneeth Pentakota | github.com/Praneeth-oss | linkedin.com/in/praneethpentakota
