import nmap
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import requests
import json
import os
import sys
import time
import logging
import sqlite3
import socket
import subprocess
import re
import threading
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Image, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER
from flask import Flask, render_template_string, send_file

# ================================================
# CONFIGURATION — Edit only these values
# ================================================

NETWORK_RANGE      = "10.0.2.0/24"
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_HERE"
SCAN_INTERVAL      = 300   # seconds between scans (5 minutes)
LATENCY_THRESHOLD  = 200   # ms — flag device if RTT above this

TOPOLOGY_IMG = "network_topology.png"
PDF_REPORT   = "network_audit_report.pdf"
LOG_FILE     = "network_mapper.log"
DB_FILE      = "network_history.db"

# ================================================
# LOGGING SETUP
# ================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ================================================
# NETWORK ENGINEERING AI PLAYBOOK — 10 SECTIONS
# ================================================

NETWORK_PLAYBOOK = """
You are a senior Network Security Engineer and Network Auditor AI.

Your role is to analyze structured network scan data provided in JSON format
and produce a professional network audit report following a defined playbook.

You are a defensive network analysis assistant only.

You must strictly follow all sections below.

------------------------------------------------------------
SECTION 1 — INPUT VALIDATION
------------------------------------------------------------

1. Confirm the input is valid JSON.
2. Ensure required fields exist:
   - scan_time
   - network_range
   - total_devices
   - devices array containing ip, hostname, os, ports
3. If data is incomplete, note it in confidence_level only.
   Do NOT fabricate missing information under any circumstances.

------------------------------------------------------------
SECTION 2 — DEVICE CLASSIFICATION
------------------------------------------------------------

Classify each device as exactly one of:
- Gateway / Router
- Web Server
- Database Server
- File Server
- Windows Workstation
- Linux Workstation
- Network Printer
- IoT Device
- Unknown Device

Base classification ONLY on open ports and OS data provided.
Do NOT assume device type without clear evidence in the data.
When uncertain, always classify as Unknown Device.

------------------------------------------------------------
SECTION 3 — PORT RISK ASSESSMENT
------------------------------------------------------------

Classify each open port strictly using these definitions only:

CRITICAL (immediate action required):
- Port 23   : Telnet — unencrypted remote access
- Port 21   : FTP — unencrypted file transfer
- Port 512  : rexec — remote execution
- Port 513  : rlogin — remote login
- Port 514  : rsh — remote shell
- Port 1900 : UPnP — network exposure risk

HIGH (investigate and restrict):
- Port 445  : SMB — ransomware propagation vector
- Port 3389 : RDP — brute force target
- Port 5900 : VNC — remote desktop exposure
- Port 161  : SNMP — network information leakage
- Port 135  : RPC — Windows exploitation vector

MEDIUM (monitor and review):
- Port 80   : HTTP — unencrypted web traffic
- Port 8080 : HTTP alternate
- Port 3306 : MySQL — database exposure
- Port 5432 : PostgreSQL — database exposure
- Port 27017: MongoDB — database exposure

LOW (acceptable with proper configuration):
- Port 22   : SSH — encrypted remote access
- Port 443  : HTTPS — encrypted web
- Port 53   : DNS — name resolution
- Port 67   : DHCP — address assignment

Any port not listed above: classify as LOW unless evidence suggests otherwise.

------------------------------------------------------------
SECTION 4 — MISCONFIGURATION DETECTION
------------------------------------------------------------

Flag the following as confirmed misconfigurations:
- Telnet port 23 open anywhere = CRITICAL misconfiguration
- FTP port 21 open = HIGH misconfiguration
- More than 10 open ports on one device = over-exposed device
- RDP port 3389 exposed = HIGH risk
- Database ports 3306 / 5432 / 27017 exposed = HIGH risk
- Device with no identifiable OS but multiple open ports = suspicious
- Device with only HIGH and CRITICAL ports = unusual profile

Do NOT flag misconfigurations without evidence in the provided scan data.
Do NOT invent firewall rules or network configurations.

------------------------------------------------------------
SECTION 5 — RISK SCORING MODEL (0-100)
------------------------------------------------------------

Calculate risk score per device using ONLY data provided:

- Each CRITICAL risk port open: +30 points
- Each HIGH risk port open: +20 points
- Each MEDIUM risk port open: +10 points
- Unknown OS: +15 points
- More than 10 open ports: +20 points
- CRITICAL misconfiguration confirmed: +25 points

Cap total score at 100. Never go below 0.

Risk level classification:
0-29   = Low
30-59  = Medium
60-79  = High
80-100 = Critical

Always explain in analysis_reasoning exactly how score was calculated.

------------------------------------------------------------
SECTION 6 — NETWORK TOPOLOGY ASSESSMENT
------------------------------------------------------------

Assess the overall network based on ALL devices combined:
- Identify unexpected device types
- Flag devices that appear unusual
- Assess network segmentation adequacy
- Identify rogue or unidentified devices
- Determine overall attack surface

Base assessment ONLY on provided scan data.

------------------------------------------------------------
SECTION 7 — ESCALATION LOGIC
------------------------------------------------------------

Per device:
- risk_score >= 80: escalation_required = true
- risk_score < 80: escalation_required = false

For immediate_actions list:
- Critical device found: recommend immediate isolation
- Telnet open: recommend immediate port closure
- Overall High/Critical risk: recommend access control audit

------------------------------------------------------------
SECTION 8 — EXECUTIVE SUMMARY
------------------------------------------------------------

Write exactly 2-3 sentences in plain language:
- No technical jargon or port numbers
- Focus on business impact
- State the single most critical finding
- State the single most important recommended action

------------------------------------------------------------
SECTION 9 — OUTPUT FORMAT (STRICT)
------------------------------------------------------------

You must respond ONLY in this exact JSON format.
Do NOT include markdown.
Do NOT include backticks.
Do NOT include any text before or after the JSON.
Do NOT include conversational filler.

{
  "scan_summary": {
    "total_devices": 0,
    "critical_findings": 0,
    "overall_network_risk": "",
    "confidence_level": "",
    "executive_summary": ""
  },
  "devices": [
    {
      "ip": "",
      "device_type": "",
      "os_guess": "",
      "risk_score": 0,
      "risk_level": "",
      "escalation_required": false,
      "open_ports": [],
      "critical_ports": [],
      "analysis_reasoning": "",
      "findings": [],
      "recommendations": []
    }
  ],
  "network_recommendations": [],
  "immediate_actions": []
}

------------------------------------------------------------
SECTION 10 — GUARDRAILS
------------------------------------------------------------

You must:
- NEVER fabricate open ports not present in the scan data
- NEVER invent OS information not detected by the scanner
- NEVER assume device purpose without port-based evidence
- NEVER add findings without direct scan-based evidence
- NEVER hallucinate threat intelligence, CVEs, or exploit names
- NEVER speculate beyond the data provided
- NEVER assign a risk score without showing the calculation
- ALWAYS state uncertainty clearly in confidence_level
- ALWAYS maintain professional network engineering tone
- If a field has no applicable data, return empty string or empty array

Confidence levels:
Low    = OS unknown for most devices, minimal port data
Medium = OS known for some devices, reasonable port coverage
High   = OS identified, multiple ports, clear device profiles

You are a defensive network analysis system only.
Do not provide offensive security guidance or attack instructions.

End of instructions.
"""

# ================================================
# FLASK DASHBOARD
# ================================================

app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Network Monitor</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #0f0f1a; color: #e0e0e0; }
    .navbar { background: #1F4E79 !important; }
    .card { background: #1a1a2e; border: 1px solid #2d2d4e; }
    .card-header { background: #1F4E79; color: white; font-weight: bold; }
    .table { color: #e0e0e0; }
    .table-dark { background: #1a1a2e; }
    .badge-critical { background: #e74c3c; }
    .badge-high { background: #e67e22; }
    .badge-medium { background: #f39c12; }
    .badge-low { background: #27ae60; }
    .stat-card { text-align: center; padding: 20px; }
    .stat-number { font-size: 2.5rem; font-weight: bold; color: #3498db; }
    .risk-critical { color: #e74c3c; font-weight: bold; }
    .risk-high { color: #e67e22; font-weight: bold; }
    .risk-medium { color: #f39c12; font-weight: bold; }
    .risk-low { color: #27ae60; font-weight: bold; }
    th { color: #3498db; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container">
      <a class="navbar-brand" href="/">🔍 AI Network Monitor</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link text-white" href="/">Dashboard</a>
        <a class="nav-link text-white" href="/devices">Devices</a>
        <a class="nav-link text-white" href="/topology">Topology</a>
        <a class="nav-link text-white" href="/incidents">Incidents</a>
        <a class="nav-link text-white" href="/report">PDF Report</a>
      </div>
    </div>
  </nav>

  <div class="container mt-4">
    {% block content %}{% endblock %}
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

HOME_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Network Monitor — Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <meta http-equiv="refresh" content="60">
  <style>
    body { background: #0f0f1a; color: #e0e0e0; }
    .navbar { background: #1F4E79 !important; }
    .card { background: #1a1a2e; border: 1px solid #2d2d4e; color: #e0e0e0; }
    .card-header { background: #1F4E79; color: white; font-weight: bold; }
    .stat-number { font-size: 2.5rem; font-weight: bold; color: #3498db; }
    .risk-Critical { color: #e74c3c; font-weight: bold; }
    .risk-High { color: #e67e22; font-weight: bold; }
    .risk-Medium { color: #f39c12; font-weight: bold; }
    .risk-Low { color: #27ae60; font-weight: bold; }
    .risk-Unknown { color: #95a5a6; }
    .table { color: #e0e0e0; }
    th { color: #3498db; }
    .badge { font-size: 0.85rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="/">🔍 AI Network Monitor</a>
    <div class="navbar-nav ms-auto">
      <a class="nav-link text-white" href="/">Dashboard</a>
      <a class="nav-link text-white" href="/devices">Devices</a>
      <a class="nav-link text-white" href="/topology">Topology</a>
      <a class="nav-link text-white" href="/incidents">Incidents</a>
      <a class="nav-link text-white" href="/report">PDF Report</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h4 class="mb-1">Network: <code style="color:#3498db">{{ network_range }}</code></h4>
  <small class="text-muted">Last scan: {{ last_scan }} &nbsp;|&nbsp; Auto-refreshes every 60 seconds</small>

  <div class="row mt-3">
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number">{{ total_scans }}</div>
        <div>Total Scans</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number">{{ active_devices }}</div>
        <div>Active Devices</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number">{{ total_incidents }}</div>
        <div>Total Incidents</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number risk-{{ overall_risk }}">{{ overall_risk }}</div>
        <div>Network Risk</div>
      </div>
    </div>
  </div>

  <div class="row mt-4">
    <div class="col-md-8">
      <div class="card">
        <div class="card-header">Recent Scans</div>
        <div class="card-body p-0">
          <table class="table table-sm mb-0">
            <thead><tr><th>Time</th><th>Devices</th><th>Risk</th></tr></thead>
            <tbody>
              {% for scan in recent_scans %}
              <tr>
                <td>{{ scan.timestamp }}</td>
                <td>{{ scan.devices_found }}</td>
                <td class="risk-{{ scan.overall_risk }}">{{ scan.overall_risk }}</td>
              </tr>
              {% else %}
              <tr><td colspan="3" class="text-muted text-center p-3">No scans yet</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card">
        <div class="card-header">Recent Incidents</div>
        <div class="card-body p-0">
          <table class="table table-sm mb-0">
            <thead><tr><th>Type</th><th>IP</th></tr></thead>
            <tbody>
              {% for inc in recent_incidents %}
              <tr>
                <td><span class="badge bg-danger">{{ inc.incident_type }}</span></td>
                <td>{{ inc.ip }}</td>
              </tr>
              {% else %}
              <tr><td colspan="2" class="text-muted text-center p-3">No incidents</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>
"""

DEVICES_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Devices</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #0f0f1a; color: #e0e0e0; }
    .navbar { background: #1F4E79 !important; }
    .card { background: #1a1a2e; border: 1px solid #2d2d4e; }
    .card-header { background: #1F4E79; color: white; font-weight: bold; }
    .table { color: #e0e0e0; }
    th { color: #3498db; }
    .risk-Critical { color: #e74c3c; font-weight: bold; }
    .risk-High { color: #e67e22; font-weight: bold; }
    .risk-Medium { color: #f39c12; font-weight: bold; }
    .risk-Low { color: #27ae60; font-weight: bold; }
    .risk-Unknown { color: #95a5a6; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="/">🔍 AI Network Monitor</a>
    <div class="navbar-nav ms-auto">
      <a class="nav-link text-white" href="/">Dashboard</a>
      <a class="nav-link text-white" href="/devices">Devices</a>
      <a class="nav-link text-white" href="/topology">Topology</a>
      <a class="nav-link text-white" href="/incidents">Incidents</a>
      <a class="nav-link text-white" href="/report">PDF Report</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <div class="card">
    <div class="card-header">Active Devices — Last Scan</div>
    <div class="card-body p-0">
      <table class="table table-sm mb-0">
        <thead>
          <tr>
            <th>IP Address</th><th>Hostname</th><th>OS</th>
            <th>Open Ports</th><th>Latency</th>
            <th>Risk Score</th><th>Risk Level</th>
          </tr>
        </thead>
        <tbody>
          {% for d in devices %}
          <tr>
            <td><code>{{ d.ip }}</code></td>
            <td>{{ d.hostname }}</td>
            <td>{{ d.os[:30] }}</td>
            <td>{{ d.open_ports }}</td>
            <td>{% if d.latency_ms %}{{ d.latency_ms }}ms{% else %}—{% endif %}</td>
            <td>{{ d.risk_score }}/100</td>
            <td class="risk-{{ d.risk_level }}">{{ d.risk_level }}</td>
          </tr>
          {% else %}
          <tr><td colspan="7" class="text-center text-muted p-4">No scan data yet</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>
"""

INCIDENTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Incidents</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #0f0f1a; color: #e0e0e0; }
    .navbar { background: #1F4E79 !important; }
    .card { background: #1a1a2e; border: 1px solid #2d2d4e; }
    .card-header { background: #1F4E79; color: white; font-weight: bold; }
    .table { color: #e0e0e0; }
    th { color: #3498db; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="/">🔍 AI Network Monitor</a>
    <div class="navbar-nav ms-auto">
      <a class="nav-link text-white" href="/">Dashboard</a>
      <a class="nav-link text-white" href="/devices">Devices</a>
      <a class="nav-link text-white" href="/topology">Topology</a>
      <a class="nav-link text-white" href="/incidents">Incidents</a>
      <a class="nav-link text-white" href="/report">PDF Report</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <div class="card">
    <div class="card-header">Incident History</div>
    <div class="card-body p-0">
      <table class="table table-sm mb-0">
        <thead>
          <tr><th>Timestamp</th><th>Type</th><th>IP</th><th>Severity</th><th>Details</th></tr>
        </thead>
        <tbody>
          {% for inc in incidents %}
          <tr>
            <td>{{ inc.timestamp }}</td>
            <td><span class="badge bg-danger">{{ inc.incident_type }}</span></td>
            <td><code>{{ inc.ip }}</code></td>
            <td>
              {% if inc.severity == 'Critical' %}<span class="badge" style="background:#e74c3c">Critical</span>
              {% elif inc.severity == 'High' %}<span class="badge" style="background:#e67e22">High</span>
              {% elif inc.severity == 'Medium' %}<span class="badge" style="background:#f39c12">Medium</span>
              {% else %}<span class="badge" style="background:#27ae60">Low</span>{% endif %}
            </td>
            <td>{{ inc.details }}</td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="text-center text-muted p-4">No incidents recorded yet</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>
"""

TOPOLOGY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Network Topology</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #0f0f1a; color: #e0e0e0; }
    .navbar { background: #1F4E79 !important; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="/">🔍 AI Network Monitor</a>
    <div class="navbar-nav ms-auto">
      <a class="nav-link text-white" href="/">Dashboard</a>
      <a class="nav-link text-white" href="/devices">Devices</a>
      <a class="nav-link text-white" href="/topology">Topology</a>
      <a class="nav-link text-white" href="/incidents">Incidents</a>
      <a class="nav-link text-white" href="/report">PDF Report</a>
    </div>
  </div>
</nav>
<div class="container mt-4 text-center">
  <h5 class="mb-3">Network Topology Map — Last Scan</h5>
  {% if topology_exists %}
  <img src="/topology_img" style="max-width:100%; border-radius:8px;">
  {% else %}
  <p class="text-muted mt-5">Topology not yet generated. Wait for first scan to complete.</p>
  {% endif %}
</div>
</body>
</html>
"""

# ================================================
# FLASK ROUTES
# ================================================

@app.route('/')
def home():
    conn   = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute(
            "SELECT timestamp, devices_found, overall_risk "
            "FROM scans ORDER BY id DESC LIMIT 5"
        )
        rows = cursor.fetchall()
        recent_scans = [
            {"timestamp": r[0], "devices_found": r[1], "overall_risk": r[2]}
            for r in rows
        ]

        cursor.execute(
            "SELECT COUNT(*) FROM devices WHERE scan_id = "
            "(SELECT MAX(id) FROM scans)"
        )
        active_devices = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]

        cursor.execute(
            "SELECT overall_risk FROM scans ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        overall_risk = row[0] if row else "Unknown"

        cursor.execute(
            "SELECT incident_type, ip FROM incidents ORDER BY id DESC LIMIT 5"
        )
        inc_rows = cursor.fetchall()
        recent_incidents = [
            {"incident_type": r[0], "ip": r[1]} for r in inc_rows
        ]

        cursor.execute(
            "SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        last_scan = row[0] if row else "Never"

    except sqlite3.OperationalError:
        total_scans = active_devices = total_incidents = 0
        overall_risk = "Unknown"
        recent_scans = recent_incidents = []
        last_scan = "Never"
    finally:
        conn.close()

    return render_template_string(HOME_HTML,
        network_range=NETWORK_RANGE,
        last_scan=last_scan,
        total_scans=total_scans,
        active_devices=active_devices,
        total_incidents=total_incidents,
        overall_risk=overall_risk,
        recent_scans=recent_scans,
        recent_incidents=recent_incidents
    )

@app.route('/devices')
def devices_page():
    conn   = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT ip, hostname, os, open_ports, latency_ms, risk_score, risk_level "
            "FROM devices WHERE scan_id = (SELECT MAX(id) FROM scans)"
        )
        rows = cursor.fetchall()
        devices = [
            {
                "ip": r[0], "hostname": r[1], "os": r[2],
                "open_ports": r[3], "latency_ms": r[4],
                "risk_score": r[5], "risk_level": r[6]
            }
            for r in rows
        ]
    except sqlite3.OperationalError:
        devices = []
    finally:
        conn.close()
    return render_template_string(DEVICES_HTML, devices=devices)

@app.route('/incidents')
def incidents_page():
    conn   = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT timestamp, incident_type, ip, severity, details "
            "FROM incidents ORDER BY id DESC LIMIT 100"
        )
        rows = cursor.fetchall()
        incidents = [
            {
                "timestamp": r[0], "incident_type": r[1],
                "ip": r[2], "severity": r[3], "details": r[4]
            }
            for r in rows
        ]
    except sqlite3.OperationalError:
        incidents = []
    finally:
        conn.close()
    return render_template_string(INCIDENTS_HTML, incidents=incidents)

@app.route('/topology')
def topology_page():
    return render_template_string(
        TOPOLOGY_HTML,
        topology_exists=os.path.exists(TOPOLOGY_IMG)
    )

@app.route('/topology_img')
def topology_img():
    if os.path.exists(TOPOLOGY_IMG):
        return send_file(
            os.path.abspath(TOPOLOGY_IMG),
            mimetype='image/png'
        )
    return "Not found", 404

@app.route('/report')
def report():
    if os.path.exists(PDF_REPORT):
        return send_file(
            os.path.abspath(PDF_REPORT),
            mimetype='application/pdf'
        )
    return "Report not yet generated", 404

# ================================================
# DATABASE SETUP
# ================================================

def init_database():
    conn   = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            network_range   TEXT,
            devices_found   INTEGER,
            overall_risk    TEXT,
            confidence_level TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            timestamp   TEXT,
            ip          TEXT,
            hostname    TEXT,
            os          TEXT,
            risk_score  INTEGER,
            risk_level  TEXT,
            open_ports  TEXT,
            latency_ms  REAL,
            status      TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            incident_type   TEXT,
            ip              TEXT,
            details         TEXT,
            severity        TEXT
        )
    ''')

    conn.commit()
    conn.close()
    log.info(f"Database initialised → {DB_FILE}")

# ================================================
# STARTUP CHECK
# ================================================

def startup_check():
    if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        raise ValueError("Gemini API key is missing. Set GEMINI_API_KEY in configuration.")

    if os.geteuid() != 0:
        raise PermissionError(
            "Root privileges required for Nmap OS detection.\n"
            "Run with: sudo python3 network_mapper.py"
        )

    init_database()

    with open(LOG_FILE, "a") as f:
        f.write("\n" + "=" * 60 + "\n")
        f.write(f" NEW SESSION — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f" Network Range: {NETWORK_RANGE}\n")
        f.write("=" * 60 + "\n")

    log.info("Startup check passed. Running as root.")

# ================================================
# STEP 1 — SCAN NETWORK
# ================================================

def scan_network(network_range):
    log.info(f"Scanning network: {network_range}")
    log.info("Flags: -O (OS) -sV (versions) -F (fast) --open -T4")
    log.info("Estimated time: 2-4 minutes...")

    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments="-O -sV -F --open -T4")

    devices = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            device = {
                "ip":       host,
                "hostname": nm[host].hostname() or "Unknown",
                "state":    "up",
                "os":       "Unknown",
                "ports":    []
            }

            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                device['os'] = nm[host]['osmatch'][0]['name']

            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info = nm[host][proto][port]
                    if info['state'] == 'open':
                        device['ports'].append({
                            "port":     port,
                            "protocol": proto,
                            "service":  info.get('name', 'unknown'),
                            "version":  info.get('version', ''),
                            "state":    "open"
                        })

            devices.append(device)
            log.info(f"  Found: {host} | OS: {device['os'][:25]} "
                     f"| Ports: {len(device['ports'])}")

    log.info(f"Scan complete — {len(devices)} active devices found.")
    return devices

# ================================================
# STEP 2 — ENHANCED CHECKS
# ================================================

def get_latency(host):
    """Ping the host and return RTT in milliseconds."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r'time[=<](\d+\.?\d*)', result.stdout)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return None

def check_dns(ip):
    """Check for DNS misconfiguration — forward/reverse DNS mismatch."""
    issues = []
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        try:
            forward_ip = socket.gethostbyname(hostname)
            if forward_ip != ip:
                issues.append(
                    f"DNS mismatch: {hostname} resolves to "
                    f"{forward_ip}, not {ip}"
                )
        except socket.gaierror:
            issues.append(
                f"Forward DNS failed for reverse hostname: {hostname}"
            )
    except socket.herror:
        pass  # No reverse DNS — common and not always an issue
    return issues

def check_duplicate_ips(devices):
    """Detect if same IP appears multiple times in scan results."""
    issues = []
    seen = {}
    for device in devices:
        ip = device['ip']
        if ip in seen:
            issues.append({
                "type": "DUPLICATE_IP",
                "ip": ip,
                "details": f"IP {ip} appeared multiple times in scan",
                "severity": "High"
            })
        else:
            seen[ip] = device
    return issues

def run_enhanced_checks(devices):
    """Run latency, DNS and duplicate IP checks on all devices."""
    log.info("Running enhanced checks (latency, DNS, duplicate IP)...")

    enhanced_issues = []
    duplicate_issues = check_duplicate_ips(devices)
    enhanced_issues.extend(duplicate_issues)

    for device in devices:
        ip = device['ip']

        # Latency check
        rtt = get_latency(ip)
        device['latency_ms'] = rtt

        if rtt is not None:
            if rtt > LATENCY_THRESHOLD:
                log.warning(
                    f"HIGH LATENCY: {ip} RTT={rtt}ms "
                    f"(threshold {LATENCY_THRESHOLD}ms)"
                )
                enhanced_issues.append({
                    "type":     "HIGH_LATENCY",
                    "ip":       ip,
                    "details":  f"RTT {rtt}ms exceeds threshold {LATENCY_THRESHOLD}ms",
                    "severity": "Medium"
                })
        else:
            device['latency_ms'] = None

        # DNS check
        dns_issues = check_dns(ip)
        for issue in dns_issues:
            log.warning(f"DNS ISSUE on {ip}: {issue}")
            enhanced_issues.append({
                "type":     "DNS_MISMATCH",
                "ip":       ip,
                "details":  issue,
                "severity": "Medium"
            })

    return devices, enhanced_issues

# ================================================
# STEP 3 — BASELINE COMPARISON
# ================================================

def get_last_scan_devices():
    """Get device IPs and ports from the most recent scan in SQLite."""
    try:
        conn   = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip, open_ports FROM devices "
            "WHERE scan_id = (SELECT MAX(id) FROM scans)"
        )
        rows = cursor.fetchall()
        conn.close()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}

def compare_with_baseline(current_devices, last_devices):
    """
    Compare current scan against last scan.
    Returns list of incident dicts for:
      - new devices
      - offline devices
      - new ports opened
    """
    incidents = []
    current_ips = {d['ip'] for d in current_devices}

    # New devices
    for device in current_devices:
        ip = device['ip']
        if ip not in last_devices:
            if last_devices:  # Only alert if we have a baseline
                log.warning(f"NEW DEVICE detected: {ip}")
                incidents.append({
                    "type":     "NEW_DEVICE",
                    "ip":       ip,
                    "details":  f"New device {ip} appeared on network. "
                                f"OS: {device['os']}, "
                                f"Ports: {len(device['ports'])} open",
                    "severity": "High"
                })

    # Offline devices
    for ip in last_devices:
        if ip not in current_ips:
            log.warning(f"DEVICE OFFLINE: {ip}")
            incidents.append({
                "type":     "DEVICE_OFFLINE",
                "ip":       ip,
                "details":  f"Device {ip} was online in previous scan but is now unreachable",
                "severity": "High"
            })

    # New ports opened
    for device in current_devices:
        ip = device['ip']
        if ip in last_devices:
            prev_ports_str = last_devices[ip] or ""
            prev_ports = set(
                p.strip() for p in prev_ports_str.split(',')
                if p.strip()
            )
            curr_ports = {str(p['port']) for p in device['ports']}
            new_ports  = curr_ports - prev_ports

            for port in new_ports:
                severity = "Critical" if int(port) in [21, 23, 512, 513, 514] else "Medium"
                log.warning(f"NEW PORT on {ip}: port {port} opened")
                incidents.append({
                    "type":     "NEW_PORT",
                    "ip":       ip,
                    "details":  f"Port {port} newly opened on {ip}",
                    "severity": severity
                })

    return incidents

# ================================================
# STEP 4 — BUILD TOPOLOGY
# ================================================

def classify_device(device):
    ports  = [p['port'] for p in device['ports']]
    os_str = device['os'].lower()
    ip     = device['ip']

    if ip in ['10.0.2.2', '10.0.2.1', '192.168.1.1', '192.168.0.1']:
        return "gateway"
    elif any(p in ports for p in [80, 443, 8080, 8443]):
        return "server"
    elif 'windows' in os_str:
        return "windows"
    elif any(k in os_str for k in ['linux','unix','ubuntu','debian','kali']):
        return "linux"
    elif any(p in ports for p in [9100, 515, 631]):
        return "printer"
    else:
        return "unknown"

def build_topology(devices, offline_ips=None):
    if offline_ips is None:
        offline_ips = []

    log.info("Building network topology graph...")
    G = nx.Graph()

    gateway = "10.0.2.2"
    G.add_node(gateway, device_type="gateway", label="Gateway\n10.0.2.2", offline=False)

    for device in devices:
        ip       = device['ip']
        hostname = device['hostname']
        label    = f"{ip}\n{hostname[:14]}" if hostname != 'Unknown' else ip
        G.add_node(ip,
            device_type=classify_device(device),
            label=label,
            offline=(ip in offline_ips)
        )
        if ip != gateway:
            G.add_edge(gateway, ip)

    # Add offline devices to graph (greyed out)
    for ip in offline_ips:
        if ip not in G.nodes():
            G.add_node(ip,
                device_type="offline",
                label=f"{ip}\n[OFFLINE]",
                offline=True
            )
            G.add_edge(gateway, ip)

    return G

# ================================================
# STEP 5 — DRAW TOPOLOGY
# ================================================

def draw_topology(G, output_file):
    log.info("Rendering network topology diagram...")

    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_facecolor('#1a1a2e')
    fig.patch.set_facecolor('#1a1a2e')

    color_map = {
        "gateway": "#e74c3c",
        "server":  "#3498db",
        "windows": "#2ecc71",
        "linux":   "#f39c12",
        "printer": "#9b59b6",
        "offline": "#555555",
        "unknown": "#95a5a6"
    }

    node_colors = []
    for n in G.nodes():
        dtype = G.nodes[n].get('device_type', 'unknown')
        node_colors.append(color_map.get(dtype, "#95a5a6"))

    n = len(G.nodes())
    if n == 0:
        return
    elif n <= 4:
        pos = nx.circular_layout(G)
    elif n <= 10:
        pos = nx.shell_layout(G)
    else:
        pos = nx.spring_layout(G, k=2.5, seed=42)

    # Draw edges — dashed for offline
    for u, v in G.edges():
        offline = (
            G.nodes[u].get('offline', False) or
            G.nodes[v].get('offline', False)
        )
        nx.draw_networkx_edges(
            G, pos, edgelist=[(u, v)], ax=ax,
            edge_color='#555555' if offline else '#4a4a6a',
            width=2, alpha=0.6,
            style='dotted' if offline else 'dashed'
        )

    nx.draw_networkx_nodes(G, pos, ax=ax,
        node_color=node_colors, node_size=3000, alpha=0.95)

    labels = nx.get_node_attributes(G, 'label')
    if not labels:
        labels = {n: n for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, ax=ax,
        font_size=8, font_color='white', font_weight='bold')

    legend_elements = [
        mpatches.Patch(color=color_map['gateway'], label='Gateway / Router'),
        mpatches.Patch(color=color_map['server'],  label='Server'),
        mpatches.Patch(color=color_map['windows'], label='Windows Device'),
        mpatches.Patch(color=color_map['linux'],   label='Linux Device'),
        mpatches.Patch(color=color_map['offline'], label='Offline Device'),
        mpatches.Patch(color=color_map['unknown'], label='Unknown Device'),
    ]
    ax.legend(handles=legend_elements, loc='upper left',
              facecolor='#2d2d4e', labelcolor='white',
              fontsize=9, framealpha=0.9)

    ax.set_title(
        f"Network Topology  —  {datetime.now().strftime('%Y-%m-%d %H:%M')}  "
        f"|  Range: {NETWORK_RANGE}",
        color='white', fontsize=13, fontweight='bold', pad=15
    )
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='#1a1a2e')
    plt.close()
    log.info(f"Topology saved → {output_file}")

# ================================================
# STEP 6 — GEMINI AI ANALYSIS
# ================================================

def analyze_with_gemini(devices):
    log.info("Sending scan data to Gemini AI...")

    scan_data = {
        "scan_time":     datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "network_range": NETWORK_RANGE,
        "total_devices": len(devices),
        "devices":       devices
    }

    prompt = (NETWORK_PLAYBOOK +
              "\n\nNetwork scan data to analyze:\n" +
              json.dumps(scan_data, indent=2))

    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        f"models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    )

    for attempt in range(1, 4):
        try:
            log.info(f"Gemini API attempt {attempt}/3...")
            response = requests.post(url, json=payload, timeout=60)
            if response.status_code == 429:
                wait = 30 * attempt
                log.warning(f"Rate limited — waiting {wait}s...")
                time.sleep(wait)
                continue
            response.raise_for_status()
            break
        except requests.exceptions.RequestException as e:
            if attempt == 3:
                raise RuntimeError(f"Gemini API failed: {e}")
            time.sleep(30)

    data = response.json()
    try:
        raw = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        raise RuntimeError(f"Unexpected Gemini response: {data}")

    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
        raw = raw.rsplit("```", 1)[0].strip()

    try:
        analysis = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"Gemini returned invalid JSON:\n{raw}")

    print("\n[+] ===== GEMINI NETWORK ANALYSIS =====")
    print(json.dumps(analysis, indent=2))
    print("[+] =====================================\n")

    return analysis

# ================================================
# STEP 7 — GENERATE PDF REPORT
# ================================================

def generate_pdf_report(devices, analysis, topology_img, incidents):
    log.info("Generating PDF report...")

    doc = SimpleDocTemplate(
        PDF_REPORT, pagesize=A4,
        rightMargin=50, leftMargin=50,
        topMargin=50, bottomMargin=50
    )

    styles = getSampleStyleSheet()
    story  = []

    title_s = ParagraphStyle('T', parent=styles['Title'],
        fontSize=20, textColor=colors.HexColor('#1F4E79'),
        spaceAfter=6, alignment=TA_CENTER)
    sub_s   = ParagraphStyle('S', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#555555'),
        spaceAfter=15, alignment=TA_CENTER)
    head_s  = ParagraphStyle('H', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor('#1F4E79'),
        spaceBefore=15, spaceAfter=8)
    norm_s  = ParagraphStyle('N', parent=styles['Normal'],
        fontSize=10, spaceAfter=6, leading=14)
    find_s  = ParagraphStyle('F', parent=styles['Normal'],
        fontSize=10, spaceAfter=4, leftIndent=15, leading=14)
    inc_s   = ParagraphStyle('I', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#e74c3c'),
        spaceAfter=4, leftIndent=10, leading=14)

    risk_colors = {
        "Low":      colors.HexColor('#27ae60'),
        "Medium":   colors.HexColor('#f39c12'),
        "High":     colors.HexColor('#e67e22'),
        "Critical": colors.HexColor('#e74c3c')
    }

    # Title
    story.append(Paragraph(
        "Network Topology &amp; Security Audit Report", title_s))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}  "
        f"|  Network: {NETWORK_RANGE}  |  Powered by Gemini AI",
        sub_s
    ))
    story.append(HRFlowable(width="100%", thickness=2,
        color=colors.HexColor('#1F4E79')))
    story.append(Spacer(1, 15))

    # Executive Summary
    summary = analysis.get("scan_summary", {})
    story.append(Paragraph("Executive Summary", head_s))
    story.append(Paragraph(
        summary.get("executive_summary", "No summary available."), norm_s))
    story.append(Spacer(1, 10))

    # Stats table
    stats = [
        ["Metric", "Value"],
        ["Total Devices",    str(summary.get("total_devices", len(devices)))],
        ["Critical Findings", str(summary.get("critical_findings", 0))],
        ["Overall Risk",     summary.get("overall_network_risk", "Unknown")],
        ["AI Confidence",    summary.get("confidence_level", "Unknown")],
        ["Incidents Found",  str(len(incidents))],
        ["Scan Time",        datetime.now().strftime('%Y-%m-%d %H:%M')],
        ["Network",          NETWORK_RANGE],
    ]
    t = Table(stats, colWidths=[250, 250])
    t.setStyle(TableStyle([
        ('BACKGROUND',     (0,0), (-1,0),  colors.HexColor('#1F4E79')),
        ('TEXTCOLOR',      (0,0), (-1,0),  colors.white),
        ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',       (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
            [colors.white, colors.HexColor('#f0f4f8')]),
        ('GRID',           (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING',        (0,0), (-1,-1), 8),
        ('FONTNAME',       (0,1), (0,-1),  'Helvetica-Bold'),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Immediate Actions
    immediate = analysis.get("immediate_actions", [])
    if immediate:
        story.append(Paragraph("Immediate Actions Required", head_s))
        story.append(HRFlowable(width="100%", thickness=1,
            color=colors.HexColor('#e74c3c')))
        story.append(Spacer(1, 8))
        for i, action in enumerate(immediate, 1):
            story.append(Paragraph(f"<b>{i}. {action}</b>", inc_s))
        story.append(Spacer(1, 15))

    # Incidents
    if incidents:
        story.append(Paragraph("Incidents Detected This Scan", head_s))
        story.append(HRFlowable(width="100%", thickness=1,
            color=colors.HexColor('#dddddd')))
        story.append(Spacer(1, 8))
        for inc in incidents:
            story.append(Paragraph(
                f"<b>[{inc['type']}]</b> {inc['ip']} — {inc['details']}",
                find_s
            ))
        story.append(Spacer(1, 15))

    # Topology
    story.append(Paragraph("Network Topology Map", head_s))
    if os.path.exists(topology_img):
        try:
            img = Image(topology_img, width=5*inch, height=3.5*inch)
            img.hAlign = 'CENTER'
            story.append(img)
        except Exception as e:
            log.warning(f"Could not embed topology: {e}")
            story.append(Paragraph(
                "(Topology diagram unavailable — see network_topology.png)",
                norm_s
            ))
    story.append(Spacer(1, 15))

    # Device Analysis
    story.append(Paragraph("Device-by-Device Analysis", head_s))
    story.append(HRFlowable(width="100%", thickness=1,
        color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 8))

    for device in analysis.get("devices", []):
        risk      = device.get("risk_level", "Unknown")
        r_color   = risk_colors.get(risk, colors.grey)
        esc       = device.get("escalation_required", False)
        esc_badge = "  ⚠ ESCALATION REQUIRED" if esc else ""

        story.append(Paragraph(
            f"<b>{device.get('ip','?')} — "
            f"{device.get('device_type','Unknown')}{esc_badge}</b>",
            ParagraphStyle('DH', parent=styles['Normal'],
                fontSize=11, textColor=colors.HexColor('#1F4E79'),
                spaceBefore=12, spaceAfter=5)
        ))

        ports_str = ", ".join(str(p) for p in device.get("open_ports",[])) or "None"
        crit_str  = ", ".join(str(p) for p in device.get("critical_ports",[])) or "None"

        dev_t = Table([
            ["OS",         device.get("os_guess","Unknown"),
             "Risk Score", f"{device.get('risk_score',0)}/100"],
            ["Risk Level", risk,
             "Critical Ports", crit_str[:40]],
            ["Open Ports", ports_str[:60],
             "Escalation", "YES" if esc else "NO"],
        ], colWidths=[85, 185, 85, 140])
        dev_t.setStyle(TableStyle([
            ('FONTNAME',   (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTNAME',   (2,0),(2,-1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0),(-1,-1), 9),
            ('BACKGROUND', (0,0),(-1,-1), colors.HexColor('#f8f9fa')),
            ('GRID',       (0,0),(-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('PADDING',    (0,0),(-1,-1), 6),
            ('TEXTCOLOR',  (1,1),(1,1),  r_color),
            ('FONTNAME',   (1,1),(1,1),  'Helvetica-Bold'),
        ]))
        story.append(dev_t)
        story.append(Spacer(1, 5))

        reasoning = device.get("analysis_reasoning", "")
        if reasoning:
            story.append(Paragraph(
                f"<i>{reasoning}</i>",
                ParagraphStyle('R', parent=styles['Normal'],
                    fontSize=9, textColor=colors.HexColor('#666666'),
                    spaceAfter=5, leftIndent=10, leading=13)
            ))

        for f in device.get("findings", []):
            story.append(Paragraph(f"• {f}", find_s))
        for r in device.get("recommendations", []):
            story.append(Paragraph(f"→ {r}", find_s))

    story.append(Spacer(1, 15))

    # Network Recommendations
    story.append(Paragraph("Overall Network Recommendations", head_s))
    story.append(HRFlowable(width="100%", thickness=1,
        color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 8))
    for i, rec in enumerate(analysis.get("network_recommendations", []), 1):
        story.append(Paragraph(f"{i}. {rec}", norm_s))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1,
        color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "AI-Powered Network Topology Mapper &amp; Health Monitor  |  "
        "Built by Praneeth Pentakota  |  github.com/Praneeth-oss",
        ParagraphStyle('Footer', parent=styles['Normal'],
            fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    log.info(f"PDF report saved → {PDF_REPORT}")

# ================================================
# STEP 8 — DISCORD ALERT
# ================================================

def send_discord_alert(analysis, device_count, incidents, cycle):
    if not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "YOUR_DISCORD_WEBHOOK_HERE":
        log.info("No Discord webhook — skipping.")
        return

    summary  = analysis.get("scan_summary", {})
    risk     = summary.get("overall_network_risk", "Unknown")
    critical = summary.get("critical_findings", 0)
    emoji    = "🔴" if risk in ["Critical","High"] else "🟡" if risk == "Medium" else "🟢"

    # Build incident summary
    inc_lines = ""
    if incidents:
        inc_lines = "\n".join(
            f"  ⚠ [{i['type']}] {i['ip']}" for i in incidents[:5]
        )
        inc_lines = f"\n**Incidents:**\n{inc_lines}"

    message = {"content": (
        f"{emoji} **NETWORK SCAN CYCLE {cycle} COMPLETE**\n"
        f"**Network:** `{NETWORK_RANGE}`\n"
        f"**Active Devices:** {device_count}\n"
        f"**Overall Risk:** {risk}\n"
        f"**Critical Findings:** {critical}\n"
        f"**Incidents This Scan:** {len(incidents)}"
        f"{inc_lines}\n"
        f"**Dashboard:** http://localhost:5000"
    )}

    try:
        r = requests.post(DISCORD_WEBHOOK, json=message, timeout=10)
        if r.status_code == 204:
            log.info("Discord alert sent.")
        else:
            log.warning(f"Discord returned: {r.status_code}")
    except Exception as e:
        log.error(f"Discord failed: {e}")

# ================================================
# STEP 9 — SAVE TO SQLITE
# ================================================

def save_to_sqlite(devices, analysis, incidents):
    conn   = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()

    summary = analysis.get("scan_summary", {})
    ts      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Insert scan
    cursor.execute(
        "INSERT INTO scans (timestamp, network_range, devices_found, "
        "overall_risk, confidence_level) VALUES (?,?,?,?,?)",
        (
            ts,
            NETWORK_RANGE,
            len(devices),
            summary.get("overall_network_risk", "Unknown"),
            summary.get("confidence_level", "Unknown")
        )
    )
    scan_id = cursor.lastrowid

    # Build a risk lookup from Gemini analysis
    risk_lookup = {}
    for d in analysis.get("devices", []):
        risk_lookup[d.get("ip","")] = {
            "risk_score": d.get("risk_score", 0),
            "risk_level": d.get("risk_level", "Unknown")
        }

    # Insert devices
    for device in devices:
        ip         = device['ip']
        ports_str  = ",".join(str(p['port']) for p in device['ports'])
        risk_info  = risk_lookup.get(ip, {})
        cursor.execute(
            "INSERT INTO devices (scan_id, timestamp, ip, hostname, os, "
            "risk_score, risk_level, open_ports, latency_ms, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                scan_id, ts, ip,
                device.get('hostname', 'Unknown'),
                device.get('os', 'Unknown'),
                risk_info.get('risk_score', 0),
                risk_info.get('risk_level', 'Unknown'),
                ports_str,
                device.get('latency_ms'),
                'up'
            )
        )

    # Insert incidents
    for inc in incidents:
        cursor.execute(
            "INSERT INTO incidents (timestamp, incident_type, ip, details, severity) "
            "VALUES (?,?,?,?,?)",
            (ts, inc['type'], inc['ip'], inc['details'], inc['severity'])
        )

    conn.commit()
    conn.close()
    log.info(f"Scan cycle saved to SQLite (scan_id={scan_id}, "
             f"{len(incidents)} incidents)")

# ================================================
# FLASK THREAD
# ================================================

def run_flask():
    import warnings
    warnings.filterwarnings('ignore')
    app.run(host='0.0.0.0', port=5000,
            debug=False, use_reloader=False)

# ================================================
# MAIN MONITORING LOOP
# ================================================

def main():
    print("=" * 60)
    print("   AI NETWORK TOPOLOGY MAPPER & HEALTH MONITOR")
    print(f"   Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Network:  {NETWORK_RANGE}")
    print(f"   Interval: every {SCAN_INTERVAL//60} minutes")
    print(f"   Dashboard: http://localhost:5000")
    print("   Press Ctrl+C to stop")
    print("=" * 60)

    try:
        startup_check()
    except (ValueError, PermissionError) as e:
        log.error(str(e))
        sys.exit(1)

    # Start Flask dashboard in background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    log.info("Flask dashboard running at http://localhost:5000")

    cycle = 1

    while True:
        try:
            log.info(f"\n{'='*50}")
            log.info(f"SCAN CYCLE {cycle} — {datetime.now().strftime('%H:%M:%S')}")
            log.info(f"{'='*50}")

            # Get last scan for comparison
            last_devices = get_last_scan_devices()

            # Step 1: Nmap scan
            current_devices = scan_network(NETWORK_RANGE)

            if not current_devices:
                log.warning("No devices found this cycle. Check network range.")
                time.sleep(SCAN_INTERVAL)
                cycle += 1
                continue

            # Step 2: Enhanced checks
            current_devices, enhanced_issues = run_enhanced_checks(current_devices)

            # Step 3: Baseline comparison
            baseline_incidents = compare_with_baseline(current_devices, last_devices)
            all_incidents      = baseline_incidents + enhanced_issues

            if all_incidents:
                log.warning(f"{len(all_incidents)} incident(s) detected this cycle!")
            else:
                log.info("No incidents detected — network is clean.")

            # Step 4 & 5: Topology
            offline_ips = [i['ip'] for i in all_incidents if i['type'] == 'DEVICE_OFFLINE']
            G = build_topology(current_devices, offline_ips)
            draw_topology(G, TOPOLOGY_IMG)

            # Step 6: Gemini AI analysis
            analysis = analyze_with_gemini(current_devices)

            # Step 7: PDF report
            generate_pdf_report(current_devices, analysis, TOPOLOGY_IMG, all_incidents)

            # Step 8: Discord alert
            send_discord_alert(analysis, len(current_devices), all_incidents, cycle)

            # Step 9: Save to SQLite
            save_to_sqlite(current_devices, analysis, all_incidents)

            # Final summary
            risk = analysis.get('scan_summary',{}).get('overall_network_risk','?')
            print(f"\n{'='*60}")
            print(f"   CYCLE {cycle} COMPLETE")
            print(f"   Active devices:   {len(current_devices)}")
            print(f"   Network risk:     {risk}")
            print(f"   Incidents:        {len(all_incidents)}")
            print(f"   Topology:         {TOPOLOGY_IMG}")
            print(f"   Report:           {PDF_REPORT}")
            print(f"   Dashboard:        http://localhost:5000")
            print(f"   Next scan in:     {SCAN_INTERVAL//60} minutes")
            print(f"{'='*60}\n")

            log.info(f"Cycle {cycle} complete. Sleeping {SCAN_INTERVAL}s...")
            cycle += 1
            time.sleep(SCAN_INTERVAL)

        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped by user. Goodbye.")
            break

        except Exception as e:
            log.error(f"Error in cycle {cycle}: {e}")
            log.info("Restarting cycle in 60 seconds...")
            time.sleep(60)
            cycle += 1

if __name__ == "__main__":
    main()
