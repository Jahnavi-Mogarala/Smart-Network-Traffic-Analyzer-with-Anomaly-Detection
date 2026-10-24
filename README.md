# Smart Network Traffic Analyzer

### Network visibility, traffic intelligence, and anomaly detection from a single dashboard.

A full-stack network monitoring and analysis platform built to inspect packet captures, understand protocol behaviour, identify unusual traffic patterns, and turn raw network data into useful security insights.

The application supports both **PCAP/PCAPNG analysis** and **live network capture**, providing an interactive dashboard for packet inspection, protocol statistics, anomaly alerts, historical analysis, and downloadable reports.

---
https://sproutmarkup.com/view/312e6520aa7f4e76a9d11e426144b03a

## Overview

Modern networks generate thousands of packets every second. Looking through them manually is slow, repetitive, and often makes unusual behaviour difficult to notice.

**Smart Network Traffic Analyzer** was built to make that process easier.

Instead of treating packet captures as raw logs, the platform converts network traffic into structured information that can be explored visually.

It can:

- inspect uploaded packet captures
- monitor live network traffic
- classify common protocols
- calculate traffic statistics
- identify suspicious traffic patterns
- generate anomaly alerts
- maintain analysis history
- export findings as PDF, CSV, or JSON

The goal is simple:

> **Capture → Understand → Detect → Investigate → Report**

---

# Key Features

## Live Network Monitoring

Capture traffic directly from available network interfaces and monitor packet activity during a configurable capture window.

The live monitor supports:

- interface selection
- controlled capture duration
- capture status monitoring
- manual capture termination
- automatic packet processing

Live capture requires the appropriate operating-system permissions.

---

## PCAP / PCAPNG Analysis

Upload packet captures collected using tools such as Wireshark and inspect them through the web interface.

The analyzer validates uploaded files before processing them and supports standard:

```text
.pcap
.pcapng
```

Uploaded capture files are parsed and removed after processing rather than being permanently retained.

---

## Packet Explorer

Investigate captured packets without manually navigating a raw capture file.

Packet information can be explored using server-side:

- filtering
- sorting
- pagination
- protocol information
- source and destination details
- packet size information
- timestamps

This makes large traffic captures significantly easier to inspect.

---

## Protocol Intelligence

Packets are classified into meaningful protocol categories including:

```text
ARP
ICMP
ICMPv6
DNS
TLS
HTTP
TCP
UDP
Other
```

The dashboard provides both high-level protocol distribution and transport/layer statistics.

A single headline protocol is assigned to each packet to prevent misleading double counting in overall totals.

---

# Anomaly Detection

The project does more than count packets.

Traffic behaviour is evaluated using statistical baselines and rule-based indicators designed to highlight patterns worth investigating.

The detection pipeline considers signals such as:

- abnormal packet-rate changes
- sudden traffic-volume increases
- connection bursts
- unusual destination-port diversity
- unanswered TCP SYN activity
- elevated DNS request rates
- repeated DNS queries
- unusually long DNS names
- excessive small-packet activity

Packet-rate behaviour is evaluated using a **median / Median Absolute Deviation (MAD)** baseline, while traffic volume is evaluated over rolling windows.

Duplicate alerts occurring within the configured suppression interval are merged to reduce unnecessary alert noise.

> Alerts indicate unusual statistical or behavioural patterns. They should be treated as investigation signals rather than proof of a security incident.

---

# Dashboard

The dashboard acts as the central command view of an analysis.

It brings together:

- traffic summaries
- packet counts
- protocol statistics
- anomaly information
- recent analyses
- alert activity
- network behaviour indicators

The interface uses **Chart.js** to transform packet statistics into readable visualizations.

---

# Alerts Center

Detected anomalies are collected in a dedicated alert workflow.

Analysts can inspect alerts and mark reviewed events after investigation.

This separates simple traffic visualization from the actual security-analysis workflow:

```text
Traffic
   ↓
Detection Rules
   ↓
Anomaly
   ↓
Alert
   ↓
Investigation
   ↓
Reviewed
```

---

# Analysis History

Completed analyses are stored locally so previous captures can be revisited without rebuilding the entire analysis workflow.

The History section allows users to:

- inspect earlier analyses
- reopen results
- generate reports
- remove stored analyses

Retention duration can also be configured from application settings.

---

# Reporting

Analysis results can be exported into multiple formats.

### PDF

Useful for reports, demonstrations, project documentation, and sharing analysis findings.

### CSV

Useful for spreadsheets, further statistical processing, and dataset exploration.

### JSON

Useful for programmatic processing, API integration, and development workflows.

---

# Privacy by Design

Network captures can contain sensitive information, so the application intentionally limits what is retained.

The analyzer stores **packet metadata rather than packet payload contents**.

It does not persist:

- packet payloads
- HTTP URLs
- HTTP headers

Uploaded capture files are deleted after parsing.

Stored analyses can also expire automatically according to the configured retention period.

---

# Security Considerations

Several defensive measures are built into the application.

These include:

- CSRF protection for state-changing API requests
- HTTP-only session cookies
- SameSite cookie configuration
- upload-size restrictions
- extension validation
- PCAP file-signature validation
- server-controlled upload filenames
- parameterized SQL
- whitelisted sorting fields
- escaped HTML output
- CSV formula-injection protection
- generic server-error responses
- security-related HTTP headers
- localhost-only default server binding

The Flask development debugger is intentionally disabled.

---

# System Architecture

```text
                     ┌───────────────────────────┐
                     │          USER             │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │       WEB INTERFACE       │
                     │                           │
                     │ Dashboard                 │
                     │ Live Monitor              │
                     │ PCAP Upload               │
                     │ Packet Explorer           │
                     │ Protocol Analytics        │
                     │ Alerts                    │
                     │ History                   │
                     │ Settings                  │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │       FLASK SERVER        │
                     │      REST API Layer       │
                     └─────────────┬─────────────┘
                                   │
                  ┌────────────────┴────────────────┐
                  │                                 │
                  ▼                                 ▼
       ┌─────────────────────┐          ┌─────────────────────┐
       │   PCAP PROCESSING   │          │    LIVE CAPTURE     │
       │                     │          │                     │
       │   PCAP / PCAPNG     │          │       Scapy         │
       └──────────┬──────────┘          └──────────┬──────────┘
                  │                                 │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │      PACKET ANALYSIS      │
                     │                           │
                     │ Protocol Classification   │
                     │ Traffic Statistics        │
                     │ Flow Characteristics      │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │    ANOMALY DETECTION      │
                     │                           │
                     │ Median / MAD Baseline     │
                     │ Rolling Traffic Windows   │
                     │ Behavioural Rules         │
                     │ Alert Suppression         │
                     └─────────────┬─────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
          ┌───────────────────┐        ┌──────────────────────┐
          │      SQLite       │        │      REPORTING       │
          │                   │        │                      │
          │ Analyses          │        │ PDF                  │
          │ Packets           │        │ CSV                  │
          │ Alerts            │        │ JSON                 │
          │ Settings          │        │                      │
          └───────────────────┘        └──────────────────────┘
```

---

# Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python |
| Web Framework | Flask |
| Packet Processing | Scapy |
| Data Processing | Pandas |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Visualization | Chart.js |
| Icons | Font Awesome |
| PDF Generation | ReportLab |
| Environment Configuration | python-dotenv |

---

# Project Workflow

```text
PCAP Upload / Live Capture
            │
            ▼
     Packet Acquisition
            │
            ▼
      Packet Parsing
            │
            ▼
   Protocol Classification
            │
            ▼
    Statistical Analysis
            │
            ▼
   Behavioural Detection
            │
            ▼
      Alert Generation
            │
            ▼
   SQLite Persistence
            │
            ▼
 Dashboard / Explorer
            │
            ▼
    PDF / CSV / JSON
```

---

# Getting Started

## Prerequisites

Install:

- Python 3.10+
- pip
- a modern web browser

The project was developed using Python 3.12.

For live packet capture on Windows, install **Npcap**.

---

## Clone the Repository

```bash
git clone https://github.com/Jahnavi-Mogarala/Smart-Network-Traffic-Analyzer-with-Anomaly-Detection.git

cd Smart-Network-Traffic-Analyzer-with-Anomaly-Detection
```

---

## Create a Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Configuration

Configuration can be supplied using environment variables.

If required, copy:

```text
.env.example
```

to:

```text
.env
```

The application automatically creates its SQLite database and secret key on first startup.

---

# Run the Application

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The application runs on localhost by default with Flask debugging disabled.

---

# No Capture File?

The application includes synthetic sample analysis support, allowing the dashboard and analysis workflow to be demonstrated without capturing real network traffic.

From the dashboard, select:

```text
Create Sample Analysis
```

A repeatable sample PCAP can also be generated when the sample-data utility is available:

```bash
python sample_data/generate_sample_pcap.py
```

Then upload:

```text
sample_data/sample_traffic.pcap
```

---

# Live Capture Permissions

Packet capture normally requires elevated network privileges.

### Windows

Install Npcap.

If network interfaces are unavailable, run the terminal with Administrator privileges.

### Linux

Depending on the system, the application may require root access:

```bash
sudo venv/bin/python app.py
```

Alternatively, packet-capture capabilities can be assigned to the Python executable.

### macOS

Access to `/dev/bpf*` is required.

This may require elevated permissions or the Wireshark ChmodBPF helper.

> Only monitor networks and systems that you own or have explicit authorization to inspect.

---

# API

The application exposes a JSON API used by the frontend.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Application and capture capability status |
| `GET` | `/api/dashboard` | Dashboard analysis data |
| `POST` | `/api/analyze/upload` | Submit PCAP/PCAPNG analysis |
| `POST` | `/api/analyze/sample` | Generate sample analysis |
| `POST` | `/api/capture/start` | Start live capture |
| `POST` | `/api/capture/stop` | Stop active capture |
| `GET` | `/api/capture/status` | Capture status |
| `GET` | `/api/capture/interfaces` | Available interfaces |
| `GET` | `/api/packets` | Packet exploration |
| `GET` | `/api/protocols` | Protocol statistics |
| `GET` | `/api/alerts` | Retrieve anomaly alerts |
| `PATCH` | `/api/alerts/<id>` | Update alert review state |
| `GET` | `/api/history` | Analysis history |
| `DELETE` | `/api/history/<id>` | Delete stored analysis |
| `GET` | `/api/reports/<id>/pdf` | PDF report |
| `GET` | `/api/reports/<id>/csv` | CSV export |
| `GET` | `/api/reports/<id>/json` | JSON export |
| `GET / PUT / DELETE` | `/api/settings` | Manage analyzer settings |

State-changing API requests require the application's CSRF token.

---

# Detection Philosophy

This project intentionally avoids treating every unusual packet as an attack.

Network behaviour varies significantly between environments. A development machine, university network, server, IoT environment, and enterprise network can all have very different definitions of "normal."

The analyzer therefore combines:

```text
Statistical Baselines
        +
Rolling Windows
        +
Behavioural Indicators
        +
Configurable Thresholds
        =
Investigation Signals
```

The result is an explainable anomaly-monitoring approach where alerts can be traced back to observable network behaviour.

---

# Testing

Run the included tests using:

```bash
python -m unittest discover -s . -p "test_*.py" -t .
```

or, with pytest installed:

```bash
pytest
```

Tests use temporary databases and synthetic traffic, so real network traffic is not required for normal test execution.

---

# Example Use Cases

This project can be used for:

- network traffic visualization
- packet-analysis practice
- cybersecurity laboratory exercises
- PCAP investigation
- protocol-distribution analysis
- abnormal traffic detection
- network troubleshooting
- security-monitoring demonstrations
- computer networks coursework
- intrusion-detection experimentation

---

# Project Structure

```text
Smart-Network-Traffic-Analyzer-with-Anomaly-Detection/
│
├── app.py
├── config.py
├── database.py
├── models.py
├── requirements.txt
├── .env.example
│
├── routes/
│   ├── analysis
│   ├── capture
│   ├── dashboard
│   ├── packets
│   ├── protocols
│   ├── alerts
│   ├── history
│   ├── reports
│   └── settings
│
├── templates/
│   └── application pages
│
├── static/
│   ├── CSS
│   └── JavaScript
│
├── sample_data/
│   └── sample traffic utilities
│
└── tests/
    └── application tests
```

---

# Why This Project?

Traditional packet inspection tools are extremely powerful, but learning how network-monitoring systems work requires understanding what happens **after packets are captured**.

This project explores that complete pipeline:

**packet acquisition → parsing → classification → aggregation → anomaly detection → persistence → visualization → investigation → reporting**

That makes the project more than a dashboard.

It is an implementation of the core ideas behind network observability and lightweight network-security monitoring.

---

# Limitations

The analyzer is intended for education, experimentation, network visibility, and defensive monitoring.

It is **not a replacement for an enterprise IDS/IPS, SIEM, firewall, or dedicated network-forensics platform**.

An anomaly means:

> "This traffic differs from expected behaviour."

It does not automatically mean:

> "This traffic is malicious."

Security conclusions should always be supported by further investigation and context.

---

# Future Scope

Potential extensions include:

- IPv6-focused analytics
- flow reconstruction
- configurable custom detection rules
- GeoIP visualization
- threat-intelligence enrichment
- long-term traffic baselining
- WebSocket-based live dashboard updates
- authentication and multi-user environments
- PostgreSQL support
- Docker deployment
- distributed packet collectors
- alert integrations
- network topology visualization
- deeper TCP session analytics

---

# Ethical Use

Packet capture can expose sensitive network information.

Use this project only on:

- networks you own
- systems you administer
- lab environments
- environments where you have explicit authorization

Unauthorized interception or monitoring of network traffic may violate privacy policies or applicable laws.

---

# Author

**Jahnavi Mogarala**

Built as a practical exploration of **Computer Networks, Network Security, Traffic Analysis, Flask development, packet processing, and anomaly detection**.

---

# Repository

Smart Network Traffic Analyzer with Anomaly Detection

GitHub:

```text
https://github.com/Jahnavi-Mogarala/Smart-Network-Traffic-Analyzer-with-Anomaly-Detection
```

---

## Final Note

Every network has a normal rhythm.

The difficult part is noticing when that rhythm changes.

**Smart Network Traffic Analyzer turns packets into visibility — and visibility into something you can investigate.**

---

⭐ If you found this project useful, consider starring the repository.
