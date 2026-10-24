# Smart Network Traffic Analyzer with Anomaly Detection

Flask · Scapy · Pandas · SQLite · Chart.js · ReportLab. Analyze PCAP files or (optionally) live traffic,
explore packets and protocols, get explainable anomaly alerts, export PDF/CSV/JSON reports.

## 1. Prerequisites
- Python 3.10 or newer (developed on 3.12), pip
- Internet access in the browser for the Chart.js and Font Awesome CDN files (cdnjs)
- Windows only, for live capture: [Npcap](https://npcap.com)

## 2. Setup
```
python -m venv venv
venv\Scripts\activate            # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```
The SQLite database (`instance/analyzer.db`) and a random secret key (`instance/secret_key`) are created
automatically on first start. Optional: copy `.env.example` to `.env`.

## 3. Run
```
python app.py
```
Open http://127.0.0.1:5000. The server listens on localhost only and runs with debug off.

## 4. Using it
- **No data yet?** Dashboard -> *Create sample analysis* (clearly labelled synthetic traffic).
- **Upload a PCAP:** Upload page -> drag a `.pcap`/`.pcapng` file. For a repeatable demo file run
  `python sample_data/generate_sample_pcap.py` and upload `sample_data/sample_traffic.pcap`.
- **Live capture (optional):** Live Monitor -> choose interface and duration (3-300 s) -> Start. Stop ends it early.
  Only capture networks you own or are authorised to monitor.
- Explore: Packet Explorer, Protocols, Alerts Center (mark reviewed), History, Settings (thresholds, retention, theme).
- Reports: History or Upload result -> PDF / CSV / JSON.

### Live-capture permissions (vary by OS)
- **Linux:** usually root (`sudo venv/bin/python app.py`) or `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python)`.
- **macOS:** access to `/dev/bpf*` (often `sudo`, or install the Wireshark ChmodBPF helper).
- **Windows:** Npcap installed; if no interfaces/packets appear, start the terminal as Administrator.
- If it is refused you get a clear message; PCAP upload never needs special permissions.

## 5. Tests
```
python -m unittest discover -s . -p "test_*.py" -t .      # or: pip install pytest && pytest
```
Tests use a throw-away database and synthetic data; no real traffic needed. Tests that need Scapy are skipped
automatically if it is not installed.

## 6. API (all JSON, state-changing calls need the `X-CSRF-Token` header the pages send automatically)
| Method & path | Purpose |
|---|---|
| GET /api/health | status, Scapy availability, upload limit |
| GET /api/dashboard | latest (or `?analysis_id=`) analysis summary, alerts, history |
| POST /api/analyze/upload | multipart `file`; returns 202 + analysis id (background job) |
| POST /api/analyze/sample | create the synthetic sample analysis |
| POST /api/capture/start · /stop, GET /api/capture/status, /interfaces | bounded live capture |
| GET /api/packets, /api/packets/<id> | server-side filter / sort / pagination |
| GET /api/protocols | headline, transport and layer statistics |
| GET /api/alerts, PATCH /api/alerts/<id> | list/filter; `{"reviewed": true}` |
| GET /api/history, /history/<id>; DELETE /api/history/<id> | stored analyses |
| GET /api/reports/<id>/pdf · csv · json | exports |
| GET/PUT/DELETE /api/settings | validated settings (DELETE restores defaults) |

## 7. Design notes
- **Counting rules:** each packet gets one headline label (ARP > ICMPv6 > ICMP > DNS > TLS > HTTP > TCP > UDP > Other), so totals never double count. The TCP/UDP/DNS cards overlap by design (DNS is also UDP).
- **Detection:** robust median/MAD packet-rate baseline, 10-second rolling volume mean, per-window rules for connection bursts, port diversity, unanswered SYNs, DNS rate/repeats/long names, and tiny-packet dominance. Duplicate alerts inside the suppression interval are merged. Alerts are statistical anomalies, not verified incidents; captures shorter than the configured minimum skip rate rules.
- **Privacy:** only metadata is stored (no payloads, no HTTP URLs/headers). Uploads are deleted after parsing. Analyses expire after the retention period (default 30 days) or can be deleted in History.
- **Security:** extension + file-signature checks, size limit, server-chosen filenames, parameterized SQL with whitelisted sort columns, CSRF tokens, escaped HTML output, CSV formula-injection neutralised, no stack traces to users, localhost-only default.

## 8. Troubleshooting
- *"Scapy is not installed"* -> `pip install scapy` inside the activated venv.
- *Charts/icons missing* -> the browser needs internet access to cdnjs.cloudflare.com.
- *Live capture refused / no interfaces* -> see permissions above; use PCAP upload meanwhile.
- *"File content is not a PCAP/PCAPNG capture"* -> the file signature is wrong (e.g. renamed text file or `.etl`); re-export from Wireshark as pcap/pcapng.
- *Port already in use* -> set `SNTA_PORT=5001` in `.env`.
- *Start fresh* -> stop the app and delete the `instance/` folder.
