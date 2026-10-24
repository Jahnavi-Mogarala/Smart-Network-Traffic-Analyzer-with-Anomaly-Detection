"""Central configuration: paths, limits and the schema of user-editable settings."""
import os
import secrets
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:          # python-dotenv is optional
    pass

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.environ.get("SNTA_INSTANCE_DIR", BASE_DIR / "instance"))
UPLOAD_DIR = INSTANCE_DIR / "uploads"            # outside static/ -> never served publicly
DB_PATH = INSTANCE_DIR / "analyzer.db"

HOST = os.environ.get("SNTA_HOST", "127.0.0.1")   # localhost-only by default
PORT = int(os.environ.get("SNTA_PORT", "5000"))
MAX_UPLOAD_MB = int(os.environ.get("SNTA_MAX_UPLOAD_MB", "50"))
HARD_CAPTURE_LIMIT_SECONDS = 300                   # upper bound no setting can exceed

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
# pcap (both endiannesses, micro/nano) and pcapng section header block
PCAP_MAGICS = {bytes.fromhex(h) for h in
               ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a")}


def load_secret_key():
    """SECRET_KEY env var, else a random key generated once and kept in instance/secret_key."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    path = INSTANCE_DIR / "secret_key"
    if not path.exists():
        path.write_text(secrets.token_hex(32))
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return path.read_text().strip()


def _s(default, kind, lo=None, hi=None, label="", group="", help="", choices=None):
    return {"default": default, "type": kind, "min": lo, "max": hi, "label": label,
            "group": group, "help": help, "choices": choices}


# name -> definition. The settings page and the API validation are both generated from this.
SETTINGS_SCHEMA = {
    "window_seconds": _s(10, "int", 1, 300, "Analysis window (s)", "Anomaly thresholds",
                         "Bucket size used by connection, port, DNS and SYN rules."),
    "pps_sigma": _s(4.0, "float", 1, 20, "Packet-rate sensitivity (robust z)", "Anomaly thresholds",
                    "Lower = more alerts. Compared against the median and MAD of packets/second."),
    "pps_min": _s(30, "int", 1, 100000, "Minimum packets/s to flag", "Anomaly thresholds",
                  "Rates below this are never flagged, however unusual statistically."),
    "volume_ratio": _s(4.0, "float", 1.5, 100, "Volume spike ratio", "Anomaly thresholds",
                       "Bytes/s versus the rolling mean of the previous 10 seconds."),
    "conn_burst": _s(100, "int", 5, 100000, "Connection burst (per window)", "Anomaly thresholds",
                     "New TCP connection attempts from one source to one destination."),
    "scan_ports": _s(15, "int", 3, 1000, "Distinct destination ports (per window)", "Anomaly thresholds",
                     "One source touching this many ports on one host looks like port probing."),
    "incomplete_syn": _s(50, "int", 5, 100000, "Unanswered SYNs (per window)", "Anomaly thresholds",
                         "TCP connection attempts with no SYN-ACK observed."),
    "dns_rate": _s(100, "int", 5, 100000, "DNS queries per window", "Anomaly thresholds"),
    "dns_repeat": _s(30, "int", 3, 100000, "Same DNS name repeated", "Anomaly thresholds"),
    "dns_long_len": _s(50, "int", 20, 253, "Long DNS name length", "Anomaly thresholds",
                       "Very long names can indicate DNS tunnelling, or just CDN hostnames."),
    "small_pkt_share": _s(0.9, "float", 0.5, 1.0, "Small-packet share", "Anomaly thresholds",
                          "Share of one source's packets that are 80 bytes or less."),
    "dedup_seconds": _s(30, "int", 0, 3600, "Duplicate-alert suppression (s)", "Anomaly thresholds",
                        "Same category + source + destination within this interval is suppressed."),
    "min_baseline_seconds": _s(20, "int", 5, 3600, "Minimum capture length for rate baselines (s)",
                               "Anomaly thresholds",
                               "Shorter captures skip statistical rate rules (too little baseline)."),
    "capture_duration": _s(30, "int", 3, 300, "Default capture duration (s)", "Capture & processing"),
    "max_packets": _s(100000, "int", 1000, 1000000, "Max packets per analysis", "Capture & processing",
                      "Extra packets are ignored and the analysis is flagged as truncated."),
    "max_processing_seconds": _s(60, "int", 5, 600, "Max parsing time (s)", "Capture & processing"),
    "retention_days": _s(30, "int", 0, 3650, "Keep analyses for (days, 0 = forever)", "Data retention"),
    "theme": _s("dark", "str", label="Theme", group="Appearance", choices=["dark", "light"]),
    "refresh_interval": _s(10, "int", 0, 300, "Dashboard refresh (s, 0 = off)", "Appearance"),
}
