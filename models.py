"""Data-access layer: every SQL statement is parameterized; sort columns are whitelisted."""
import json
import math
from datetime import datetime, timedelta, timezone

from database import db

PACKET_SORT = {"ts", "src", "dst", "sport", "dport", "proto", "length", "id"}
SEVERITY_RANK_SQL = ("CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 "
                     "WHEN 'Low' THEN 2 ELSE 3 END")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(v):
    """NaN/NaT/numpy scalars -> plain Python values SQLite understands."""
    if v is None:
        return None
    if hasattr(v, "item"):
        v = v.item()
    if isinstance(v, float) and math.isnan(v):
        return None
    return v


def _like(text):
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ---------------- analyses ----------------
def create_analysis(source_type, source_name, status="queued"):
    with db() as c:
        cur = c.execute("INSERT INTO analyses(source_type, source_name, created_at, status) VALUES(?,?,?,?)",
                        (source_type, source_name[:200], now_iso(), status))
        return cur.lastrowid


_UPDATABLE = {"status", "error", "total_packets", "total_bytes", "duration_sec", "unique_src",
              "unique_dst", "alert_count", "truncated", "summary_json"}


def update_analysis(analysis_id, **fields):
    bad = set(fields) - _UPDATABLE
    if bad:
        raise ValueError(f"Cannot update: {bad}")
    if "summary_json" in fields and not isinstance(fields["summary_json"], str):
        fields["summary_json"] = json.dumps(fields["summary_json"])
    cols = ", ".join(f"{k} = ?" for k in fields)
    with db() as c:
        c.execute(f"UPDATE analyses SET {cols} WHERE id = ?", (*fields.values(), analysis_id))


def _analysis_dict(row, with_summary=False):
    d = dict(row)
    raw = d.pop("summary_json", None)
    if with_summary:
        d["summary"] = json.loads(raw) if raw else None
    return d


def get_analysis(analysis_id, with_summary=True):
    with db() as c:
        row = c.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    return _analysis_dict(row, with_summary) if row else None


def list_analyses(limit=100):
    with db() as c:
        rows = c.execute("SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_analysis_dict(r) for r in rows]


def latest_completed_id():
    with db() as c:
        row = c.execute("SELECT id FROM analyses WHERE status = 'completed' ORDER BY id DESC LIMIT 1").fetchone()
    return row["id"] if row else None


def delete_analysis(analysis_id):
    with db() as c:
        return c.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,)).rowcount > 0


def purge_expired(retention_days):
    if not retention_days:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec="seconds")
    with db() as c:
        return c.execute("DELETE FROM analyses WHERE created_at < ? AND status != 'processing'",
                         (cutoff,)).rowcount


def mark_stale_processing():
    """After a restart no worker can still be running: fail anything left in a transient state."""
    with db() as c:
        c.execute("UPDATE analyses SET status='failed', error='Interrupted by application restart' "
                  "WHERE status IN ('queued','processing')")


# ---------------- packets & protocol stats ----------------
PACKET_COLS = ["ts", "src", "dst", "sport", "dport", "transport", "proto", "length", "flags",
               "dns_query", "layers", "info"]


def save_packets(analysis_id, df):
    rows = [(analysis_id, *[_clean(v) for v in r]) for r in df[PACKET_COLS].itertuples(index=False, name=None)]
    with db() as c:
        c.executemany("INSERT INTO packets(analysis_id, " + ", ".join(PACKET_COLS) + ") VALUES ("
                      + ", ".join("?" * (len(PACKET_COLS) + 1)) + ")", rows)


def save_protocol_stats(analysis_id, summary):
    rows = []
    for category, key in (("headline", "protocols"), ("transport", "transports"), ("layer", "layers")):
        for name, v in summary[key].items():
            rows.append((analysis_id, category, name, v["packets"], v["bytes"]))
    with db() as c:
        c.executemany("INSERT INTO protocol_stats(analysis_id, category, name, packets, bytes) "
                      "VALUES(?,?,?,?,?)", rows)


def get_protocol_stats(analysis_id):
    out = {"headline": [], "transport": [], "layer": []}
    with db() as c:
        for r in c.execute("SELECT category, name, packets, bytes FROM protocol_stats "
                           "WHERE analysis_id = ? ORDER BY packets DESC", (analysis_id,)):
            out[r["category"]].append({"name": r["name"], "packets": r["packets"], "bytes": r["bytes"]})
    return out


def query_packets(analysis_id, q="", proto="", t_from=None, t_to=None, min_len=None, max_len=None,
                  sort="ts", direction="asc", page=1, per_page=50, start_ts=0.0):
    where, args = ["analysis_id = ?"], [analysis_id]
    if q:
        where.append("(src LIKE ? ESCAPE '\\' OR dst LIKE ? ESCAPE '\\' OR dns_query LIKE ? ESCAPE '\\')")
        args += [_like(q)] * 3
    if proto:
        where.append("proto = ?")
        args.append(proto)
    if t_from is not None:
        where.append("ts >= ?")
        args.append(start_ts + t_from)
    if t_to is not None:
        where.append("ts <= ?")
        args.append(start_ts + t_to)
    if min_len is not None:
        where.append("length >= ?")
        args.append(min_len)
    if max_len is not None:
        where.append("length <= ?")
        args.append(max_len)
    sort = sort if sort in PACKET_SORT else "ts"
    direction = "DESC" if str(direction).lower() == "desc" else "ASC"
    clause = " AND ".join(where)
    with db() as c:
        total = c.execute(f"SELECT COUNT(*) FROM packets WHERE {clause}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM packets WHERE {clause} ORDER BY {sort} {direction}, id {direction} "
                         "LIMIT ? OFFSET ?", (*args, per_page, (page - 1) * per_page)).fetchall()
    return total, [dict(r) for r in rows]


def get_packet(analysis_id, packet_id):
    with db() as c:
        row = c.execute("SELECT * FROM packets WHERE analysis_id = ? AND id = ?",
                        (analysis_id, packet_id)).fetchone()
    return dict(row) if row else None


def iter_packets(analysis_id, batch=5000):
    """Generator used for CSV export so huge analyses never sit fully in memory."""
    last = 0
    while True:
        with db() as c:
            rows = c.execute("SELECT * FROM packets WHERE analysis_id = ? AND id > ? ORDER BY id LIMIT ?",
                             (analysis_id, last, batch)).fetchall()
        if not rows:
            return
        last = rows[-1]["id"]
        for r in rows:
            yield dict(r)


# ---------------- alerts ----------------
ALERT_COLS = ["alert_uid", "detected_at", "event_ts", "window_end", "severity", "category", "source",
              "destination", "observed", "baseline", "explanation", "recommendation"]


def save_alerts(analysis_id, alerts):
    rows = [(analysis_id, *[a.get(k) for k in ALERT_COLS]) for a in alerts]
    with db() as c:
        c.executemany("INSERT INTO alerts(analysis_id, " + ", ".join(ALERT_COLS) + ") VALUES ("
                      + ", ".join("?" * (len(ALERT_COLS) + 1)) + ")", rows)


def query_alerts(analysis_id=None, severity="", category="", reviewed=None, q="", page=1, per_page=50):
    where, args = ["1=1"], []
    if analysis_id:
        where.append("analysis_id = ?")
        args.append(analysis_id)
    if severity:
        where.append("severity = ?")
        args.append(severity)
    if category:
        where.append("category = ?")
        args.append(category)
    if reviewed is not None:
        where.append("reviewed = ?")
        args.append(1 if reviewed else 0)
    if q:
        where.append("(source LIKE ? ESCAPE '\\' OR destination LIKE ? ESCAPE '\\' "
                     "OR explanation LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\')")
        args += [_like(q)] * 4
    clause = " AND ".join(where)
    with db() as c:
        total = c.execute(f"SELECT COUNT(*) FROM alerts WHERE {clause}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM alerts WHERE {clause} ORDER BY {SEVERITY_RANK_SQL}, event_ts, id "
                         "LIMIT ? OFFSET ?", (*args, per_page, (page - 1) * per_page)).fetchall()
        counts = {r["severity"]: r["n"] for r in c.execute(
            f"SELECT severity, COUNT(*) n FROM alerts WHERE {clause} GROUP BY severity", args)}
    return total, [dict(r) for r in rows], counts


def get_alert(alert_id):
    with db() as c:
        row = c.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def set_alert_reviewed(alert_id, reviewed):
    with db() as c:
        return c.execute("UPDATE alerts SET reviewed = ? WHERE id = ?",
                         (1 if reviewed else 0, alert_id)).rowcount > 0


def alert_categories():
    with db() as c:
        return [r[0] for r in c.execute("SELECT DISTINCT category FROM alerts ORDER BY category")]


def alerts_for_analysis(analysis_id, limit=1000):
    return query_alerts(analysis_id=analysis_id, per_page=limit)[1]
