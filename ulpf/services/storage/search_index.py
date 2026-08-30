"""
SIEM-Facing Search & Analytics Storage Engine
Provides sub-millisecond search, structured filters, faceting, and forensic queries.
"""

import datetime
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from ulpf.packages.schemas.models import EventEnvelope


class SearchIndex:
    """
    SQLite-backed SIEM index with FTS5 full-text search and analytical aggregation queries.
    Air-gapped, zero external network dependency, self-healing.
    """

    def __init__(self, db_path: str = "data/search_index.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS normalized_events (
                    event_id TEXT PRIMARY KEY,
                    ingest_timestamp TEXT,
                    time_dt TEXT,
                    time_epoch INTEGER,
                    vendor TEXT,
                    product TEXT,
                    detected_format TEXT,
                    collector_host TEXT,
                    class_uid INTEGER,
                    class_name TEXT,
                    category_uid INTEGER,
                    category_name TEXT,
                    severity_id INTEGER,
                    severity TEXT,
                    status_id INTEGER,
                    status TEXT,
                    disposition_id INTEGER,
                    disposition TEXT,
                    action TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol_name TEXT,
                    app_name TEXT,
                    raw_sha256 TEXT,
                    byte_length INTEGER,
                    parser_used TEXT,
                    parser_version TEXT,
                    template_id INTEGER,
                    confidence REAL,
                    raw_payload TEXT,
                    ocsf_json TEXT,
                    envelope_json TEXT
                )
            """)

            # Indexes for fast SIEM queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON normalized_events(time_epoch)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_vendor ON normalized_events(vendor)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON normalized_events(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON normalized_events(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON normalized_events(severity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_disposition ON normalized_events(disposition)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_raw_sha ON normalized_events(raw_sha256)")

            # FTS5 full-text search table
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    event_id UNINDEXED,
                    raw_payload,
                    ocsf_json,
                    tokenize='porter unicode61'
                )
            """)

            # Audit Trail table (persistent privileged action log)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    audit_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    time_epoch INTEGER,
                    user TEXT,
                    role TEXT,
                    action TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    details_json TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_trail(time_epoch)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_trail(user)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_trail(action)")

            conn.commit()
            conn.close()

    def index_event(self, envelope: EventEnvelope):
        """Index a normalized event envelope."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            ocsf = envelope.ocsf or {}
            src = ocsf.get("src_endpoint", {}) if isinstance(ocsf.get("src_endpoint"), dict) else {}
            dst = ocsf.get("dst_endpoint", {}) if isinstance(ocsf.get("dst_endpoint"), dict) else {}
            conn_info = ocsf.get("connection_info", {}) if isinstance(ocsf.get("connection_info"), dict) else {}
            
            ocsf_json = json.dumps(ocsf)
            envelope_json = envelope.model_dump_json()

            time_epoch = ocsf.get("time") or int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
            time_dt = ocsf.get("time_dt") or envelope.ingest_timestamp

            cursor.execute("""
                INSERT OR REPLACE INTO normalized_events (
                    event_id, ingest_timestamp, time_dt, time_epoch,
                    vendor, product, detected_format, collector_host,
                    class_uid, class_name, category_uid, category_name,
                    severity_id, severity, status_id, status,
                    disposition_id, disposition, action,
                    src_ip, src_port, dst_ip, dst_port,
                    protocol_name, app_name,
                    raw_sha256, byte_length,
                    parser_used, parser_version, template_id, confidence,
                    raw_payload, ocsf_json, envelope_json
                ) VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?
                )
            """, (
                envelope.event_id,
                envelope.ingest_timestamp,
                time_dt,
                time_epoch,
                envelope.source.vendor,
                envelope.source.product,
                str(envelope.source.detected_format.value if hasattr(envelope.source.detected_format, 'value') else envelope.source.detected_format),
                envelope.source.collector_host,
                ocsf.get("class_uid", 4001),
                ocsf.get("class_name", "Network Activity"),
                ocsf.get("category_uid", 4),
                ocsf.get("category_name", "Network Activity"),
                ocsf.get("severity_id", 1),
                ocsf.get("severity", "Informational"),
                ocsf.get("status_id", 1),
                ocsf.get("status", "Success"),
                ocsf.get("disposition_id", 1),
                ocsf.get("disposition", "Allowed"),
                ocsf.get("action") or ocsf.get("activity_name"),
                src.get("ip"),
                src.get("port"),
                dst.get("ip"),
                dst.get("port"),
                conn_info.get("protocol_name", "TCP"),
                ocsf.get("app_name"),
                envelope.raw.sha256,
                envelope.raw.byte_length,
                envelope.parsing.parser_used,
                envelope.parsing.parser_version,
                envelope.parsing.template_id,
                envelope.parsing.confidence,
                envelope.raw.raw_payload,
                ocsf_json,
                envelope_json
            ))

            # FTS insert
            cursor.execute("""
                INSERT OR REPLACE INTO events_fts (event_id, raw_payload, ocsf_json)
                VALUES (?, ?, ?)
            """, (
                envelope.event_id,
                envelope.raw.raw_payload,
                ocsf_json
            ))

            conn.commit()
            conn.close()

    def index_batch(self, envelopes: list[EventEnvelope]):
        """Index a batch of events efficiently in a single transaction."""
        if not envelopes:
            return
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            rows = []
            fts_rows = []
            for envelope in envelopes:
                ocsf = envelope.ocsf or {}
                src = ocsf.get("src_endpoint", {}) if isinstance(ocsf.get("src_endpoint"), dict) else {}
                dst = ocsf.get("dst_endpoint", {}) if isinstance(ocsf.get("dst_endpoint"), dict) else {}
                conn_info = ocsf.get("connection_info", {}) if isinstance(ocsf.get("connection_info"), dict) else {}
                
                ocsf_json = json.dumps(ocsf)
                envelope_json = envelope.model_dump_json()
                time_epoch = ocsf.get("time") or int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
                time_dt = ocsf.get("time_dt") or envelope.ingest_timestamp

                rows.append((
                    envelope.event_id,
                    envelope.ingest_timestamp,
                    time_dt,
                    time_epoch,
                    envelope.source.vendor,
                    envelope.source.product,
                    str(envelope.source.detected_format.value if hasattr(envelope.source.detected_format, 'value') else envelope.source.detected_format),
                    envelope.source.collector_host,
                    ocsf.get("class_uid", 4001),
                    ocsf.get("class_name", "Network Activity"),
                    ocsf.get("category_uid", 4),
                    ocsf.get("category_name", "Network Activity"),
                    ocsf.get("severity_id", 1),
                    ocsf.get("severity", "Informational"),
                    ocsf.get("status_id", 1),
                    ocsf.get("status", "Success"),
                    ocsf.get("disposition_id", 1),
                    ocsf.get("disposition", "Allowed"),
                    ocsf.get("action") or ocsf.get("activity_name"),
                    src.get("ip"),
                    src.get("port"),
                    dst.get("ip"),
                    dst.get("port"),
                    conn_info.get("protocol_name", "TCP"),
                    ocsf.get("app_name"),
                    envelope.raw.sha256,
                    envelope.raw.byte_length,
                    envelope.parsing.parser_used,
                    envelope.parsing.parser_version,
                    envelope.parsing.template_id,
                    envelope.parsing.confidence,
                    envelope.raw.raw_payload,
                    ocsf_json,
                    envelope_json
                ))
                fts_rows.append((envelope.event_id, envelope.raw.raw_payload, ocsf_json))

            cursor.executemany("""
                INSERT OR REPLACE INTO normalized_events (
                    event_id, ingest_timestamp, time_dt, time_epoch,
                    vendor, product, detected_format, collector_host,
                    class_uid, class_name, category_uid, category_name,
                    severity_id, severity, status_id, status,
                    disposition_id, disposition, action,
                    src_ip, src_port, dst_ip, dst_port,
                    protocol_name, app_name,
                    raw_sha256, byte_length,
                    parser_used, parser_version, template_id, confidence,
                    raw_payload, ocsf_json, envelope_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

            cursor.executemany("""
                INSERT OR REPLACE INTO events_fts (event_id, raw_payload, ocsf_json)
                VALUES (?, ?, ?)
            """, fts_rows)

            conn.commit()
            conn.close()

    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Retrieve full event by event_id."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM normalized_events WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        if d.get("ocsf_json"):
            d["ocsf"] = json.loads(d["ocsf_json"])
        if d.get("envelope_json"):
            d["envelope"] = json.loads(d["envelope_json"])
        return d

    def search_events(
        self,
        query: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        detected_format: str | None = None,
        severity_id: int | None = None,
        disposition: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        limit: int = 50,
        offset: int = 0
    ) -> dict[str, Any]:
        """
        Execute faceted SIEM search query.
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        conditions = []
        params = []

        if query:
            clean_query = query.strip()
            if clean_query.startswith('"') and clean_query.endswith('"'):
                fts_param = clean_query
            else:
                escaped = clean_query.replace('"', '""')
                fts_param = f'"{escaped}"'
            conditions.append("e.event_id IN (SELECT event_id FROM events_fts WHERE events_fts MATCH ?)")
            params.append(fts_param)

        if vendor:
            conditions.append("e.vendor = ?")
            params.append(vendor)
        if product:
            conditions.append("e.product = ?")
            params.append(product)
        if detected_format:
            conditions.append("e.detected_format = ?")
            params.append(detected_format)
        if severity_id is not None:
            conditions.append("e.severity_id = ?")
            params.append(severity_id)
        if disposition:
            conditions.append("e.disposition = ?")
            params.append(disposition)
        if src_ip:
            conditions.append("e.src_ip LIKE ?")
            params.append(f"%{src_ip}%")
        if dst_ip:
            conditions.append("e.dst_ip LIKE ?")
            params.append(f"%{dst_ip}%")

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Total count query
        count_sql = f"SELECT COUNT(*) as total FROM normalized_events e {where_clause}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()["total"]

        # Data query
        data_sql = f"""
            SELECT e.event_id, e.ingest_timestamp, e.time_dt, e.vendor, e.product,
                   e.detected_format, e.class_name, e.severity_id, e.severity,
                   e.disposition, e.action, e.src_ip, e.src_port, e.dst_ip, e.dst_port,
                   e.protocol_name, e.app_name, e.raw_sha256, e.parser_used,
                   e.confidence, e.raw_payload, e.ocsf_json
            FROM normalized_events e
            {where_clause}
            ORDER BY e.time_epoch DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(data_sql, params + [limit, offset])
        rows = [dict(r) for r in cursor.fetchall()]
        for r in rows:
            if r.get("ocsf_json"):
                try:
                    r["ocsf"] = json.loads(r["ocsf_json"])
                except Exception:
                    pass

        conn.close()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": rows
        }

    def get_metrics_summary(self) -> dict[str, Any]:
        """Calculates system metrics, vendor distribution, severity counts, and ingestion stats."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total_events FROM normalized_events")
        total_events = cursor.fetchone()["total_events"]

        cursor.execute("SELECT vendor, COUNT(*) as count FROM normalized_events GROUP BY vendor ORDER BY count DESC LIMIT 10")
        vendor_dist = {r["vendor"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT detected_format, COUNT(*) as count FROM normalized_events GROUP BY detected_format ORDER BY count DESC")
        format_dist = {r["detected_format"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT severity, COUNT(*) as count FROM normalized_events GROUP BY severity ORDER BY count DESC")
        severity_dist = {r["severity"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT disposition, COUNT(*) as count FROM normalized_events GROUP BY disposition ORDER BY count DESC")
        disposition_dist = {r["disposition"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT parser_used, COUNT(*) as count FROM normalized_events GROUP BY parser_used ORDER BY count DESC LIMIT 10")
        parser_dist = {r["parser_used"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT SUM(byte_length) as total_bytes FROM normalized_events")
        total_bytes = cursor.fetchone()["total_bytes"] or 0

        conn.close()
        return {
            "total_events": total_events,
            "total_bytes": total_bytes,
            "vendor_distribution": vendor_dist,
            "format_distribution": format_dist,
            "severity_distribution": severity_dist,
            "disposition_distribution": disposition_dist,
            "parser_distribution": parser_dist
        }

    def record_audit(self, audit: Any):
        """Persists an audit log record into SQLite."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            audit_dict = audit.model_dump() if hasattr(audit, "model_dump") else dict(audit)
            now_dt = audit_dict.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()
            time_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
            details_json = json.dumps(audit_dict.get("details", {}))

            cursor.execute("""
                INSERT OR REPLACE INTO audit_trail (
                    audit_id, timestamp, time_epoch, user, role, action, resource_type, resource_id, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                audit_dict.get("audit_id"),
                now_dt,
                time_epoch,
                audit_dict.get("user", "unknown"),
                audit_dict.get("role", "OPERATOR"),
                audit_dict.get("action", "UNKNOWN_ACTION"),
                audit_dict.get("resource_type", "SYSTEM"),
                audit_dict.get("resource_id", "none"),
                details_json
            ))
            conn.commit()
            conn.close()

    def list_audits(
        self,
        user: str | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0
    ) -> list[dict[str, Any]]:
        """Queries persistent audit trail with optional filtering."""
        conn = self._get_conn()
        cursor = conn.cursor()

        conditions = []
        params = []
        if user:
            conditions.append("user = ?")
            params.append(user)
        if action:
            conditions.append("action = ?")
            params.append(action)

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"""
            SELECT audit_id, timestamp, user, role, action, resource_type, resource_id, details_json
            FROM audit_trail
            {where_clause}
            ORDER BY time_epoch DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(sql, params + [limit, offset])
        rows = [dict(r) for r in cursor.fetchall()]
        for r in rows:
            if r.get("details_json"):
                try:
                    r["details"] = json.loads(r["details_json"])
                except Exception:
                    r["details"] = {}
                del r["details_json"]
        conn.close()
        return rows
