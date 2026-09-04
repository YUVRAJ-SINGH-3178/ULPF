"""
Search & Analytics Storage Engine
Provides abstract BaseSearchStore with SQLiteSearchStore (development / test) and OpenSearchStore (production).
Provides sub-millisecond full-text queries, faceted filters, aggregations, and persistent audit logging.
"""

import datetime
import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ulpf.packages.config.settings import Settings, get_settings
from ulpf.packages.schemas.models import EventEnvelope


class BaseSearchStore(ABC):
    """
    Abstract interface for searchable event indexing and analytics.
    """

    @abstractmethod
    def index_event(self, envelope: EventEnvelope):
        """Indexes a single normalized event envelope."""

    @abstractmethod
    def index_batch(self, envelopes: list[EventEnvelope]):
        """Indexes a batch of normalized event envelopes."""

    @abstractmethod
    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Retrieves full event details and OCSF representation by event_id."""

    @abstractmethod
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
        offset: int = 0,
    ) -> dict[str, Any]:
        """Executes faceted SIEM search queries with pagination."""

    @abstractmethod
    def get_metrics_summary(self) -> dict[str, Any]:
        """Calculates system metrics, vendor distribution, and severity breakdown."""

    @abstractmethod
    def record_audit(self, audit: Any):
        """Persists an administrative audit record."""

    @abstractmethod
    def list_audits(
        self,
        user: str | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Queries persistent audit records with optional filters."""

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Probes search store connectivity and readiness."""


class SQLiteSearchStore(BaseSearchStore):
    """
    SQLite-backed SIEM index with WAL mode and FTS5 full-text search.
    100% self-contained, air-gapped, zero external network dependency.
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

            # Normalized Events table
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

            # Query performance indexes
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_time ON normalized_events(time_epoch)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_vendor ON normalized_events(vendor)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON normalized_events(src_ip)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON normalized_events(dst_ip)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_severity ON normalized_events(severity_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_disposition ON normalized_events(disposition)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_raw_sha ON normalized_events(raw_sha256)"
            )

            # FTS5 full-text search table
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    event_id UNINDEXED,
                    raw_payload,
                    ocsf_json,
                    tokenize='porter unicode61'
                )
            """)

            # Audit Trail table
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
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_trail(time_epoch)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_trail(user)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_trail(action)"
            )

            conn.commit()
            conn.close()

    def index_event(self, envelope: EventEnvelope):
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            ocsf = envelope.ocsf or {}
            src = (
                ocsf.get("src_endpoint", {})
                if isinstance(ocsf.get("src_endpoint"), dict)
                else {}
            )
            dst = (
                ocsf.get("dst_endpoint", {})
                if isinstance(ocsf.get("dst_endpoint"), dict)
                else {}
            )
            conn_info = (
                ocsf.get("connection_info", {})
                if isinstance(ocsf.get("connection_info"), dict)
                else {}
            )

            ocsf_json = json.dumps(ocsf)
            envelope_json = envelope.model_dump_json()

            time_epoch = ocsf.get("time") or int(
                datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000
            )
            time_dt = ocsf.get("time_dt") or envelope.ingest_timestamp

            cursor.execute(
                """
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
            """,
                (
                    envelope.event_id,
                    envelope.ingest_timestamp,
                    time_dt,
                    time_epoch,
                    envelope.source.vendor,
                    envelope.source.product,
                    str(
                        envelope.source.detected_format.value
                        if hasattr(envelope.source.detected_format, "value")
                        else envelope.source.detected_format
                    ),
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
                    envelope_json,
                ),
            )

            cursor.execute(
                """
                INSERT OR REPLACE INTO events_fts (event_id, raw_payload, ocsf_json)
                VALUES (?, ?, ?)
            """,
                (envelope.event_id, envelope.raw.raw_payload, ocsf_json),
            )

            conn.commit()
            conn.close()

    def index_batch(self, envelopes: list[EventEnvelope]):
        if not envelopes:
            return
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            rows = []
            fts_rows = []
            for envelope in envelopes:
                ocsf = envelope.ocsf or {}
                src = (
                    ocsf.get("src_endpoint", {})
                    if isinstance(ocsf.get("src_endpoint"), dict)
                    else {}
                )
                dst = (
                    ocsf.get("dst_endpoint", {})
                    if isinstance(ocsf.get("dst_endpoint"), dict)
                    else {}
                )
                conn_info = (
                    ocsf.get("connection_info", {})
                    if isinstance(ocsf.get("connection_info"), dict)
                    else {}
                )

                ocsf_json = json.dumps(ocsf)
                envelope_json = envelope.model_dump_json()
                time_epoch = ocsf.get("time") or int(
                    datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000
                )
                time_dt = ocsf.get("time_dt") or envelope.ingest_timestamp

                rows.append(
                    (
                        envelope.event_id,
                        envelope.ingest_timestamp,
                        time_dt,
                        time_epoch,
                        envelope.source.vendor,
                        envelope.source.product,
                        str(
                            envelope.source.detected_format.value
                            if hasattr(envelope.source.detected_format, "value")
                            else envelope.source.detected_format
                        ),
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
                        envelope_json,
                    )
                )
                fts_rows.append(
                    (envelope.event_id, envelope.raw.raw_payload, ocsf_json)
                )

            cursor.executemany(
                """
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
            """,
                rows,
            )

            cursor.executemany(
                """
                INSERT OR REPLACE INTO events_fts (event_id, raw_payload, ocsf_json)
                VALUES (?, ?, ?)
            """,
                fts_rows,
            )

            conn.commit()
            conn.close()

    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM normalized_events WHERE event_id = ?", (event_id,)
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        if d.get("ocsf_json"):
            try:
                d["ocsf"] = json.loads(d["ocsf_json"])
            except Exception:
                pass
        if d.get("envelope_json"):
            try:
                env_data = json.loads(d["envelope_json"])
                d["envelope"] = env_data
                if "raw" in env_data:
                    raw_info = env_data["raw"]
                    d["raw_storage_uri"] = (
                        f"{raw_info.get('bucket')}/{raw_info.get('object_key')}"
                    )
                if "traceability" in env_data:
                    d["trace_id"] = env_data["traceability"].get("trace_id")
            except Exception:
                pass
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
        offset: int = 0,
    ) -> dict[str, Any]:
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
            conditions.append(
                "e.event_id IN (SELECT event_id FROM events_fts WHERE events_fts MATCH ?)"
            )
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

        count_sql = f"SELECT COUNT(*) as total FROM normalized_events e {where_clause}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()["total"]

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
        return {"total": total, "limit": limit, "offset": offset, "events": rows}

    def get_metrics_summary(self) -> dict[str, Any]:
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total_events FROM normalized_events")
        total_events = cursor.fetchone()["total_events"]

        cursor.execute(
            "SELECT vendor, COUNT(*) as count FROM normalized_events GROUP BY vendor ORDER BY count DESC LIMIT 10"
        )
        vendor_dist = {r["vendor"]: r["count"] for r in cursor.fetchall()}

        cursor.execute(
            "SELECT detected_format, COUNT(*) as count FROM normalized_events GROUP BY detected_format ORDER BY count DESC"
        )
        format_dist = {r["detected_format"]: r["count"] for r in cursor.fetchall()}

        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM normalized_events GROUP BY severity ORDER BY count DESC"
        )
        severity_dist = {r["severity"]: r["count"] for r in cursor.fetchall()}

        cursor.execute(
            "SELECT disposition, COUNT(*) as count FROM normalized_events GROUP BY disposition ORDER BY count DESC"
        )
        disposition_dist = {r["disposition"]: r["count"] for r in cursor.fetchall()}

        cursor.execute(
            "SELECT parser_used, COUNT(*) as count FROM normalized_events GROUP BY parser_used ORDER BY count DESC LIMIT 10"
        )
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
            "parser_distribution": parser_dist,
        }

    def record_audit(self, audit: Any):
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            audit_dict = (
                audit.model_dump() if hasattr(audit, "model_dump") else dict(audit)
            )
            now_dt = (
                audit_dict.get("timestamp")
                or datetime.datetime.now(datetime.timezone.utc).isoformat()
            )
            time_epoch = int(
                datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000
            )
            details_json = json.dumps(audit_dict.get("details", {}))

            cursor.execute(
                """
                INSERT OR REPLACE INTO audit_trail (
                    audit_id, timestamp, time_epoch, user, role, action, resource_type, resource_id, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    audit_dict.get("audit_id"),
                    now_dt,
                    time_epoch,
                    audit_dict.get("user", "unknown"),
                    audit_dict.get("role", "OPERATOR"),
                    audit_dict.get("action", "UNKNOWN_ACTION"),
                    audit_dict.get("resource_type", "SYSTEM"),
                    audit_dict.get("resource_id", "none"),
                    details_json,
                ),
            )
            conn.commit()
            conn.close()

    def list_audits(
        self,
        user: str | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
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

    def health_check(self) -> dict[str, Any]:
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM normalized_events")
            row_count = cur.fetchone()[0]
            conn.close()
            return {
                "backend": "SQLiteSearchStore",
                "status": "HEALTHY",
                "indexed_records": row_count,
                "db_path": str(self.db_path.resolve()),
            }
        except Exception as e:
            return {
                "backend": "SQLiteSearchStore",
                "status": "UNHEALTHY",
                "error": str(e),
            }


class OpenSearchStore(BaseSearchStore):
    """
    Production OpenSearch SIEM storage adapter for high-volume normalized OCSF telemetry.
    Features:
    - Index templates with explicit strict mappings (avoids dynamic mapping explosions).
    - Deterministic doc IDs (_id = event_id) for idempotent ingestion & replay.
    - References raw MinIO URIs instead of duplicating raw payloads.
    - Faceted aggregations for metrics summaries.
    - Dedicated audit log indices.
    """

    def __init__(
        self,
        url: str,
        username: str | None = None,
        password: str | None = None,
        index_prefix: str = "ulpf-events-v1",
        verify_certs: bool = False,
        ca_certs: str | None = None,
    ):
        try:
            from opensearchpy import OpenSearch
        except ImportError:
            raise ImportError(
                "The 'opensearch-py' package is required for OpenSearchStore. Install with: pip install opensearch-py"
            )

        self.url = url
        self.index_prefix = index_prefix
        self.audit_index = f"{index_prefix}-audit"

        auth = (username, password) if username and password else None
        client_kwargs: dict[str, Any] = {
            "hosts": [url],
            "http_auth": auth,
            "use_ssl": url.startswith("https"),
            "verify_certs": verify_certs,
            "ssl_show_warn": False,
        }
        if ca_certs:
            client_kwargs["ca_certs"] = ca_certs

        self.client = OpenSearch(**client_kwargs)
        self._ensure_index_template()

    def _get_current_index(self) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        return f"{self.index_prefix}-{now.strftime('%Y.%m.%d')}"

    def _ensure_index_template(self):
        """Creates explicit index template to prevent mapping explosion."""
        template_body = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "1s",
                },
                "mappings": {
                    "properties": {
                        "event_id": {"type": "keyword"},
                        "ingest_timestamp": {"type": "date"},
                        "time_epoch": {"type": "long"},
                        "time_dt": {"type": "date"},
                        "vendor": {"type": "keyword"},
                        "product": {"type": "keyword"},
                        "detected_format": {"type": "keyword"},
                        "collector_host": {"type": "keyword"},
                        "class_uid": {"type": "integer"},
                        "class_name": {"type": "keyword"},
                        "category_uid": {"type": "integer"},
                        "category_name": {"type": "keyword"},
                        "severity_id": {"type": "integer"},
                        "severity": {"type": "keyword"},
                        "status_id": {"type": "integer"},
                        "status": {"type": "keyword"},
                        "disposition_id": {"type": "integer"},
                        "disposition": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "src_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_ip": {"type": "ip"},
                        "dst_port": {"type": "integer"},
                        "protocol_name": {"type": "keyword"},
                        "app_name": {"type": "keyword"},
                        "raw_sha256": {"type": "keyword"},
                        "sha256_hash": {"type": "keyword"},
                        "raw_storage_uri": {"type": "keyword"},
                        "trace_id": {"type": "keyword"},
                        "byte_length": {"type": "integer"},
                        "parser_used": {"type": "keyword"},
                        "parser_version": {"type": "keyword"},
                        "ocsf_schema_version": {"type": "keyword"},
                        "template_id": {"type": "integer"},
                        "confidence": {"type": "float"},
                        "ocsf": {"type": "object", "dynamic": True},
                    }
                },
            },
        }
        try:
            self.client.indices.put_index_template(
                name=f"{self.index_prefix}-template", body=template_body
            )
        except Exception:
            pass

    def _envelope_to_doc(self, envelope: EventEnvelope) -> dict[str, Any]:
        ocsf = envelope.ocsf or {}
        src = (
            ocsf.get("src_endpoint", {})
            if isinstance(ocsf.get("src_endpoint"), dict)
            else {}
        )
        dst = (
            ocsf.get("dst_endpoint", {})
            if isinstance(ocsf.get("dst_endpoint"), dict)
            else {}
        )
        conn_info = (
            ocsf.get("connection_info", {})
            if isinstance(ocsf.get("connection_info"), dict)
            else {}
        )

        time_epoch = ocsf.get("time") or int(
            datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000
        )
        time_dt = ocsf.get("time_dt") or envelope.ingest_timestamp
        trace_id = (
            envelope.traceability.get("trace_id")
            if envelope.traceability
            else envelope.event_id
        ) or envelope.event_id

        doc = {
            "event_id": envelope.event_id,
            "ingest_timestamp": envelope.ingest_timestamp,
            "time_dt": time_dt,
            "time_epoch": time_epoch,
            "trace_id": trace_id,
            "vendor": envelope.source.vendor,
            "product": envelope.source.product,
            "detected_format": str(
                envelope.source.detected_format.value
                if hasattr(envelope.source.detected_format, "value")
                else envelope.source.detected_format
            ),
            "collector_host": envelope.source.collector_host,
            "class_uid": ocsf.get("class_uid", 4001),
            "class_name": ocsf.get("class_name", "Network Activity"),
            "category_uid": ocsf.get("category_uid", 4),
            "category_name": ocsf.get("category_name", "Network Activity"),
            "severity_id": ocsf.get("severity_id", 1),
            "severity": ocsf.get("severity", "Informational"),
            "status_id": ocsf.get("status_id", 1),
            "status": ocsf.get("status", "Success"),
            "disposition_id": ocsf.get("disposition_id", 1),
            "disposition": ocsf.get("disposition", "Allowed"),
            "action": ocsf.get("action") or ocsf.get("activity_name") or "allow",
            "protocol_name": conn_info.get("protocol_name", "TCP"),
            "app_name": ocsf.get("app_name"),
            "raw_sha256": envelope.raw.sha256,
            "sha256_hash": envelope.raw.sha256,
            "raw_storage_uri": f"{envelope.raw.bucket}/{envelope.raw.object_key}",
            "byte_length": envelope.raw.byte_length,
            "parser_used": envelope.parsing.parser_used,
            "parser_version": envelope.parsing.parser_version,
            "ocsf_schema_version": "1.1.0",
            "template_id": envelope.parsing.template_id,
            "confidence": envelope.parsing.confidence,
            "ocsf": ocsf,
        }
        if src.get("ip"):
            doc["src_ip"] = src["ip"]
        if src.get("port"):
            doc["src_port"] = src["port"]
        if dst.get("ip"):
            doc["dst_ip"] = dst["ip"]
        if dst.get("port"):
            doc["dst_port"] = dst["port"]

        return doc

    def index_event(self, envelope: EventEnvelope):
        doc = self._envelope_to_doc(envelope)
        index_name = self._get_current_index()
        self.client.index(
            index=index_name, id=envelope.event_id, body=doc, refresh="wait_for"
        )

    def index_batch(self, envelopes: list[EventEnvelope]):
        if not envelopes:
            return
        from opensearchpy.helpers import bulk

        index_name = self._get_current_index()
        actions = [
            {
                "_index": index_name,
                "_id": env.event_id,
                "_source": self._envelope_to_doc(env),
            }
            for env in envelopes
        ]
        bulk(self.client, actions, refresh="wait_for")

    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        try:
            res = self.client.search(
                index=f"{self.index_prefix}-*",
                body={"query": {"term": {"event_id": event_id}}, "size": 1},
            )
            hits = res.get("hits", {}).get("hits", [])
            if hits:
                source = hits[0]["_source"]
                return source
            return None
        except Exception:
            return None

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
        offset: int = 0,
    ) -> dict[str, Any]:
        must_clauses = []
        if query:
            must_clauses.append(
                {
                    "multi_match": {
                        "query": query,
                        "fields": [
                            "raw_payload",
                            "ocsf.*",
                            "vendor",
                            "product",
                            "action",
                        ],
                    }
                }
            )
        if vendor:
            must_clauses.append({"term": {"vendor": vendor}})
        if product:
            must_clauses.append({"term": {"product": product}})
        if detected_format:
            must_clauses.append({"term": {"detected_format": detected_format}})
        if severity_id is not None:
            must_clauses.append({"term": {"severity_id": severity_id}})
        if disposition:
            must_clauses.append({"term": {"disposition": disposition}})
        if src_ip:
            must_clauses.append({"term": {"src_ip": src_ip}})
        if dst_ip:
            must_clauses.append({"term": {"dst_ip": dst_ip}})

        query_body = {
            "query": {"bool": {"must": must_clauses}}
            if must_clauses
            else {"match_all": {}},
            "sort": [{"time_epoch": {"order": "desc"}}],
            "from": offset,
            "size": limit,
        }

        try:
            res = self.client.search(index=f"{self.index_prefix}-*", body=query_body)
            total = res.get("hits", {}).get("total", {}).get("value", 0)
            hits = [h["_source"] for h in res.get("hits", {}).get("hits", [])]
            return {"total": total, "limit": limit, "offset": offset, "events": hits}
        except Exception as e:
            return {
                "total": 0,
                "limit": limit,
                "offset": offset,
                "events": [],
                "error": str(e),
            }

    def get_metrics_summary(self) -> dict[str, Any]:
        agg_body = {
            "size": 0,
            "aggs": {
                "vendors": {"terms": {"field": "vendor", "size": 10}},
                "formats": {"terms": {"field": "detected_format", "size": 10}},
                "severities": {"terms": {"field": "severity", "size": 10}},
                "dispositions": {"terms": {"field": "disposition", "size": 10}},
                "parsers": {"terms": {"field": "parser_used", "size": 10}},
                "total_bytes": {"sum": {"field": "byte_length"}},
            },
        }
        try:
            res = self.client.search(index=f"{self.index_prefix}-*", body=agg_body)
            total = res.get("hits", {}).get("total", {}).get("value", 0)
            aggs = res.get("aggregations", {})

            vendor_dist = {
                b["key"]: b["doc_count"]
                for b in aggs.get("vendors", {}).get("buckets", [])
            }
            format_dist = {
                b["key"]: b["doc_count"]
                for b in aggs.get("formats", {}).get("buckets", [])
            }
            severity_dist = {
                b["key"]: b["doc_count"]
                for b in aggs.get("severities", {}).get("buckets", [])
            }
            disposition_dist = {
                b["key"]: b["doc_count"]
                for b in aggs.get("dispositions", {}).get("buckets", [])
            }
            parser_dist = {
                b["key"]: b["doc_count"]
                for b in aggs.get("parsers", {}).get("buckets", [])
            }
            total_bytes = int(aggs.get("total_bytes", {}).get("value", 0))

            return {
                "total_events": total,
                "total_bytes": total_bytes,
                "vendor_distribution": vendor_dist,
                "format_distribution": format_dist,
                "severity_distribution": severity_dist,
                "disposition_distribution": disposition_dist,
                "parser_distribution": parser_dist,
            }
        except Exception:
            return {
                "total_events": 0,
                "total_bytes": 0,
                "vendor_distribution": {},
                "format_distribution": {},
                "severity_distribution": {},
                "disposition_distribution": {},
                "parser_distribution": {},
            }

    def record_audit(self, audit: Any):
        audit_dict = audit.model_dump() if hasattr(audit, "model_dump") else dict(audit)
        audit_id = audit_dict.get("audit_id")
        self.client.index(
            index=self.audit_index, id=audit_id, body=audit_dict, refresh="wait_for"
        )

    def list_audits(
        self,
        user: str | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        must = []
        if user:
            must.append({"term": {"user": user}})
        if action:
            must.append({"term": {"action": action}})
        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "from": offset,
            "size": limit,
        }
        try:
            res = self.client.search(index=self.audit_index, body=body)
            return [h["_source"] for h in res.get("hits", {}).get("hits", [])]
        except Exception:
            return []

    def health_check(self) -> dict[str, Any]:
        try:
            health = self.client.cluster.health()
            return {
                "backend": "OpenSearchStore",
                "status": "HEALTHY"
                if health.get("status") in ["green", "yellow"]
                else "DEGRADED",
                "cluster_name": health.get("cluster_name"),
                "cluster_status": health.get("status"),
                "node_count": health.get("number_of_nodes"),
                "active_shards": health.get("active_primary_shards"),
            }
        except Exception as e:
            return {
                "backend": "OpenSearchStore",
                "status": "UNHEALTHY",
                "url": self.url,
                "error": str(e),
            }


# Backwards compatibility alias
SearchIndex = SQLiteSearchStore


def get_search_store(settings: Settings | None = None) -> BaseSearchStore:
    """
    Factory creating the configured SearchStore adapter (SQLiteSearchStore or OpenSearchStore).
    """
    s = settings or get_settings()
    if s.ULPF_SEARCH_BACKEND == "opensearch" and s.ULPF_OPENSEARCH_URL:
        return OpenSearchStore(
            url=s.ULPF_OPENSEARCH_URL,
            username=s.ULPF_OPENSEARCH_USERNAME,
            password=s.ULPF_OPENSEARCH_PASSWORD,
            index_prefix=s.ULPF_OPENSEARCH_INDEX_PREFIX,
            verify_certs=s.ULPF_OPENSEARCH_VERIFY_CERTS,
            ca_certs=s.ULPF_OPENSEARCH_CA_CERTS,
        )
    return SQLiteSearchStore(db_path=f"{s.ULPF_BASE_DATA_DIR}/search_index.db")
