"""CanaryMesh Database & Persistence Layer using SQLite with WAL Mode"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.config import get_settings


class Database:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_settings().database_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode and foreign keys for high concurrency & integrity
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Honeytokens registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    token_value_hash TEXT NOT NULL,
                    display_token TEXT NOT NULL,
                    token_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    creator TEXT DEFAULT 'system',
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    trigger_count INTEGER DEFAULT 0,
                    last_triggered_at TEXT,
                    webhook_url TEXT,
                    metadata_json TEXT DEFAULT '{}'
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_value_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_active ON tokens(is_active);")

            # Alerts & Forensic Breadcrumbs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    token_label TEXT NOT NULL,
                    token_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    http_method TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    request_headers_json TEXT NOT NULL,
                    request_payload TEXT,
                    query_params_json TEXT,
                    geo_location_json TEXT,
                    decoy_response_code INTEGER NOT NULL,
                    decoy_response_body TEXT,
                    severity TEXT DEFAULT 'CRITICAL',
                    notified INTEGER DEFAULT 0,
                    FOREIGN KEY(token_id) REFERENCES tokens(id) ON DELETE CASCADE
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_token ON alerts(token_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);")

            # Standalone decoy and cloud-provider events need no registered token.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS breach_logs (
                    id TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    path TEXT,
                    action TEXT,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    event_id TEXT,
                    source TEXT NOT NULL DEFAULT 'decoy',
                    account_id TEXT,
                    principal_arn TEXT,
                    severity TEXT NOT NULL DEFAULT 'CRITICAL'
                );
            """)
            existing_breach_columns = {
                row["name"] for row in cursor.execute("PRAGMA table_info(breach_logs)")
            }
            for name, definition in (
                ("event_id", "TEXT"),
                ("source", "TEXT NOT NULL DEFAULT 'decoy'"),
                ("account_id", "TEXT"),
                ("principal_arn", "TEXT"),
                ("severity", "TEXT NOT NULL DEFAULT 'CRITICAL'"),
            ):
                if name not in existing_breach_columns:
                    cursor.execute(f"ALTER TABLE breach_logs ADD COLUMN {name} {definition}")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_breach_logs_time ON breach_logs(timestamp);")
            cursor.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_breach_logs_event_id "
                "ON breach_logs(event_id) WHERE event_id IS NOT NULL;"
            )
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notification_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT
                );
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_notifications_status "
                "ON notification_deliveries(status, created_at);"
            )
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
            """)
            if not cursor.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 1"
            ).fetchone():
                self._redact_legacy_alert_data(cursor)
                cursor.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (1, datetime.now(timezone.utc).isoformat()),
                )
            conn.commit()

    @staticmethod
    def _redact_legacy_alert_data(cursor: sqlite3.Cursor) -> None:
        from app.core.forensics import redact_sensitive_data, sanitize_request_payload

        rows = cursor.execute(
            "SELECT id, request_headers_json, request_payload, query_params_json FROM alerts"
        ).fetchall()
        for row in rows:
            try:
                headers = json.loads(row["request_headers_json"] or "{}")
            except json.JSONDecodeError:
                headers = {}
            try:
                query_params = json.loads(row["query_params_json"] or "{}")
            except json.JSONDecodeError:
                query_params = {}
            cursor.execute(
                """
                UPDATE alerts
                SET request_headers_json = ?, request_payload = ?, query_params_json = ?
                WHERE id = ?
                """,
                (
                    json.dumps(redact_sensitive_data(headers)),
                    sanitize_request_payload(row["request_payload"]),
                    json.dumps(redact_sensitive_data(query_params)),
                    row["id"],
                ),
            )

    def record_breach(
        self,
        breach_id: str,
        token_type: str,
        source_ip: str,
        user_agent: str,
        path: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        source: str = "decoy",
        account_id: Optional[str] = None,
        principal_arn: Optional[str] = None,
        severity: str = "CRITICAL",
    ) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            if event_id:
                existing = conn.execute(
                    "SELECT * FROM breach_logs WHERE event_id = ?", (event_id,)
                ).fetchone()
                if existing:
                    breach = self._row_to_breach_dict(existing)
                    breach["_duplicate"] = True
                    return breach
            try:
                conn.execute(
                    """
                INSERT INTO breach_logs (
                    id, token_type, source_ip, user_agent, timestamp, path, action, details_json,
                    event_id, source, account_id, principal_arn, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        breach_id, token_type, source_ip, user_agent, now_iso, path, action,
                        json.dumps(details or {}), event_id, source, account_id, principal_arn,
                        severity,
                    ),
                )
            except sqlite3.IntegrityError:
                if not event_id:
                    raise
                existing = conn.execute(
                    "SELECT * FROM breach_logs WHERE event_id = ?", (event_id,)
                ).fetchone()
                if existing is None:
                    raise
                breach = self._row_to_breach_dict(existing)
                breach["_duplicate"] = True
                return breach
            conn.commit()
        return self.get_breach(breach_id)  # type: ignore

    def get_breach(self, breach_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM breach_logs WHERE id = ?", (breach_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_breach_dict(row)

    @staticmethod
    def _row_to_breach_dict(row: sqlite3.Row) -> Dict[str, Any]:
        breach = dict(row)
        breach["details"] = json.loads(breach.pop("details_json") or "{}")
        return breach

    def list_breaches(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM breach_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._row_to_breach_dict(row) for row in rows]

    def list_events(
        self,
        limit: int = 100,
        token_id: Optional[str] = None,
        token_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        predicates = []
        params: List[Any] = []
        for field, value in (
            ("token_id", token_id),
            ("token_type", token_type),
            ("source_ip", source_ip),
            ("severity", severity),
            ("source", source),
        ):
            if value is not None:
                predicates.append(f"{field} = ?")
                params.append(value)
        if since is not None:
            predicates.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            predicates.append("timestamp <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(predicates)}" if predicates else ""
        query = f"""
            SELECT * FROM (
                SELECT
                    id, timestamp, token_type, client_ip AS source_ip, user_agent,
                    'token' AS source, request_path AS path, http_method AS action,
                    severity, token_id, token_label, NULL AS event_id, NULL AS account_id,
                    NULL AS principal_arn, geo_location_json AS details_json
                FROM alerts
                UNION ALL
                SELECT
                    id, timestamp, token_type, source_ip, user_agent, source, path, action,
                    severity, NULL AS token_id, NULL AS token_label, event_id, account_id,
                    principal_arn, details_json
                FROM breach_logs
            ) {where}
            ORDER BY timestamp DESC LIMIT ?
        """
        params.append(limit)
        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            try:
                event["details"] = json.loads(event.pop("details_json") or "{}")
            except json.JSONDecodeError:
                event["details"] = {}
            events.append(event)
        return events

    def create_notification(self, event_id: str) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO notification_deliveries
                    (event_id, status, attempts, created_at, updated_at)
                VALUES (?, 'pending', 0, ?, ?)
                """,
                (event_id, now_iso, now_iso),
            )
            row = conn.execute(
                "SELECT * FROM notification_deliveries WHERE event_id = ?", (event_id,)
            ).fetchone()
        return dict(row)

    def get_notification(self, notification_id: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM notification_deliveries WHERE id = ?", (notification_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_notifications(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM notification_deliveries ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_pending_notifications(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM notification_deliveries WHERE status = 'pending' "
                "ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def update_notification(
        self,
        notification_id: int,
        status: str,
        attempts: int,
        last_error: Optional[str] = None,
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE notification_deliveries
                SET status = ?, attempts = ?, last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, attempts, last_error, datetime.now(timezone.utc).isoformat(), notification_id),
            )
            conn.commit()

    def retry_notification(self, notification_id: int) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET status = 'pending', attempts = 0, last_error = NULL, updated_at = ?
                WHERE id = ? AND status = 'failed'
                """,
                (datetime.now(timezone.utc).isoformat(), notification_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        breach = self.get_breach(event_id)
        if breach:
            return breach
        return self.get_alert(event_id)

    def get_event_webhook_url(self, event_id: str) -> Optional[str]:
        alert = self.get_alert(event_id)
        if not alert:
            return None
        token = self.get_token(alert["token_id"])
        return token.get("webhook_url") if token else None

    def mark_alert_notified(self, alert_id: str, notified: bool) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE alerts SET notified = ? WHERE id = ?",
                (1 if notified else 0, alert_id),
            )
            conn.commit()

    def save_token(
        self,
        token_id: str,
        token_value_hash: str,
        display_token: str,
        token_type: str,
        label: str,
        environment: str,
        creator: str = "system",
        expires_at: Optional[datetime] = None,
        webhook_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        expires_iso = expires_at.isoformat() if expires_at else None
        meta_json = json.dumps(metadata or {})

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tokens (
                    id, token_value_hash, display_token, token_type, label,
                    environment, creator, created_at, expires_at, is_active,
                    trigger_count, last_triggered_at, webhook_url, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, NULL, ?, ?)
                """,
                (
                    token_id,
                    token_value_hash,
                    display_token,
                    token_type,
                    label,
                    environment,
                    creator,
                    now_iso,
                    expires_iso,
                    webhook_url,
                    meta_json,
                ),
            )
            conn.commit()

        return self.get_token(token_id)  # type: ignore

    def get_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tokens WHERE id = ?", (token_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_token_dict(row)

    def find_token_by_hash(self, token_value_hash: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tokens WHERE token_value_hash = ?", (token_value_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_token_dict(row)

    def list_tokens(self, is_active: Optional[bool] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if is_active is not None:
                cursor.execute(
                    "SELECT * FROM tokens WHERE is_active = ? ORDER BY created_at DESC LIMIT ?",
                    (1 if is_active else 0, limit),
                )
            else:
                cursor.execute("SELECT * FROM tokens ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [self._row_to_token_dict(r) for r in rows]

    def revoke_token(self, token_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE tokens SET is_active = 0 WHERE id = ?", (token_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_token(self, token_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
            conn.commit()
            return cursor.rowcount > 0

    def record_alert(
        self,
        alert_id: str,
        token_id: str,
        token_label: str,
        token_type: str,
        client_ip: str,
        user_agent: str,
        http_method: str,
        request_path: str,
        headers: Dict[str, str],
        payload: Optional[str],
        query_params: Optional[Dict[str, Any]],
        geo_location: Optional[Dict[str, Any]],
        decoy_response_code: int,
        decoy_response_body: Optional[str],
        severity: str = "CRITICAL",
        notified: bool = False,
    ) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert alert record
            cursor.execute(
                """
                INSERT INTO alerts (
                    id, token_id, token_label, token_type, timestamp, client_ip,
                    user_agent, http_method, request_path, request_headers_json,
                    request_payload, query_params_json, geo_location_json,
                    decoy_response_code, decoy_response_body, severity, notified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    token_id,
                    token_label,
                    token_type,
                    now_iso,
                    client_ip,
                    user_agent,
                    http_method,
                    request_path,
                    json.dumps(headers),
                    payload,
                    json.dumps(query_params or {}),
                    json.dumps(geo_location or {}),
                    decoy_response_code,
                    decoy_response_body,
                    severity,
                    1 if notified else 0,
                ),
            )

            # Update token stats
            cursor.execute(
                """
                UPDATE tokens
                SET trigger_count = trigger_count + 1,
                    last_triggered_at = ?
                WHERE id = ?
                """,
                (now_iso, token_id),
            )
            conn.commit()

        return self.get_alert(alert_id)  # type: ignore

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_alert_dict(row)

    def list_alerts(self, token_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if token_id:
                cursor.execute(
                    "SELECT * FROM alerts WHERE token_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (token_id, limit),
                )
            else:
                cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [self._row_to_alert_dict(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tokens WHERE is_active = 1")
            active_tokens = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE is_active = 0")
            revoked_tokens = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE trigger_count > 0")
            tripped_tokens = cursor.fetchone()[0]

            cursor.execute(
                "SELECT (SELECT COUNT(*) FROM alerts) + "
                "(SELECT COUNT(*) FROM breach_logs)"
            )
            total_alerts = cursor.fetchone()[0]

            # Count by token type
            cursor.execute("SELECT token_type, COUNT(*) FROM tokens GROUP BY token_type")
            type_distribution = {r[0]: r[1] for r in cursor.fetchall()}

            return {
                "active_tokens": active_tokens,
                "revoked_tokens": revoked_tokens,
                "tripped_tokens": tripped_tokens,
                "total_alerts": total_alerts,
                "token_type_distribution": type_distribution,
            }

    @staticmethod
    def _row_to_token_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["is_active"] = bool(d["is_active"])
        try:
            d["metadata"] = json.loads(d.get("metadata_json") or "{}")
        except Exception:
            d["metadata"] = {}
        d.pop("metadata_json", None)
        return d

    @staticmethod
    def _row_to_alert_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["notified"] = bool(d["notified"])
        try:
            d["headers"] = json.loads(d.get("request_headers_json") or "{}")
        except Exception:
            d["headers"] = {}
        try:
            d["query_params"] = json.loads(d.get("query_params_json") or "{}")
        except Exception:
            d["query_params"] = {}
        try:
            d["geo_location"] = json.loads(d.get("geo_location_json") or "{}")
        except Exception:
            d["geo_location"] = {}
        d.pop("request_headers_json", None)
        d.pop("query_params_json", None)
        d.pop("geo_location_json", None)
        d["payload"] = d.pop("request_payload", None)
        return d


# Global database instance
_db_instance: Optional[Database] = None


def get_db() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
