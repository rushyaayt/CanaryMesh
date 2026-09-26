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

            cursor.execute("SELECT COUNT(*) FROM alerts")
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
        return d


# Global database instance
_db_instance: Optional[Database] = None


def get_db() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
