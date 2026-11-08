from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.models.artefact import (
    Artefact,
    ArtefactType,
    Location,
    QuantumStatus,
    Scan,
    ScanStatus,
)

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "ecdat.db"


class DatabaseManager:
    """
    SQLite persistence layer for ECDAT scans, discovered artefacts, and quantum postures.
    """

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = str(db_path) if db_path is not None else str(DEFAULT_DB_PATH)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_artefacts INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    metadata_json TEXT DEFAULT '{}'
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS artefacts (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    mode TEXT,
                    key_size INTEGER,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    column_number INTEGER,
                    detection_method TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    quantum_status TEXT,
                    nist_replacement TEXT,
                    notes TEXT,
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_artefacts_scan_id ON artefacts(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_artefacts_type ON artefacts(type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_artefacts_quantum ON artefacts(quantum_status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_artefacts_name ON artefacts(name);")
            conn.commit()

    def create_scan(
        self,
        target_path: str,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Scan:
        """Create a new scan record."""
        scan_kwargs = {
            "target_path": target_path,
            "status": ScanStatus.PENDING,
            "total_artefacts": 0,
            "created_at": datetime.now(timezone.utc),
            "metadata": metadata or {},
        }
        if scan_id:
            scan_kwargs["id"] = scan_id

        scan = Scan(**scan_kwargs)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, target_path, status, total_artefacts, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.id,
                    scan.target_path,
                    scan.status.value,
                    scan.total_artefacts,
                    scan.created_at.isoformat(),
                    json.dumps(scan.metadata),
                ),
            )
            conn.commit()
        return scan

    def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus | str,
        completed_at: Optional[datetime] = None,
        total_artefacts: Optional[int] = None,
    ) -> Optional[Scan]:
        """Update scan status and completion time."""
        status_val = status.value if isinstance(status, ScanStatus) else str(status)
        completed_iso = completed_at.isoformat() if completed_at else None

        with self._get_connection() as conn:
            if total_artefacts is not None:
                conn.execute(
                    """
                    UPDATE scans
                    SET status = ?, completed_at = COALESCE(?, completed_at), total_artefacts = ?
                    WHERE id = ?
                    """,
                    (status_val, completed_iso, total_artefacts, scan_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE scans
                    SET status = ?, completed_at = COALESCE(?, completed_at)
                    WHERE id = ?
                    """,
                    (status_val, completed_iso, scan_id),
                )
            conn.commit()

        return self.get_scan(scan_id)

    def save_artefacts(self, scan_id: str, artefacts: List[Artefact]) -> int:
        """Persist a list of discovered artefacts for a given scan."""
        if not artefacts:
            return 0

        rows = []
        for a in artefacts:
            rows.append((
                a.id,
                scan_id,
                a.type.value if hasattr(a.type, "value") else str(a.type),
                a.name,
                a.version,
                a.mode,
                a.key_size,
                a.location.file,
                a.location.line,
                a.location.column,
                a.detection_method,
                a.evidence,
                a.confidence,
                a.quantum_status.value if a.quantum_status else None,
                a.nist_replacement,
                a.notes,
                json.dumps(a.metadata),
                a.created_at.isoformat(),
            ))

        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO artefacts (
                    id, scan_id, type, name, version, mode, key_size,
                    file_path, line_number, column_number,
                    detection_method, evidence, confidence,
                    quantum_status, nist_replacement, notes,
                    metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

            # Update total count in scan
            conn.execute(
                "UPDATE scans SET total_artefacts = (SELECT COUNT(*) FROM artefacts WHERE scan_id = ?) WHERE id = ?",
                (scan_id, scan_id),
            )
            conn.commit()

        return len(artefacts)

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Fetch a single scan by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_scan(row)

    def list_scans(self) -> List[Scan]:
        """List all scans in descending order of creation."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scans ORDER BY created_at DESC")
            return [self._row_to_scan(row) for row in cursor.fetchall()]

    def get_artefacts(
        self,
        scan_id: str,
        type_filter: Optional[str] = None,
        quantum_filter: Optional[str] = None,
    ) -> List[Artefact]:
        """Query artefacts for a scan with optional filters."""
        query = "SELECT * FROM artefacts WHERE scan_id = ?"
        params: List[Any] = [scan_id]

        if type_filter:
            query += " AND type = ?"
            params.append(type_filter.lower())
        if quantum_filter:
            query += " AND quantum_status = ?"
            params.append(quantum_filter.lower())

        query += " ORDER BY file_path, line_number"

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_artefact(row) for row in cursor.fetchall()]

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated artefacts via CASCADE."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_scan_summary(self, scan_id: str) -> Dict[str, Any]:
        """Generate high-level aggregation metrics for a scan."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT quantum_status, COUNT(*) as count FROM artefacts WHERE scan_id = ? GROUP BY quantum_status",
                (scan_id,),
            )
            quantum_counts = {row["quantum_status"] or "unclassified": row["count"] for row in cur.fetchall()}

            cur = conn.execute(
                "SELECT type, COUNT(*) as count FROM artefacts WHERE scan_id = ? GROUP BY type",
                (scan_id,),
            )
            type_counts = {row["type"]: row["count"] for row in cur.fetchall()}

            cur = conn.execute("SELECT COUNT(*) as total FROM artefacts WHERE scan_id = ?", (scan_id,))
            total = cur.fetchone()["total"]

            return {
                "scan_id": scan_id,
                "total_artefacts": total,
                "by_quantum_status": quantum_counts,
                "by_type": type_counts,
            }

    @staticmethod
    def _row_to_scan(row: sqlite3.Row) -> Scan:
        return Scan(
            id=row["id"],
            target_path=row["target_path"],
            status=ScanStatus(row["status"]),
            total_artefacts=row["total_artefacts"],
            created_at=datetime.fromisoformat(row["created_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    @staticmethod
    def _row_to_artefact(row: sqlite3.Row) -> Artefact:
        return Artefact(
            id=row["id"],
            scan_id=row["scan_id"],
            type=ArtefactType(row["type"]),
            name=row["name"],
            version=row["version"],
            mode=row["mode"],
            key_size=row["key_size"],
            location=Location(
                file=row["file_path"],
                line=row["line_number"],
                column=row["column_number"],
            ),
            detection_method=row["detection_method"],
            evidence=row["evidence"],
            confidence=row["confidence"],
            quantum_status=QuantumStatus(row["quantum_status"]) if row["quantum_status"] else None,
            nist_replacement=row["nist_replacement"],
            notes=row["notes"],
            metadata=json.loads(row["metadata_json"] or "{}"),
            created_at=datetime.fromisoformat(row["created_at"]),
        )


# Global default database instance
db = DatabaseManager()
