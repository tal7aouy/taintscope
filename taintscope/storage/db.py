"""PostgreSQL findings storage via SQLAlchemy.

The schema stores one row per finding plus a JSONB column for the rendered
data-flow path and (optionally) the LLM verdict. The database is *optional*:
if ``TAINTSCOPE_DB_ENABLED`` is false (the default) or the connection cannot
be opened, the engine silently falls back to in-memory / JSON-only reporting.
This keeps TaintScope usable out-of-the-box for bug-hunting without forcing
operators to stand up Postgres.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from ..config import settings
from ..taint.engine import Finding

Base = declarative_base()


class FindingRow(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    language = Column(String(16), nullable=False, index=True)
    category = Column(String(32), nullable=False, index=True)
    sink = Column(String(128), nullable=False)
    source = Column(String(256), nullable=False)
    sink_location = Column(String(256))
    source_location = Column(String(256))
    flow = Column(Text)
    severity = Column(String(16), default="High")
    llm_verdict = Column(String(16))
    llm_confidence = Column(String(16))
    llm_reasoning = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class Database:
    """Thin wrapper around a SQLAlchemy session for findings."""

    def __init__(self, url: str) -> None:
        self.engine = create_engine(url, future=True)
        self.Session = sessionmaker(bind=self.engine, future=True)
        Base.metadata.create_all(self.engine)

    def save_findings(self, findings: List[Finding]) -> int:
        session: Session = self.Session()
        try:
            for f in findings:
                row = FindingRow(
                    language=f.language,
                    category=f.category,
                    sink=f.sink,
                    source=f.source,
                    sink_location=f.sink_location,
                    source_location=f.source_location,
                    flow=f.flow,
                    severity=f.severity,
                    llm_verdict=f.llm_verdict,
                    llm_confidence=None if f.llm_confidence is None else f"{f.llm_confidence:.2f}",
                    llm_reasoning=f.llm_reasoning,
                )
                session.add(row)
            session.commit()
            return len(findings)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def list_findings(self, limit: int = 100) -> List[dict]:
        session: Session = self.Session()
        try:
            rows = session.query(FindingRow).order_by(FindingRow.id.desc()).limit(limit).all()
            return [_row_to_dict(r) for r in rows]
        finally:
            session.close()

    def findings_by_category(self, category: str) -> List[dict]:
        session: Session = self.Session()
        try:
            rows = session.query(FindingRow).filter(FindingRow.category == category).all()
            return [_row_to_dict(r) for r in rows]
        finally:
            session.close()


def _row_to_dict(r: FindingRow) -> dict:
    return {
        "id": r.id,
        "language": r.language,
        "category": r.category,
        "sink": r.sink,
        "source": r.source,
        "sink_location": r.sink_location,
        "source_location": r.source_location,
        "flow": r.flow,
        "severity": r.severity,
        "llm_verdict": r.llm_verdict,
        "llm_confidence": r.llm_confidence,
        "llm_reasoning": r.llm_reasoning,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def get_database() -> Optional[Database]:
    """Return a Database if enabled & reachable, else None."""
    if not settings.db_enabled:
        return None
    try:
        return Database(settings.database_url)
    except Exception:
        # Connection failures are non-fatal; the engine still reports.
        return None
