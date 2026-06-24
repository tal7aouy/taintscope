"""FastAPI service exposing stored findings and an on-demand scan endpoint.

Run with::

    uvicorn taintscope.api.main:app --reload

Endpoints:

* ``GET /``                              — health / version
* ``GET /findings``                      — list recent findings (optional ``?category=``)
* ``GET /findings/{id}``                 — fetch a single finding
* ``POST /scan``                         — scan a list of file paths on demand
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from .. import __version__
from ..storage.db import get_database
from ..taint.engine import TaintEngine, Finding


class ScanRequest(BaseModel):
    paths: List[str]
    enable_llm: bool = False


def create_app() -> FastAPI:
    application = FastAPI(title="TaintScope", version=__version__)
    db = get_database()

    @application.get("/")
    def root() -> dict:
        return {
            "name": "TaintScope",
            "version": __version__,
            "db_enabled": db is not None,
        }

    @application.get("/findings")
    def list_findings(
        category: Optional[str] = Query(None),
        limit: int = Query(100, le=1000),
    ) -> List[dict]:
        if db is None:
            raise HTTPException(status_code=503, detail="Database persistence is disabled (set TAINTSCOPE_DB_ENABLED=1).")
        if category:
            return db.findings_by_category(category)
        return db.list_findings(limit=limit)

    @application.post("/scan")
    def scan(req: ScanRequest) -> dict:
        engine = TaintEngine()
        findings = engine.analyze_paths(req.paths)
        if req.enable_llm:
            from ..llm.classifier import LLMClassifier

            LLMClassifier().classify(findings)
        if db is not None and findings:
            db.save_findings(findings)
        return {
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

    return application


app = create_app()
