"""Findings persistence (PostgreSQL via SQLAlchemy, optional)."""

from .db import Database, get_database

__all__ = ["Database", "get_database"]
