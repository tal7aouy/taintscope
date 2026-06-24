"""Configuration for TaintScope.

All settings can be overridden via environment variables, which keeps the
engine usable both as a library and as a CLI without hard-coded paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    """Runtime settings for the engine."""

    # Path to the PHP AST dumper script (uses nikic/PHP-Parser).
    php_dumper: str = field(
        default_factory=lambda: os.environ.get(
            "TAINTSCOPE_PHP_DUMPER",
            str(Path(__file__).resolve().parent.parent / "php-ast" / "dump_ast.php"),
        )
    )

    # Path to the php binary.
    php_binary: str = field(default_factory=lambda: os.environ.get("TAINTSCOPE_PHP_BINARY", "php"))

    # PostgreSQL connection URL. If unset, DB persistence is disabled and
    # findings are only returned in-memory / written to JSON.
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "TAINTSCOPE_DATABASE_URL", "postgresql+psycopg2://taintscope:taintscope@localhost:5432/taintscope"
        )
    )
    db_enabled: bool = field(default_factory=lambda: _env_bool("TAINTSCOPE_DB_ENABLED", False))

    # OpenAI settings for the LLM exploitability classifier.
    openai_api_key: str = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY", ""))
    openai_model: str = field(default_factory=lambda: os.environ.get("TAINTSCOPE_OPENAI_MODEL", "gpt-4o-mini"))
    llm_enabled: bool = field(default_factory=lambda: _env_bool("TAINTSCOPE_LLM_ENABLED", False))

    # Analysis tuning.
    max_call_depth: int = field(default_factory=lambda: int(os.environ.get("TAINTSCOPE_MAX_CALL_DEPTH", "5")))
    include_info: bool = field(default_factory=lambda: _env_bool("TAINTSCOPE_INCLUDE_INFO", False))


settings = Settings()
