"""TaintScope — a PHP/Python taint analysis engine.

TaintScope parses a codebase into ASTs, builds a call graph, and performs
intra- and inter-procedural taint analysis to follow user-controlled input
from *sources* (e.g. ``$_GET``, ``request.args``) to *sinks* (e.g.
``mysqli_query``, ``exec``, ``eval``) without passing through a *sanitizer*.
Findings are persisted to PostgreSQL, exposed via a FastAPI service, and
optionally post-filtered by an LLM-based exploitability classifier that
mimics the false-positive reduction shown in recent SAST research.
"""

__version__ = "0.1.0"
