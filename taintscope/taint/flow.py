"""Taint state and data-flow path representation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..ast.base import Location


@dataclass(frozen=True)
class TaintState:
    """Marks a variable as tainted at a given point in the program.

    ``origin`` is a human-readable description of where the taint came from
    (e.g. ``"$_GET['id']"``). ``sanitized_for`` lists categories for which
    the taint has been neutralized (e.g. ``{"SQLi"}`` after
    ``mysqli_real_escape_string``).
    """

    var: str
    origin: str
    origin_location: Optional[str] = None
    sanitized_for: frozenset = field(default_factory=frozenset)

    def is_tainted_for(self, category: str) -> bool:
        return category not in self.sanitized_for

    def sanitize(self, category: str) -> "TaintState":
        return TaintState(
            var=self.var,
            origin=self.origin,
            origin_location=self.origin_location,
            sanitized_for=self.sanitized_for | {category},
        )


@dataclass
class TaintPath:
    """One step in a data-flow path."""

    description: str
    location: Optional[str] = None
    node_kind: str = ""

    def __str__(self) -> str:
        loc = f" at {self.location}" if self.location else ""
        return f"{self.description}{loc}"


@dataclass
class DataFlowPath:
    """A full source-to-sink data flow."""

    steps: List[TaintPath] = field(default_factory=list)

    def add(self, description: str, location: Optional[str] = None, node_kind: str = "") -> None:
        self.steps.append(TaintPath(description, location, node_kind))

    def render(self) -> str:
        return " -> ".join(str(s) for s in self.steps)
