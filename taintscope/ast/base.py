"""Normalized AST IR shared by the PHP and Python front-ends.

Both front-ends convert their language-specific ASTs into the lightweight
``Node`` tree defined here. The taint engine only depends on this IR, so
adding a new language only requires writing a new parser module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Location:
    """A source span."""

    file: str
    start_line: int
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.start_line}"


@dataclass
class Node:
    """A normalized AST node.

    ``kind`` is a stable, language-agnostic tag (e.g. ``"Assign"``,
    ``"FuncCall"``, ``"ArrayDimFetch"``, ``"Return"``). ``attrs`` holds any
    language-specific extras. ``children`` holds sub-nodes in order.
    """

    kind: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    children: List["Node"] = field(default_factory=list)
    location: Optional[Location] = None

    # Convenience accessors used across the engine.
    @property
    def name(self) -> Optional[str]:
        return self.attrs.get("name")

    def walk(self):
        """Depth-first pre-order traversal yielding every node."""
        yield self
        for child in self.children:
            yield from child.walk()


@dataclass
class FunctionDef:
    """A discovered function/method definition used to build the call graph."""

    name: str
    params: List[str]
    body: Node  # kind == "StmtBlock"
    location: Optional[Location] = None
    class_name: Optional[str] = None
    is_method: bool = False


def make_node(kind: str, **attrs) -> Node:
    """Quick constructor for tests / fixtures."""
    return Node(kind=kind, attrs=attrs)
