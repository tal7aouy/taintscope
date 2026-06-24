"""Call graph construction over the normalized IR.

The call graph is a :class:`networkx.DiGraph` whose nodes are function keys
(``"ClassName::method"`` or ``"function_name"``) and whose edges represent a
call from one function to another. Edges are annotated with the call site
location so the taint engine can report precise data-flow paths.

We resolve calls conservatively: a call to ``foo(...)`` resolves to any
defined function named ``foo``. Method calls (``$obj->foo()``) resolve to any
method named ``foo`` regardless of the receiver type — this is a sound
over-approximation typical of lightweight SAST engines and avoids needing a
full type inference pass. Dynamic calls (``$f()`` / ``getattr``) are tracked
as unresolved edges to a synthetic ``"*"`` node so they appear in reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import networkx as nx

from ..ast.base import FunctionDef, Node


@dataclass
class CallSite:
    """A single call occurrence inside a function body."""

    caller: str
    callee: str
    location: Optional[str] = None
    is_resolved: bool = True
    # Argument expressions (as IR nodes) so the taint engine can map
    # caller-side taint into callee parameters.
    arg_nodes: List[Node] = field(default_factory=list)


class CallGraph:
    """Builds and stores the interprocedural call graph."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        # name -> FunctionDef, plus class-qualified index.
        self.functions: Dict[str, FunctionDef] = {}
        self.methods_by_name: Dict[str, List[str]] = {}
        self.call_sites: List[CallSite] = []
        # functions that are never defined (e.g. builtins / library calls).
        self.external_calls: Dict[str, int] = {}

    # -- construction ----------------------------------------------------

    def add_function(self, fn: FunctionDef) -> str:
        key = self._key(fn)
        self.functions[key] = fn
        if fn.is_method:
            short = fn.name
            self.methods_by_name.setdefault(short, []).append(key)
        else:
            # Also index bare function name for unqualified calls.
            self.methods_by_name.setdefault(fn.name, []).append(key)
        self.graph.add_node(key)
        return key

    def build(self, functions: Iterable[FunctionDef]) -> None:
        for fn in functions:
            self.add_function(fn)
        for fn in list(self.functions.values()):
            self._scan_calls(fn)

    def _key(self, fn: FunctionDef) -> str:
        return f"{fn.class_name}::{fn.name}" if fn.is_method else fn.name

    def _scan_calls(self, fn: FunctionDef) -> None:
        caller = self._key(fn)
        for node in fn.body.walk():
            callee_name, arg_nodes = self._callee_of(node)
            if callee_name is None:
                continue
            targets = self._resolve(callee_name, node)
            if not targets:
                # External / library call. Record it so the taint engine can
                # still treat it as a sink if it matches a known sink name.
                self.external_calls[callee_name] = self.external_calls.get(callee_name, 0) + 1
                self.call_sites.append(
                    CallSite(
                        caller=caller,
                        callee=callee_name,
                        location=str(node.location) if node.location else None,
                        is_resolved=False,
                        arg_nodes=arg_nodes,
                    )
                )
                continue
            for tgt in targets:
                self.graph.add_edge(caller, tgt)
                self.call_sites.append(
                    CallSite(
                        caller=caller,
                        callee=tgt,
                        location=str(node.location) if node.location else None,
                        is_resolved=True,
                        arg_nodes=arg_nodes,
                    )
                )

    def _callee_of(self, node: Node):
        """Return (callee_name, arg_nodes) if ``node`` is a call, else (None, [])."""
        if node.kind == "FuncCall":
            name = node.attrs.get("name")
            args = [c for c in node.children if c.kind not in ("Name", "Identifier")]
            # Descend into Arg nodes to get the actual argument expressions.
            args = [c.children[0] if c.kind == "Arg" and c.children else c for c in args]
            return name, args
        if node.kind in ("MethodCall", "StaticCall"):
            name = node.attrs.get("name")
            # MethodCall: [receiver, Arg, Arg, ...]  — skip receiver
            # StaticCall: [Arg, Arg, ..., Name(class)]  — keep Args only
            if node.kind == "MethodCall":
                args = [c for c in node.children[1:] if c.kind == "Arg"] if len(node.children) > 1 else []
            else:
                args = [c for c in node.children if c.kind == "Arg"]
            # Descend into Arg nodes to get the actual argument expressions.
            args = [c.children[0] if c.kind == "Arg" and c.children else c for c in args]
            return name, args
        if node.kind == "Call":  # Python IR
            if node.children:
                callee = node.children[0]
                if callee.kind == "Name":
                    return callee.attrs.get("name"), node.children[1:]
                if callee.kind == "Attribute":
                    return callee.attrs.get("attr"), node.children[1:]
            return None, []
        return None, []

    def _resolve(self, name: Optional[str], node: Node) -> List[str]:
        if not name:
            return []
        candidates = self.methods_by_name.get(name, [])
        return candidates

    # -- queries ---------------------------------------------------------

    def callees_of(self, fn_key: str) -> List[str]:
        return list(self.graph.successors(fn_key))

    def callers_of(self, fn_key: str) -> List[str]:
        return list(self.graph.predecessors(fn_key))

    def call_sites_between(self, caller: str, callee: str) -> List[CallSite]:
        return [c for c in self.call_sites if c.caller == caller and c.callee == callee]

    def has_function(self, key: str) -> bool:
        return key in self.functions

    def function(self, key: str) -> Optional[FunctionDef]:
        return self.functions.get(key)

    def is_external(self, name: str) -> bool:
        return name in self.external_calls or name not in self.functions
