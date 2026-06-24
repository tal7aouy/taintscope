"""Python front-end: uses the stdlib :mod:`ast` module and normalizes to IR."""

from __future__ import annotations

import ast as pyast
from typing import List, Optional

from .base import FunctionDef, Location, Node


class PyParser:
    """Parses Python source into the normalized IR using :mod:`ast`."""

    def parse_file(self, path: str) -> Node:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        return self.parse_source(source, file=str(path))

    def parse_source(self, source: str, file: str = "<string>") -> Node:
        tree = pyast.parse(source, filename=file)
        return self._convert_module(tree, file)

    # -- internals -------------------------------------------------------

    def _convert_module(self, tree: pyast.Module, file: str) -> Node:
        children = [self._convert(n, file) for n in tree.body]
        return Node(kind="Program", attrs={"file": file}, children=children)

    def _loc(self, node: pyast.AST, file: str) -> Optional[Location]:
        return Location(
            file=file,
            start_line=getattr(node, "lineno", 0),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)) or 0,
            start_column=getattr(node, "col_offset", 0),
            end_column=getattr(node, "end_col_offset", 0) or 0,
        )

    def _convert(self, node: pyast.AST, file: str) -> Node:
        if node is None:
            return Node(kind="None")
        if isinstance(node, list):
            return Node(kind="List", children=[self._convert(n, file) for n in node])

        kind = type(node).__name__
        attrs: dict = {}
        children: List[Node] = []
        loc = self._loc(node, file)

        if isinstance(node, pyast.FunctionDef):
            attrs["name"] = node.name
            attrs["args"] = [a.arg for a in node.args.args]
            children.append(self._convert(node.body, file))
        elif isinstance(node, pyast.ClassDef):
            attrs["name"] = node.name
            children.extend(self._convert(n, file) for n in node.body)
        elif isinstance(node, pyast.Assign):
            children.append(Node(kind="AssignTarget", children=[self._convert(t, file) for t in node.targets]))
            children.append(Node(kind="AssignValue", children=[self._convert(node.value, file)]))
        elif isinstance(node, pyast.AugAssign):
            attrs["op"] = type(node.op).__name__
            children.append(Node(kind="AssignTarget", children=[self._convert(node.target, file)]))
            children.append(Node(kind="AssignValue", children=[self._convert(node.value, file)]))
        elif isinstance(node, pyast.Call):
            children.append(self._convert(node.func, file))
            children.extend(self._convert(a, file) for a in node.args)
            children.extend(self._convert(kw.value, file) for kw in node.keywords)
        elif isinstance(node, pyast.Attribute):
            attrs["attr"] = node.attr
            children.append(self._convert(node.value, file))
        elif isinstance(node, pyast.Subscript):
            children.append(self._convert(node.value, file))
            slc = node.slice
            if isinstance(slc, pyast.Index):  # py<3.9
                slc = slc.value
            children.append(self._convert(slc, file))
        elif isinstance(node, pyast.Name):
            attrs["name"] = node.id
        elif isinstance(node, pyast.Constant):
            attrs["value"] = node.value
        elif isinstance(node, (pyast.List, pyast.Tuple, pyast.Set)):
            children.extend(self._convert(e, file) for e in node.elts)
        elif isinstance(node, pyast.Dict):
            children.extend(self._convert(k, file) for k in node.keys)
            children.extend(self._convert(v, file) for v in node.values)
        elif isinstance(node, pyast.BinOp):
            attrs["op"] = type(node.op).__name__
            children.append(self._convert(node.left, file))
            children.append(self._convert(node.right, file))
        elif isinstance(node, pyast.BoolOp):
            attrs["op"] = type(node.op).__name__
            children.extend(self._convert(v, file) for v in node.values)
        elif isinstance(node, pyast.UnaryOp):
            attrs["op"] = type(node.op).__name__
            children.append(self._convert(node.operand, file))
        elif isinstance(node, pyast.Compare):
            attrs["ops"] = [type(o).__name__ for o in node.ops]
            children.append(self._convert(node.left, file))
            children.extend(self._convert(c, file) for c in node.comparators)
        elif isinstance(node, pyast.If):
            children.append(self._convert(node.test, file))
            children.append(Node(kind="Body", children=[self._convert(n, file) for n in node.body]))
            children.append(Node(kind="Orelse", children=[self._convert(n, file) for n in node.orelse]))
        elif isinstance(node, (pyast.While, pyast.For)):
            if isinstance(node, pyast.For):
                children.append(self._convert(node.target, file))
                children.append(self._convert(node.iter, file))
            else:
                children.append(self._convert(node.test, file))
            children.append(Node(kind="Body", children=[self._convert(n, file) for n in node.body]))
            children.append(Node(kind="Orelse", children=[self._convert(n, file) for n in node.orelse]))
        elif isinstance(node, pyast.Return):
            if node.value is not None:
                children.append(self._convert(node.value, file))
        elif isinstance(node, pyast.Expr):
            children.append(self._convert(node.value, file))
        elif isinstance(node, (pyast.Import, pyast.ImportFrom)):
            pass  # imports are irrelevant to taint flow
        else:
            # Generic fallback: recurse into child AST fields.
            for fld in node._fields:
                val = getattr(node, fld, None)
                if val is None:
                    continue
                if isinstance(val, list):
                    children.extend(self._convert(v, file) for v in val)
                elif isinstance(val, pyast.AST):
                    children.append(self._convert(val, file))

        return Node(kind=kind, attrs=attrs, children=children, location=loc)


def extract_functions(program: Node) -> List[FunctionDef]:
    """Walk a Python program IR and collect function/method definitions."""
    funcs: List[FunctionDef] = []

    def visit(node: Node, class_name: Optional[str] = None):
        if node.kind == "FunctionDef":
            name = node.attrs.get("name", "<anonymous>")
            params = node.attrs.get("args", []) or []
            body = Node(kind="StmtBlock")
            for child in node.children:
                if child.kind == "List":
                    body.children.extend(child.children)
                else:
                    body.children.append(child)
            funcs.append(
                FunctionDef(
                    name=name,
                    params=params,
                    body=body,
                    location=node.location,
                    class_name=class_name,
                    is_method=class_name is not None,
                )
            )
        elif node.kind == "ClassDef":
            cls = node.attrs.get("name")
            for child in node.children:
                visit(child, class_name=cls)
            return
        for child in node.children:
            visit(child, class_name=class_name)

    visit(program)

    # Collect global-scope statements into a pseudo-function.
    global_stmts = []
    if program.kind == "Program":
        for child in program.children:
            if child.kind in ("FunctionDef", "ClassDef", "Import", "ImportFrom"):
                continue
            global_stmts.append(child)
    if global_stmts:
        file_name = program.attrs.get("file", "<global>")
        from .base import Location
        funcs.append(
            FunctionDef(
                name=f"__global__{file_name}",
                params=[],
                body=Node(kind="StmtBlock", children=global_stmts),
                location=Location(file=file_name, start_line=1),
            )
        )

    return funcs
