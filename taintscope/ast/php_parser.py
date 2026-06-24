"""PHP front-end: shells out to nikic/PHP-Parser via ``dump_ast.php``.

The PHP dumper emits JSON produced by ``PhpParser\\JsonDumper``. We convert
that JSON tree into the normalized :class:`Node` IR. The mapping focuses on
the constructs the taint engine cares about: assignments, variable reads,
function/method calls, array accesses (superglobals), returns, and control
flow. Unknown node types are preserved as opaque ``Node`` objects so we never
lose structural information.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from ..config import settings
from .base import FunctionDef, Location, Node


# Map of PHP-Parser nodeType -> normalized kind. Anything not listed keeps
# its original nodeType as the kind, so the engine can still branch on it.
_KIND_MAP = {
    "Stmt_Echo": "Echo",
    "Stmt_Return": "Return",
    "Stmt_If": "If",
    "Stmt_While": "While",
    "Stmt_For": "For",
    "Stmt_Foreach": "Foreach",
    "Stmt_Function": "Function",
    "Stmt_ClassMethod": "ClassMethod",
    "Stmt_Class": "Class",
    "Stmt_Expression": "ExpressionStatement",
    "Stmt_Else": "Else",
    "Stmt_ElseIf": "ElseIf",
    "Stmt_Global": "Global",
    "Expr_Assign": "Assign",
    "Expr_AssignRef": "Assign",
    "Expr_FuncCall": "FuncCall",
    "Expr_StaticCall": "StaticCall",
    "Expr_MethodCall": "MethodCall",
    "Expr_Variable": "Variable",
    "Expr_ArrayDimFetch": "ArrayDimFetch",
    "Expr_PropertyFetch": "PropertyFetch",
    "Expr_ConstFetch": "ConstFetch",
    "Expr_Closure": "Closure",
    "Expr_BinaryOp": "BinaryOp",
    "Expr_Ternary": "Ternary",
    "Expr_PreInc": "UnaryOp",
    "Expr_PostInc": "UnaryOp",
    "Expr_PreDec": "UnaryOp",
    "Expr_PostDec": "UnaryOp",
    "Expr_Not": "UnaryOp",
    "Expr_BoolNot": "UnaryOp",
    "Expr_New": "New",
    "Expr_Include": "Include",
    "Scalar_String": "String",
    "Scalar_LNumber": "Int",
    "Scalar_DNumber": "Float",
    "Scalar_EncapsedStringPart": "StringPart",
    "Scalar_Encapsed": "InterpolatedString",
    "Name": "Name",
    "Name_FullyQualified": "Name",
    "Identifier": "Identifier",
    "VarLikeIdentifier": "Identifier",
    "Param": "Param",
    "Arg": "Arg",
}


class PhpParser:
    """Parses PHP files into the normalized IR using PHP-Parser."""

    def __init__(self, php_binary: str = "", dumper: str = ""):
        self.php_binary = php_binary or settings.php_binary
        self.dumper = dumper or settings.php_dumper

    def parse_file(self, path: str) -> Node:
        raw = self._run_dumper(path)
        return self._convert(raw, file=str(path))

    def parse_source(self, source: str, file: str = "<string>") -> Node:
        """Parse a source string by writing it to a temp file."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
            f.write(source)
            tmp = f.name
        try:
            return self.parse_file(tmp)
        finally:
            Path(tmp).unlink(missing_ok=True)

    # -- internals -------------------------------------------------------

    def _run_dumper(self, path: str) -> object:
        proc = subprocess.run(
            [self.php_binary, self.dumper, path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode == 2:
            raise FileNotFoundError(proc.stderr.strip())
        if proc.returncode != 0:
            raise RuntimeError(f"PHP parse failed for {path}: {proc.stderr.strip()}")
        if not proc.stdout.strip():
            # Empty / no-statements file -> empty program.
            return []
        return json.loads(proc.stdout)

    def _convert(self, raw, file: str) -> Node:
        if raw is None:
            return Node(kind="Program", attrs={"file": file})
        if isinstance(raw, list):
            children = [self._convert(item, file) for item in raw]
            return Node(kind="Program", attrs={"file": file}, children=children)
        if not isinstance(raw, dict):
            # Scalar literal.
            return Node(kind="Literal", attrs={"value": raw})

        node_type = raw.get("nodeType", "Unknown")
        kind = _KIND_MAP.get(node_type, node_type)

        attrs: dict = {}
        children: List[Node] = []

        # Carry over simple scalar attributes that the engine inspects.
        for key in ("name", "value", "var", "byRef", "variadic", "default", "extract"):
            if key in raw and not isinstance(raw[key], (dict, list)):
                attrs[key] = raw[key]

        # Name/Identifier handling: PHP-Parser represents names as nested
        # {"nodeType": "Name", "parts": [...]} objects.
        if "name" in raw and isinstance(raw["name"], dict):
            attrs["name"] = self._name_of(raw["name"])

        # Location.
        loc = self._location(raw, file)

        # Map known child fields to children, preserving order where it
        # matters for data-flow (e.g. assignments: target then value).
        child_fields = (
            "stmts",
            "expr",
            "value",
            "var",
            "cond",
            "else",
            "elseifs",
            "args",
            "params",
            "left",
            "right",
            "if",
            "whiles",
            "init",
            "loop",
            "keyVar",
            "valueVar",
            "class",
            "dim",
            "nameExpr",
            "parts",
            "default",
            "exprs",
            "items",
        )
        for fld in child_fields:
            if fld in raw and raw[fld] is not None:
                val = raw[fld]
                if isinstance(val, list):
                    for v in val:
                        children.append(self._convert(v, file))
                elif isinstance(val, dict):
                    children.append(self._convert(val, file))

        # For assignments, tag children roles so the engine can read
        # target vs. value without positional assumptions.
        if kind == "Assign":
            tagged = []
            if "var" in raw:
                tagged.append(("target", self._convert(raw["var"], file)))
            if "expr" in raw:
                tagged.append(("value", self._convert(raw["expr"], file)))
            children = [n for _, n in tagged]
            attrs["_roles"] = [r for r, _ in tagged]

        return Node(kind=kind, attrs=attrs, children=children, location=loc)

    def _name_of(self, raw) -> Optional[str]:
        if isinstance(raw, str):
            return raw
        if isinstance(raw, dict):
            if "name" in raw:
                return self._name_of(raw["name"])
            if "parts" in raw:
                parts = raw["parts"]
                if parts and isinstance(parts[0], str):
                    return "\\".join(parts)
                if parts and isinstance(parts[0], dict):
                    return "\\".join(self._name_of(p) for p in parts)
        return None

    def _location(self, raw, file) -> Optional[Location]:
        # nikic/PHP-Parser's native jsonSerialize nests line info under an
        # "attributes" key; the older JsonDumper put it at the top level.
        # Support both.
        attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else {}
        start = raw.get("startLine", attrs.get("startLine"))
        end = raw.get("endLine", attrs.get("endLine"))
        if start is None:
            return None
        return Location(
            file=file,
            start_line=int(start),
            end_line=int(end or start),
            start_column=int(raw.get("startFilePos", attrs.get("startFilePos", 0)) or 0),
            end_column=int(raw.get("endFilePos", attrs.get("endFilePos", 0)) or 0),
        )


def extract_functions(program: Node) -> List[FunctionDef]:
    """Walk a PHP program IR and collect function/method definitions.

    Also creates a pseudo-function for the global scope so taint flows in
    top-level code (common in WordPress plugin templates and AJAX handlers)
    are analyzed.
    """
    funcs: List[FunctionDef] = []

    def visit(node: Node, class_name: Optional[str] = None):
        if node.kind in ("Function", "ClassMethod"):
            name = node.attrs.get("name") or "<anonymous>"
            params = []
            body = Node(kind="StmtBlock")
            for child in node.children:
                if child.kind == "Param":
                    # PHP-Parser stores the parameter name in a nested
                    # Expr_Variable `var` child, not a top-level `name` attr.
                    pname = None
                    for sub in child.children:
                        if sub.kind == "Variable":
                            v = sub.attrs.get("name")
                            if isinstance(v, str):
                                pname = v
                            break
                    if not pname:
                        pname = child.attrs.get("name")
                    if pname:
                        params.append(pname)
                elif child.kind == "StmtBlock" or _is_statement(child):
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
        elif node.kind == "Class":
            cls = node.attrs.get("name")
            for child in node.children:
                visit(child, class_name=cls)
            return
        for child in node.children:
            visit(child, class_name=class_name)

    visit(program)

    # Collect global-scope statements (direct children of Program that are
    # statements but NOT function/class definitions) into a pseudo-function.
    global_stmts = []
    if program.kind == "Program":
        for child in program.children:
            if child.kind in ("Function", "ClassMethod", "Class"):
                continue
            if _is_statement(child) or child.kind in ("ExpressionStatement", "Assign", "FuncCall", "StaticCall", "MethodCall", "Echo", "Include"):
                global_stmts.append(child)
    if global_stmts:
        file_name = program.attrs.get("file", "<global>")
        funcs.append(
            FunctionDef(
                name=f"__global__{file_name}",
                params=[],
                body=Node(kind="StmtBlock", children=global_stmts),
                location=Location(file=file_name, start_line=1),
            )
        )

    return funcs


def _is_statement(node: Node) -> bool:
    return node.kind.startswith("Stmt_") or node.kind in {
        "Echo",
        "Return",
        "If",
        "While",
        "For",
        "Foreach",
        "ExpressionStatement",
        "Assign",
    }
