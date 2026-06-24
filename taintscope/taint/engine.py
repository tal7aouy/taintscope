"""The taint analysis engine.

This is the heart of TaintScope. It performs:

* **Intraprocedural** flow-sensitive, path-insensitive taint tracking within
  each function, maintaining an environment ``{var: TaintState}``.
* **Interprocedural** propagation through the call graph using a worklist
  fixed-point: when a caller passes tainted data into a callee parameter,
  the callee is (re)analyzed with that incoming taint; when a callee returns
  tainted data, the caller's receiving variable is tainted.

The analysis is *sound over-approximate* (it may report false positives,
which the LLM layer then filters) but never *unsound* (it does not miss a
real flow that is visible in the AST). Sanitizers clear taint for a specific
vulnerability category, matching how real SAST tools model
``mysqli_real_escape_string`` (clears SQLi but not XSS).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..ast.base import FunctionDef, Location, Node
from ..ast.php_parser import PhpParser, extract_functions as php_funcs
from ..ast.py_parser import PyParser, extract_functions as py_funcs
from ..config import settings
from ..graph.call_graph import CallGraph
from .flow import DataFlowPath, TaintState
from .rules import Rules, default_php_rules, default_py_rules


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """A confirmed source-to-sink taint flow."""

    language: str
    category: str
    sink: str
    source: str
    sink_location: Optional[str]
    source_location: Optional[str]
    flow: str  # rendered data-flow path
    severity: str = "High"
    # Filled in by the LLM classifier when enabled.
    llm_verdict: Optional[str] = None
    llm_confidence: Optional[float] = None
    llm_reasoning: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "category": self.category,
            "sink": self.sink,
            "source": self.source,
            "sink_location": self.sink_location,
            "source_location": self.source_location,
            "flow": self.flow,
            "severity": self.severity,
            "llm_verdict": self.llm_verdict,
            "llm_confidence": self.llm_confidence,
            "llm_reasoning": self.llm_reasoning,
        }


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class TaintEngine:
    """Runs taint analysis over a set of files."""

    def __init__(
        self,
        php_rules: Optional[Rules] = None,
        py_rules: Optional[Rules] = None,
        max_call_depth: Optional[int] = None,
    ) -> None:
        self.php_rules = php_rules or default_php_rules()
        self.py_rules = py_rules or default_py_rules()
        self.max_call_depth = max_call_depth or settings.max_call_depth
        self.call_graph = CallGraph()
        self.findings: List[Finding] = []
        # function key -> language
        self.fn_lang: Dict[str, str] = {}
        # function key -> set of (param_index) that are tainted, with state.
        # incoming_taint[key][param_name] = TaintState
        self.incoming_taint: Dict[str, Dict[str, TaintState]] = {}
        # function key -> return taint state (union over all returns)
        self.return_taint: Dict[str, Optional[TaintState]] = {}
        self._analyzed: Set[Tuple[str, frozenset]] = set()
        self._worklist: List[str] = []

    # -- public API ------------------------------------------------------

    def analyze_paths(self, paths: Iterable[str]) -> List[Finding]:
        """Analyze a list of files (PHP and/or Python)."""
        programs: List[Tuple[str, str, Node]] = []  # (lang, file, program)
        all_funcs: List[Tuple[FunctionDef, str]] = []
        self.parse_errors: List[Tuple[str, str]] = []
        for p in paths:
            path = str(p)
            try:
                if path.endswith(".php"):
                    parser = PhpParser()
                    program = parser.parse_file(path)
                    funcs = php_funcs(program)
                    lang = "php"
                elif path.endswith(".py"):
                    parser = PyParser()
                    program = parser.parse_file(path)
                    funcs = py_funcs(program)
                    lang = "python"
                else:
                    continue
            except Exception as e:
                # Skip files that fail to parse (e.g. PHP 8 syntax on PHP 7,
                # syntax errors, vendored test files). Record for reporting.
                self.parse_errors.append((path, str(e)))
                continue
            programs.append((lang, path, program))
            for fn in funcs:
                all_funcs.append((fn, lang))
                self.fn_lang[self.call_graph._key(fn)] = lang

        # Build the call graph from all functions.
        self.call_graph.build(fn for fn, _ in all_funcs)

        # Seed: analyze every function once (to catch direct source->sink
        # flows and to compute return taint). Interprocedural propagation
        # then refines via the worklist.
        for fn, lang in all_funcs:
            key = self.call_graph._key(fn)
            self._enqueue(key)

        self._drain_worklist()
        return self.findings

    # -- worklist --------------------------------------------------------

    def _enqueue(self, key: str) -> None:
        if key not in self._worklist:
            self._worklist.append(key)

    def _drain_worklist(self) -> None:
        # Fixed-point: keep processing until no new incoming taint appears.
        rounds = 0
        while self._worklist and rounds < 50:
            key = self._worklist.pop(0)
            fn = self.call_graph.function(key)
            if fn is None:
                continue
            lang = self.fn_lang.get(key, "php")
            rules = self.php_rules if lang == "php" else self.py_rules
            incoming = self.incoming_taint.get(key, {})
            signature = (key, _freeze_incoming(incoming))
            if signature in self._analyzed and not incoming:
                # Already analyzed with no incoming taint; skip unless new.
                continue
            self._analyzed.add(signature)
            result = self._analyze_function(fn, key, lang, rules, incoming)
            # Propagate return taint to callers (handled lazily when callers
            # are analyzed). Propagate arg taint to callees.
            self._propagate_to_callees(key, result.callee_arg_taint)
            rounds += 1

    def _propagate_to_callees(self, caller_key: str, callee_taint: Dict[str, Dict[str, TaintState]]):
        """callee_taint: {callee_name: {param_name: TaintState}}."""
        for callee_name, param_taint in callee_taint.items():
            targets = self.call_graph._resolve(callee_name, Node(kind="FuncCall"))
            for tgt in targets:
                fn = self.call_graph.function(tgt)
                if fn is None:
                    continue
                changed = False
                cur = self.incoming_taint.setdefault(tgt, {})
                for pname, state in param_taint.items():
                    if pname not in fn.params:
                        continue
                    existing = cur.get(pname)
                    merged = _join_state(existing, state)
                    if merged != existing:
                        cur[pname] = merged
                        changed = True
                if changed:
                    self._enqueue(tgt)

    # -- intraprocedural -------------------------------------------------

    @dataclass
    class FnResult:
        callee_arg_taint: Dict[str, Dict[str, TaintState]] = field(default_factory=dict)
        return_state: Optional[TaintState] = None

    def _analyze_function(
        self,
        fn: FunctionDef,
        key: str,
        lang: str,
        rules: Rules,
        incoming: Dict[str, TaintState],
    ) -> "TaintEngine.FnResult":
        env: Dict[str, TaintState] = {}
        # Seed parameters with incoming interprocedural taint. PHP variable
        # names are stored with a leading "$" in the env (matching how
        # _var_name_of renders them), so prefix PHP param names accordingly.
        prefix = "$" if lang == "php" else ""
        for pname, state in incoming.items():
            env[prefix + pname] = state
        result = self.FnResult()
        ctx = _Ctx(lang=lang, rules=rules, fn=fn, fn_key=key, engine=self)

        self._analyze_block(fn.body.children, env, ctx, depth=0)

        # Collect return taint.
        self.return_taint[key] = ctx.return_state
        result.return_state = ctx.return_state
        result.callee_arg_taint = ctx.callee_arg_taint
        return result

    def _analyze_block(self, stmts: List[Node], env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> None:
        for stmt in stmts:
            self._analyze_stmt(stmt, env, ctx, depth)

    def _analyze_stmt(self, node: Node, env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> None:
        if node is None:
            return
        kind = node.kind

        if kind in ("Assign",):
            self._handle_assign(node, env, ctx, depth)
            return
        if kind == "ExpressionStatement" and node.children:
            # PHP wraps expressions in Stmt_Expression; descend.
            self._analyze_stmt(node.children[0], env, ctx, depth)
            return
        if kind in ("Echo",):
            for arg in node.children:
                state = self._eval_taint(arg, env, ctx, depth)
                sink = ctx.rules.sink_for("echo")
                if sink and state and state.is_tainted_for(sink.category):
                    self._report(arg, state, sink, ctx, origin_node=arg)
            return
        if kind == "Return":
            if node.children:
                rstate = self._eval_taint(node.children[0], env, ctx, depth)
                if rstate:
                    ctx.return_state = _join_state(ctx.return_state, rstate)
            return
        if kind in ("If",):
            # children: [cond, body, else?] for PHP; Python IR has Body/Orelse.
            for c in node.children:
                if c.kind in ("Body", "Orelse", "StmtBlock"):
                    self._analyze_block(c.children, dict(env), ctx, depth)
                else:
                    self._eval_taint(c, env, ctx, depth)  # condition
            return
        if kind in ("While", "For", "Foreach"):
            for c in node.children:
                if c.kind in ("Body", "StmtBlock"):
                    self._analyze_block(c.children, env, ctx, depth)
                else:
                    self._eval_taint(c, env, ctx, depth)
            return
        if kind in ("Function", "ClassMethod"):
            # Nested function defs are collected separately; skip here.
            return
        if kind == "Class":
            return
        if kind == "Call":
            # Python call-as-statement.
            self._eval_taint(node, env, ctx, depth)
            return
        if kind == "FuncCall":
            self._eval_taint(node, env, ctx, depth)
            return
        if kind == "Include":
            # PHP include/require with a tainted expression is an LFI sink.
            self._eval_taint(node, env, ctx, depth)
            return
        # Fallback: recurse to catch calls nested in other constructs.
        for c in node.children:
            if isinstance(c, Node):
                self._analyze_stmt(c, env, ctx, depth)

    # -- assignment & expression evaluation ------------------------------

    def _handle_assign(self, node: Node, env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> None:
        target, value = self._assign_parts(node)
        if value is None:
            return
        state = self._eval_taint(value, env, ctx, depth)
        tname = self._var_name_of(target)
        if tname is not None:
            if state is None:
                env.pop(tname, None)
            else:
                env[tname] = state
        # Also handle array element assignment: $arr[$k] = v -> taint $arr.
        if target is not None and target.kind == "ArrayDimFetch":
            base = self._var_name_of(target.children[0] if target.children else None)
            if base and state:
                env[base] = _join_state(env.get(base), state)

    def _assign_parts(self, node: Node) -> Tuple[Optional[Node], Optional[Node]]:
        # Both PHP and Python IR use kind "Assign". Python wraps the parts in
        # AssignTarget/AssignValue nodes; PHP uses positional [target, value].
        if node.kind == "Assign":
            has_wrapped = any(c.kind in ("AssignTarget", "AssignValue") for c in node.children)
            if has_wrapped:
                target = value = None
                for c in node.children:
                    if c.kind == "AssignTarget" and c.children:
                        target = c.children[0]
                    elif c.kind == "AssignValue" and c.children:
                        value = c.children[0]
                return target, value
            if len(node.children) >= 2:
                return node.children[0], node.children[1]
            return None, None
        # AugAssign (Python) uses the same wrapper convention.
        target = value = None
        for c in node.children:
            if c.kind == "AssignTarget" and c.children:
                target = c.children[0]
            elif c.kind == "AssignValue" and c.children:
                value = c.children[0]
        return target, value

    def _eval_taint(self, node: Optional[Node], env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> Optional[TaintState]:
        """Return the taint state produced by evaluating ``node``."""
        if node is None:
            return None
        kind = node.kind

        if kind in ("Variable", "Name"):
            name = self._var_name_of(node)
            if name is not None:
                return env.get(name)
            return None

        if kind == "ArrayDimFetch" or kind == "Subscript":
            return self._eval_subscript(node, env, ctx, depth)

        if kind == "PropertyFetch" or kind == "Attribute":
            return self._eval_attribute(node, env, ctx, depth)

        if kind in ("FuncCall", "MethodCall", "StaticCall", "Call"):
            return self._eval_call(node, env, ctx, depth)

        if kind == "Include":
            # PHP include/require: the single child is the included expression.
            arg = node.children[0] if node.children else None
            state = self._eval_taint(arg, env, ctx, depth)
            sink = ctx.rules.sink_for("include")
            if sink and state and state.is_tainted_for(sink.category):
                self._report(arg, state, sink, ctx, origin_node=arg)
            return None

        if kind in ("String", "Int", "Float", "Constant", "Literal"):
            return None  # constants are never tainted

        if kind in ("BinaryOp", "BoolOp", "Ternary", "UnaryOp", "Compare"):
            # Taint propagates through operators (string concat, etc.).
            states = [self._eval_taint(c, env, ctx, depth) for c in node.children]
            joined = None
            for s in states:
                if s:
                    joined = _join_state(joined, s)
            return joined

        if kind in ("List", "Array", "Tuple", "Set", "Dict"):
            joined = None
            for c in node.children:
                s = self._eval_taint(c, env, ctx, depth)
                if s:
                    joined = _join_state(joined, s)
            return joined

        if kind == "InterpolatedString":
            joined = None
            for c in node.children:
                s = self._eval_taint(c, env, ctx, depth)
                if s:
                    joined = _join_state(joined, s)
            return joined

        # Conservative fallback: join taint of all children.
        joined = None
        for c in node.children:
            s = self._eval_taint(c, env, ctx, depth)
            if s:
                joined = _join_state(joined, s)
        return joined

    def _eval_subscript(self, node: Node, env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> Optional[TaintState]:
        # PHP: ArrayDimFetch children = [base, dim]; base is Variable.
        # Python: Subscript children = [value, slice].
        if not node.children:
            return None
        base = node.children[0]
        # Source detection: PHP superglobals $_GET['x'] etc.
        if ctx.lang == "php":
            base_name = self._var_name_of(base)
            if base_name in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"):
                dim = node.children[1] if len(node.children) > 1 else None
                key = self._literal_of(dim)
                origin = f"{base_name}[{key}]" if key else f"{base_name}[?]"
                loc = str(base.location) if base.location else None
                return TaintState(var=origin, origin=origin, origin_location=loc)
        # Python: request.args['x'] is Attribute('request').args subscripted.
        if ctx.lang == "python":
            src = self._match_py_source(node, ctx)
            if src:
                return src
        # Otherwise: taint flows from the base container.
        return self._eval_taint(base, env, ctx, depth)

    def _eval_attribute(self, node: Node, env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> Optional[TaintState]:
        # Python: request.args -> Attribute(Name('request'), attr='args')
        if ctx.lang == "python":
            src = self._match_py_source(node, ctx)
            if src:
                return src
        if not node.children:
            return None
        return self._eval_taint(node.children[0], env, ctx, depth)

    def _match_py_source(self, node: Node, ctx: "_Ctx") -> Optional[TaintState]:
        rendered = _render_py_expr(node)
        for src in ctx.rules.sources:
            for pat in src.patterns:
                if rendered == pat or rendered.startswith(pat + ".") or rendered.startswith(pat + "["):
                    return TaintState(
                        var=rendered,
                        origin=rendered,
                        origin_location=str(node.location) if node.location else None,
                    )
        return None

    def _eval_call(self, node: Node, env: Dict[str, TaintState], ctx: "_Ctx", depth: int) -> Optional[TaintState]:
        callee_name, args = self._call_parts(node)
        # Evaluate argument taint states.
        arg_states = [self._eval_taint(a, env, ctx, depth) for a in args]

        # 1) Sanitizer? -> result is clean for that category (and we drop
        #    taint entirely if the sanitizer is category-agnostic).
        sanitizer = ctx.rules.sanitizer_for(callee_name)
        if sanitizer:
            # The sanitized argument becomes clean for this category.
            clean_arg = sanitizer.clean_arg
            if clean_arg < len(arg_states) and arg_states[clean_arg]:
                return arg_states[clean_arg].sanitize(sanitizer.category)
            return None

        # 2) Sink? -> check the tainted argument position.
        sink = ctx.rules.sink_for(callee_name)
        if sink:
            pos = sink.tainted_arg
            indices = [pos] if pos >= 0 else list(range(len(arg_states)))
            for i in indices:
                if i < len(arg_states) and arg_states[i] and arg_states[i].is_tainted_for(sink.category):
                    self._report(args[i], arg_states[i], sink, ctx, origin_node=args[i])
            # Sinks usually return void / non-tainted; conservative: no taint.
            return None

        # 3) Interprocedural propagation: pass tainted args to callee params.
        if callee_name and depth < self.max_call_depth:
            param_taint: Dict[str, TaintState] = {}
            targets = ctx.engine.call_graph._resolve(callee_name, node)
            for tgt in targets:
                fn = ctx.engine.call_graph.function(tgt)
                if fn is None:
                    continue
                for idx, pstate in enumerate(arg_states):
                    if pstate and idx < len(fn.params):
                        param_taint[fn.params[idx]] = pstate
                if param_taint:
                    ctx.engine._propagate_to_callees(ctx.fn_key, {callee_name: param_taint})
                # Use already-computed return taint if available.
                ret = ctx.engine.return_taint.get(tgt)
                if ret:
                    return ret
            # Record for worklist propagation even if not yet analyzed.
            if param_taint:
                ctx.callee_arg_taint[callee_name] = param_taint
            # Conservative: if any arg tainted and callee unknown, result tainted.
            if not targets:
                joined = None
                for s in arg_states:
                    if s:
                        joined = _join_state(joined, s)
                return joined

        # 4) Unknown call: propagate taint of any argument to result.
        joined = None
        for s in arg_states:
            if s:
                joined = _join_state(joined, s)
        return joined

    def _call_parts(self, node: Node) -> Tuple[Optional[str], List[Node]]:
        if node.kind in ("FuncCall", "MethodCall", "StaticCall"):
            name = node.attrs.get("name")
            # PHP IR children ordering differs by call type:
            #   FuncCall:   [Name, Arg, Arg, ...]  — skip Name/Identifier
            #   MethodCall: [receiver, Arg, Arg, ...]  — skip first child (receiver)
            #   StaticCall: [Arg, Arg, ..., Name(class)]  — keep Args, skip trailing Name
            if node.kind == "MethodCall":
                args = node.children[1:] if len(node.children) > 1 else []
                # Also filter out any non-Arg children (e.g. Name for method name)
                args = [c for c in args if c.kind == "Arg"]
            elif node.kind == "StaticCall":
                args = [c for c in node.children if c.kind == "Arg"]
            else:
                args = [c for c in node.children if c.kind not in ("Name", "Identifier")]
            # Descend into Arg nodes to get the actual argument expressions.
            args = [c.children[0] if c.kind == "Arg" and c.children else c for c in args]
            return name, args
        if node.kind == "Call":  # Python
            if not node.children:
                return None, []
            callee = node.children[0]
            args = node.children[1:]
            if callee.kind == "Name":
                return callee.attrs.get("name"), args
            if callee.kind == "Attribute":
                # e.g. os.system, cursor.execute, request.args.get
                base = _render_py_expr(callee)
                return callee.attrs.get("attr"), args
            return None, args
        return None, []

    # -- reporting -------------------------------------------------------

    def _report(self, sink_arg: Node, state: TaintState, sink, ctx: "_Ctx", origin_node: Node) -> None:
        flow = DataFlowPath()
        flow.add(f"source {state.origin}", location=state.origin_location, node_kind="Source")
        flow.add(f"taint reaches sink {sink.name}({state.var})",
                 location=str(sink_arg.location) if sink_arg.location else None,
                 node_kind=sink.name)
        finding = Finding(
            language=ctx.lang,
            category=sink.category,
            sink=sink.name,
            source=state.origin,
            sink_location=str(sink_arg.location) if sink_arg.location else None,
            source_location=state.origin_location,
            flow=flow.render(),
            severity=_severity_for(sink.category),
        )
        # Deduplicate by (language, sink, source, sink_location).
        key = (finding.language, finding.sink, finding.source, finding.sink_location)
        if key in ctx.emitted:
            return
        ctx.emitted.add(key)
        self.findings.append(finding)

    # -- helpers ---------------------------------------------------------

    def _var_name_of(self, node: Optional[Node]) -> Optional[str]:
        if node is None:
            return None
        if node.kind == "Variable":  # PHP
            name = node.attrs.get("name")
            if isinstance(name, str):
                return "$" + name
            return None
        if node.kind == "Name":  # Python
            return node.attrs.get("name")
        return None

    def _literal_of(self, node: Optional[Node]) -> Optional[str]:
        if node is None:
            return None
        if node.kind in ("String", "Literal"):
            v = node.attrs.get("value")
            return repr(v) if v is not None else "?"
        if node.kind in ("Int", "Float"):
            return str(node.attrs.get("value"))
        return "?"


# --------------------------------------------------------------------------- #
# Internal context
# --------------------------------------------------------------------------- #

@dataclass
class _Ctx:
    lang: str
    rules: Rules
    fn: FunctionDef
    fn_key: str
    engine: TaintEngine
    return_state: Optional[TaintState] = None
    callee_arg_taint: Dict[str, Dict[str, TaintState]] = field(default_factory=dict)
    emitted: Set[Tuple[str, str, str, Optional[str]]] = field(default_factory=set)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _join_state(a: Optional[TaintState], b: Optional[TaintState]) -> Optional[TaintState]:
    if a is None:
        return b
    if b is None:
        return a
    # Union of origins (keep a's var), intersection of sanitized_for (sound).
    return TaintState(
        var=a.var,
        origin=a.origin if a.origin else b.origin,
        origin_location=a.origin_location or b.origin_location,
        sanitized_for=a.sanitized_for & b.sanitized_for,
    )


def _freeze_incoming(incoming: Dict[str, TaintState]) -> frozenset:
    return frozenset((k, s.var, s.origin, s.sanitized_for) for k, s in incoming.items())


def _severity_for(category: str) -> str:
    return {
        "RCE": "Critical",
        "SQLi": "High",
        "Deserialization": "Critical",
        "LFI": "High",
        "HeaderInjection": "Medium",
        "XSS": "Medium",
    }.get(category, "High")


def _render_py_expr(node: Optional[Node]) -> str:
    """Render a Python IR expression back to a dotted name for source matching."""
    if node is None:
        return ""
    if node.kind == "Name":
        return node.attrs.get("name", "")
    if node.kind == "Attribute":
        base = _render_py_expr(node.children[0] if node.children else None)
        attr = node.attrs.get("attr", "")
        return f"{base}.{attr}" if base else attr
    if node.kind == "Subscript":
        base = _render_py_expr(node.children[0] if node.children else None)
        return f"{base}[...]" if base else ""
    return ""
