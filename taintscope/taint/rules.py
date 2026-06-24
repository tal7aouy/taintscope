"""Taint rules: sources, sinks, and sanitizers per language.

Rules are intentionally explicit and enumerable — this is the knowledge base
a SAST tool maintains. Each rule carries a category so findings can be
classified (SQLi, RCE, XSS, PathTraversal, etc.) and so the LLM
post-filter can reason about exploitability per category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set


@dataclass
class Source:
    """A taint source: where user-controlled data enters the program."""

    name: str
    category: str
    # PHP superglobals are array accesses; Python sources are attribute/
    # subscript reads. ``match`` is a callable(node) -> bool used by the engine.
    match: Optional[Callable] = None
    # For simple name-based matching.
    patterns: List[str] = field(default_factory=list)


@dataclass
class Sink:
    """A dangerous sink: tainted data reaching here is a vulnerability."""

    name: str
    category: str
    # Which argument index/position is dangerous. -1 means "any argument".
    tainted_arg: int = 0
    patterns: List[str] = field(default_factory=list)
    match: Optional[Callable] = None


@dataclass
class Sanitizer:
    """A sanitizer: data passing through here is considered clean."""

    name: str
    category: str
    # Which argument is sanitized (returned clean). Default 0.
    clean_arg: int = 0
    patterns: List[str] = field(default_factory=list)
    match: Optional[Callable] = None


@dataclass
class Rules:
    """A bundle of rules for one language."""

    language: str
    sources: List[Source] = field(default_factory=list)
    sinks: List[Sink] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)

    def sink_for(self, name: Optional[str]) -> Optional[Sink]:
        if not name:
            return None
        for s in self.sinks:
            if name == s.name or name in s.patterns:
                return s
        # case-insensitive fallback for PHP function-name matching
        low = name.lower()
        for s in self.sinks:
            if low == s.name.lower() or low in [p.lower() for p in s.patterns]:
                return s
        return None

    def sanitizer_for(self, name: Optional[str]) -> Optional[Sanitizer]:
        if not name:
            return None
        for s in self.sanitizers:
            if name == s.name or name in s.patterns:
                return s
        low = name.lower()
        for s in self.sanitizers:
            if low == s.name.lower() or low in [p.lower() for p in s.patterns]:
                return s
        return None


# --------------------------------------------------------------------------- #
# PHP rules
# --------------------------------------------------------------------------- #

def default_php_rules() -> Rules:
    sources = [
        Source(
            name="$_GET",
            category="http",
            patterns=["$_GET"],
            match=lambda n: n.kind == "ArrayDimFetch" and _php_var_name(n.children[0] if n.children else None) == "$_GET",
        ),
        Source("$_POST", "http", patterns=["$_POST"],
               match=lambda n: n.kind == "ArrayDimFetch" and _php_var_name(n.children[0] if n.children else None) == "$_POST"),
        Source("$_REQUEST", "http", patterns=["$_REQUEST"],
               match=lambda n: n.kind == "ArrayDimFetch" and _php_var_name(n.children[0] if n.children else None) == "$_REQUEST"),
        Source("$_COOKIE", "http", patterns=["$_COOKIE"],
               match=lambda n: n.kind == "ArrayDimFetch" and _php_var_name(n.children[0] if n.children else None) == "$_COOKIE"),
        Source("$_FILES", "http", patterns=["$_FILES"],
               match=lambda n: n.kind == "ArrayDimFetch" and _php_var_name(n.children[0] if n.children else None) == "$_FILES"),
        Source("$_SERVER", "http", patterns=["$_SERVER"],
               match=lambda n: n.kind == "ArrayDimFetch" and _php_var_name(n.children[0] if n.children else None) == "$_SERVER"),
    ]

    sinks = [
        Sink("mysqli_query", "SQLi", tainted_arg=1, patterns=["mysqli_query", "\\mysqli_query"]),
        Sink("mysql_query", "SQLi", tainted_arg=0, patterns=["mysql_query"]),
        Sink("query", "SQLi", tainted_arg=0, patterns=["query"]),  # PDO / WP $wpdb->query
        Sink("exec", "RCE", tainted_arg=0, patterns=["exec", "\\exec"]),  # PHP shell exec(); PDO::exec is a method call resolved separately
        Sink("eval", "RCE", tainted_arg=0, patterns=["eval"]),
        Sink("system", "RCE", tainted_arg=0, patterns=["system", "\\system"]),
        Sink("shell_exec", "RCE", tainted_arg=0, patterns=["shell_exec"]),
        Sink("passthru", "RCE", tainted_arg=0, patterns=["passthru"]),
        Sink("proc_open", "RCE", tainted_arg=0, patterns=["proc_open"]),
        Sink("popen", "RCE", tainted_arg=0, patterns=["popen"]),
        Sink("include", "LFI", tainted_arg=0, patterns=["include", "require", "include_once", "require_once"]),
        Sink("file_get_contents", "LFI", tainted_arg=0, patterns=["file_get_contents"]),
        Sink("file_put_contents", "LFI", tainted_arg=1, patterns=["file_put_contents"]),
        Sink("fopen", "LFI", tainted_arg=0, patterns=["fopen"]),
        Sink("readfile", "LFI", tainted_arg=0, patterns=["readfile"]),
        Sink("unlink", "LFI", tainted_arg=0, patterns=["unlink"]),
        Sink("header", "HeaderInjection", tainted_arg=0, patterns=["header"]),
        Sink("echo", "XSS", tainted_arg=0, patterns=["echo", "print"]),
        Sink("printf", "XSS", tainted_arg=0, patterns=["printf", "sprintf"]),
        Sink("unserialize", "Deserialization", tainted_arg=0, patterns=["unserialize"]),
    ]

    sanitizers = [
        Sanitizer("mysqli_real_escape_string", "SQLi", patterns=["mysqli_real_escape_string"]),
        Sanitizer("mysql_real_escape_string", "SQLi", patterns=["mysql_real_escape_string"]),
        Sanitizer("addslashes", "SQLi", patterns=["addslashes"]),
        Sanitizer("intval", "SQLi", patterns=["intval"]),
        Sanitizer("floatval", "SQLi", patterns=["floatval"]),
        Sanitizer("htmlspecialchars", "XSS", patterns=["htmlspecialchars"]),
        Sanitizer("htmlentities", "XSS", patterns=["htmlentities"]),
        Sanitizer("strip_tags", "XSS", patterns=["strip_tags"]),
        Sanitizer("escapeshellarg", "RCE", patterns=["escapeshellarg", "escapeshellcmd"]),
        Sanitizer("basename", "LFI", patterns=["basename"]),
        Sanitizer("realpath", "LFI", patterns=["realpath"]),
        Sanitizer("is_numeric", "SQLi", patterns=["is_numeric"]),
        Sanitizer("preg_replace", "XSS", patterns=["preg_replace"]),
        # WordPress helpers
        Sanitizer("sanitize_text_field", "XSS", patterns=["sanitize_text_field"]),
        Sanitizer("esc_sql", "SQLi", patterns=["esc_sql"]),
        Sanitizer("prepare", "SQLi", patterns=["prepare"]),  # $wpdb->prepare() — canonical WP SQL sanitizer
        Sanitizer("wp_kses", "XSS", patterns=["wp_kses"]),
        Sanitizer("absint", "SQLi", patterns=["absint"]),
        Sanitizer("wp_unslash", "XSS", patterns=["wp_unslash"]),
        Sanitizer("sanitize_key", "SQLi", patterns=["sanitize_key"]),
        Sanitizer("sanitize_title", "XSS", patterns=["sanitize_title"]),
        Sanitizer("sanitize_file_name", "LFI", patterns=["sanitize_file_name"]),
        Sanitizer("wp_kses_post", "XSS", patterns=["wp_kses_post"]),
        Sanitizer("esc_url", "XSS", patterns=["esc_url"]),
        Sanitizer("esc_attr", "XSS", patterns=["esc_attr"]),
        Sanitizer("esc_html", "XSS", patterns=["esc_html"]),
        Sanitizer("esc_textarea", "XSS", patterns=["esc_textarea"]),
        Sanitizer("sanitize_email", "XSS", patterns=["sanitize_email"]),
        Sanitizer("sanitize_meta", "XSS", patterns=["sanitize_meta"]),
        Sanitizer("sanitize_option", "XSS", patterns=["sanitize_option"]),
        Sanitizer("wp_strip_all_tags", "XSS", patterns=["wp_strip_all_tags"]),
    ]

    return Rules(language="php", sources=sources, sinks=sinks, sanitizers=sanitizers)


def _php_var_name(node) -> Optional[str]:
    if node is None:
        return None
    if node.kind == "Variable":
        v = node.attrs.get("name")
        if isinstance(v, str):
            return "$" + v
        # name may itself be a node (variable variable) — ignore.
        return None
    return None


# --------------------------------------------------------------------------- #
# Python rules
# --------------------------------------------------------------------------- #

def default_py_rules() -> Rules:
    sources = [
        # Flask / Django / Bottle / FastAPI request objects.
        Source("request.args", "http", patterns=["request.args", "request.form", "request.values", "request.cookies", "request.headers", "request.data", "request.json", "request.files"]),
        Source("flask.request", "http", patterns=["request"]),
        Source("input", "http", patterns=["input"]),
        Source("sys.argv", "http", patterns=["sys.argv", "argv"]),
        Source("os.environ", "http", patterns=["os.environ", "environ"]),
        Source("GET", "http", patterns=["GET", "POST", "QueryDict"]),  # Django HttpRequest
    ]

    sinks = [
        Sink("execute", "SQLi", tainted_arg=0, patterns=["execute", "executemany"]),
        Sink("cursor.execute", "SQLi", tainted_arg=0, patterns=["execute"]),
        Sink("raw", "SQLi", tainted_arg=0, patterns=["raw"]),  # Django raw queries
        Sink("os.system", "RCE", tainted_arg=0, patterns=["system"]),
        Sink("subprocess.run", "RCE", tainted_arg=0, patterns=["run", "call", "Popen", "check_call", "check_output"]),
        Sink("os.popen", "RCE", tainted_arg=0, patterns=["popen"]),
        Sink("eval", "RCE", tainted_arg=0, patterns=["eval"]),
        Sink("exec", "RCE", tainted_arg=0, patterns=["exec"]),
        Sink("open", "LFI", tainted_arg=0, patterns=["open", "io.open"]),
        Sink("pickle.loads", "Deserialization", tainted_arg=0, patterns=["loads", "load"]),
        Sink("yaml.load", "Deserialization", tainted_arg=0, patterns=["load"]),
        Sink("render", "XSS", tainted_arg=0, patterns=["render"]),
    ]

    sanitizers = [
        Sanitizer("escape", "XSS", patterns=["escape", "html.escape", "markupsafe.escape"]),
        Sanitizer("quote", "SQLi", patterns=["quote", "psycopg2.sql"]),
        Sanitizer("int", "SQLi", patterns=["int", "float"]),
        Sanitizer("str.isdigit", "SQLi", patterns=["isdigit"]),
        Sanitizer("bleach.clean", "XSS", patterns=["clean"]),
        Sanitizer("shlex.quote", "RCE", patterns=["quote"]),
        Sanitizer("safe", "XSS", patterns=["safe"]),  # Jinja |safe is the opposite; handled in engine
    ]

    return Rules(language="python", sources=sources, sinks=sinks, sanitizers=sanitizers)
