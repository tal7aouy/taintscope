# TaintScope

A from-scratch **taint analysis engine** for **PHP** and **Python** that tracks
user-controlled input from *sources* to *sinks* without passing through a
*sanitizer*, then reports the full data-flow path. It is **not** a Semgrep
wrapper — it builds its own AST front-ends, its own call graph, and its own
flow-sensitive taint engine, the way enterprise SAST tools (Checkmarx,
Joern) do. An optional **LLM-based post-filter** classifies each finding's
exploitability to cut false positives, mirroring recent research that reduced
SAST false-positive rates from >92% to ~6.3%.

---

## How it works

```
 ┌────────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐
 │ PHP-Parser │   │  stdlib ast  │   │  Call graph│   │   Taint  │   │   LLM    │
 │ (subprocess)│  │  (Python)    │   │ (NetworkX) │   │  engine  │   │ classifier│
 │  → JSON AST │   │  → IR        │   │            │   │          │   │          │
 └─────┬──────┘   └──────┬───────┘   └─────┬──────┘   └────┬─────┘   └────┬─────┘
       │                 │                 │               │              │
       └────────┬────────┘                 │               │              │
                ▼                          │               │              │
        normalized Node IR ───────────────►│               │              │
                                                ▼           ▼              ▼
                                         findings ──► PostgreSQL ──► FastAPI
                                                      (optional)      (optional)
```

1. **AST front-ends** normalize each language into a common `Node` IR.
   - **PHP**: shells out to `nikic/PHP-Parser` via `php-ast/dump_ast.php`,
     which emits a lossless JSON AST.
   - **Python**: uses the stdlib `ast` module.
2. **Call graph** (`networkx.DiGraph`): edges from each function to its
   callees, annotated with call-site locations and argument IR nodes.
   Method calls resolve conservatively by name (sound over-approximation).
3. **Taint engine**: flow-sensitive, path-insensitive intraprocedural
   tracking per function, plus an interprocedural worklist fixed-point that
   propagates tainted arguments into callee parameters and tainted return
   values back to callers. Sanitizers clear taint *per vulnerability
   category* (e.g. `mysqli_real_escape_string` clears SQLi but not XSS).
4. **LLM classifier** (optional): each finding is sent to an LLM with its
   data-flow path; high-confidence false positives are suppressed.
5. **Storage / API**: findings persist to PostgreSQL (SQLAlchemy) and are
   exposed via FastAPI. Both are optional — the engine runs standalone.

### Sources, sinks, sanitizers (built-in)

| Category        | PHP sources                       | Python sources                    |
|-----------------|-----------------------------------|-----------------------------------|
| HTTP            | `$_GET $_POST $_REQUEST $_COOKIE $_FILES $_SERVER` | `request.args .form .values .cookies .headers .data .json .files`, `input`, `sys.argv`, `os.environ` |

| Category        | PHP sinks                         | Python sinks                      |
|-----------------|-----------------------------------|-----------------------------------|
| SQLi            | `mysqli_query`, `mysql_query`, `query` | `execute`, `raw`              |
| RCE             | `exec`, `eval`, `system`, `shell_exec`, `passthru`, `proc_open`, `popen` | `os.system`, `subprocess.*`, `eval`, `exec` |
| LFI             | `include`, `require`, `fopen`, `file_get_contents`, `readfile`, `unlink` | `open` |
| XSS             | `echo`, `print`, `printf`, `sprintf` | `render`                      |
| Deserialization | `unserialize`                     | `pickle.loads`, `yaml.load`       |
| HeaderInjection | `header`                          | —                                 |

| Sanitizers (per category) | PHP | Python |
|---------------------------|-----|--------|
| SQLi | `mysqli_real_escape_string`, `addslashes`, `intval`, `is_numeric`, `esc_sql` | `int`, `float`, `quote` |
| XSS  | `htmlspecialchars`, `htmlentities`, `strip_tags`, `wp_kses`, `sanitize_text_field` | `escape`, `bleach.clean` |
| RCE  | `escapeshellarg`, `escapeshellcmd` | `shlex.quote` |
| LFI  | `basename`, `realpath` | — |

Rules are plain data structures in `taintscope/taint/rules.py` — extend them
to cover more APIs (e.g. a specific framework's request object).

---

## Quickstart

### Prerequisites
- Python 3.9+
- PHP 7.4+ with [Composer](https://getcomposer.org/) (only for PHP scanning)

### Install

```bash
# Python package + dev deps
pip install -e ".[dev]"

# PHP AST front-end (nikic/PHP-Parser)
cd php-ast && composer install && cd ..
```

### Scan a codebase

```bash
# Scan specific files
taintscope scan ./tests/fixtures/php/sqli_basic.php ./tests/fixtures/python/vuln.py

# Scan a whole directory (auto-discovers .php and .py)
taintscope scan ./wp-plugin/

# Only PHP, write JSON output
taintscope scan --lang php --json findings.json ./target/

# Enable LLM false-positive filtering (requires OPENAI_API_KEY + TAINTSCOPE_LLM_ENABLED=1)
export OPENAI_API_KEY=sk-...
export TAINTSCOPE_LLM_ENABLED=1
taintscope scan --llm ./target/

# Persist findings to PostgreSQL
export TAINTSCOPE_DB_ENABLED=1
export TAINTSCOPE_DATABASE_URL="postgresql+psycopg2://user:pass@localhost:5432/taintscope"
taintscope scan --db ./target/
```

### Run the findings API

```bash
taintscope serve --port 8000
# GET  /            health + version
# GET  /findings    list recent findings (?category=SQLi&limit=100)
# POST /scan        {"paths": ["./target.php"], "enable_llm": false}
```

### Inspect the normalized AST (debugging)

```bash
taintscope dump-ast ./tests/fixtures/php/sqli_basic.php
```

---

## Example output

```
TaintScope v0.1.0 — scanning 2 file(s)
┌───┬────────┬──────────┬──────────┬─────────────┬────────────┐
│ # │ Lang   │ Category │ Severity │ Source      │ Sink       │
├───┼────────┼──────────┼──────────┼─────────────┼────────────┤
│ 1 │ php    │ SQLi     │ High     │ $_GET['id'] │ mysqli_query │
│ 2 │ php    │ RCE      │ Critical │ $_POST['cmd']│ exec       │
│ 3 │ python │ LFI      │ High     │ request.args│ open       │
└───┴────────┴──────────┴──────────┴─────────────┴────────────┘

Data flows:
  #1 [High] SQLi $_GET['id'] -> mysqli_query
     source $_GET['id'] at sqli_basic.php:4 -> taint reaches sink mysqli_query($_GET['id']) at sqli_basic.php:6
  #2 [Critical] RCE $_POST['cmd'] -> exec
     source $_POST['cmd'] at rce_interprocedural.php:8 -> taint reaches sink exec($_POST['cmd']) at rce_interprocedural.php:4
```

Finding #2 is **interprocedural**: `$_POST['cmd']` is read in
`handle_request()`, passed to `run_cmd()`, and reaches `exec()` in a
different function — TaintScope follows the flow across the call boundary.

---

## Project layout

```
taintscope/
├── pyproject.toml              # package + deps (networkx, fastapi, sqlalchemy, openai, ...)
├── php-ast/                    # PHP front-end helper
│   ├── composer.json           # requires nikic/php-parser
│   └── dump_ast.php            # parses PHP → JSON AST
├── taintscope/
│   ├── ast/                    # normalized IR + language front-ends
│   │   ├── base.py             # Node, FunctionDef, Location
│   │   ├── php_parser.py       # PHP-Parser subprocess → IR
│   │   └── py_parser.py        # stdlib ast → IR
│   ├── graph/call_graph.py     # NetworkX call graph
│   ├── taint/
│   │   ├── rules.py            # sources / sinks / sanitizers (PHP & Python)
│   │   ├── flow.py             # TaintState, DataFlowPath
│   │   └── engine.py           # the taint analysis engine + Finding
│   ├── storage/db.py           # PostgreSQL persistence (optional)
│   ├── api/main.py             # FastAPI findings service
│   ├── llm/classifier.py       # OpenAI exploitability classifier
│   ├── cli.py                  # `taintscope` CLI
│   └── config.py               # env-driven settings
├── tests/
│   ├── fixtures/{php,python}/  # vulnerable sample code
│   └── test_engine.py          # end-to-end detection tests
└── README.md
```

---

## Testing

```bash
pytest -q
```

The suite verifies direct source→sink detection (SQLi, RCE, LFI, XSS),
interprocedural propagation through helpers, and sanitizer suppression —
for both PHP and Python. PHP tests auto-skip if `nikic/PHP-Parser` isn't
installed.

---

## Design notes & limitations

- **Soundness vs. precision**: the engine is a sound over-approximation
  (it may produce false positives, which the LLM layer filters) but does
  not miss flows visible in the AST. Method-call resolution is by-name
  (no type inference), which is standard for lightweight SAST.
- **Interprocedural depth** is bounded by `TAINTSCOPE_MAX_CALL_DEPTH`
  (default 5) to guarantee termination; raise it for deeper codebases.
- **PHP `exec`** is modeled as RCE (the shell function); PDO's
  `->exec()` method call is a separate resolution path.
- **LLM filtering is conservative**: only `likely-false-positive` verdicts
  above a confidence threshold (default 0.7) are suppressed, so the
  symbolic engine's soundness guarantee is preserved.
- Adding a language = write a new `ast/<lang>_parser.py` that emits the
  `Node` IR and a `Rules` bundle. The engine and call graph are
  language-agnostic.

## License

MIT
