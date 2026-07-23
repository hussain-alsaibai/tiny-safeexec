# tiny-sandbox

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#)
[![tiny-*](https://img.shields.io/badge/tiny%E2%98%85-ecosystem-purple.svg)](https://github.com/hussain-alsaibai)

> **Tiny secure Python code execution sandbox using AST transformation. Zero dependencies.**

Execute untrusted Python code safely with zero external packages — just the Python standard library.

---

## Why tiny-sandbox?

| Feature | tiny-sandbox | RestrictedInterpreter | docker/process |
|---|---|---|---|
| Dependencies | **Zero** (stdlib only) | None | Heavy (~500MB image) |
| Latency | **~1ms** | ~1ms | ~500ms+ |
| AST-level enforcement | ✅ | ✅ | ❌ |
| Pure Python | ✅ | ✅ | ❌ |
| Import whitelisting | ✅ | ❌ | ✅ |
| Timeout enforcement | ✅ | ✅ | ✅ |
| Memory guard | ✅ | Limited | ✅ |
| No subprocess/mmap | ✅ | ✅ | ❌ |
| Ships as single file | ✅ | ❌ | ❌ |

## Features

- **AST-based security** — Parses and whitelists AST nodes; rejects dangerous patterns before execution
- **Safe builtins only** — Only 31 trusted builtins: `range`, `len`, `str`, `int`, `float`, `bool`, `list`, `dict`, `set`, `tuple`, `print`, `enumerate`, `zip`, `map`, `filter`, `sum`, `min`, `max`, `abs`, `round`, `sorted`, `reversed`, `any`, `all`, `isinstance`, `type`, `hash`
- **Timeout enforcement** — Signal-based (Unix) or threading-based (Windows) timeout
- **SandboxedImport context manager** — Whitelist specific stdlib modules (`math`, `json`, `random`)
- **Output capture** — Redirects and caps stdout/stderr
- **Memory guard** — Truncates large output strings and values
- **SandboxStats** — Tracks execution time, estimated memory, nodes visited, blocked ops
- **Zero dependencies** — Ships as a single `tiny_sandbox.py` file

## Quick Start

```python
from tiny_sandbox import Sandbox, execute

# Basic usage
sandbox = Sandbox()
result = sandbox.execute("print('hello'); 2 + 2")
print(result.stdout)   # hello
print(result.value)    # 4
print(result.ok)       # True

# Module-level convenience
result = execute("sum(range(100))")
print(result.value)    # 4950

# With custom timeout
result = Sandbox(timeout_seconds=1.0).execute("while True: pass")

# With whitelisted imports
from tiny_sandbox import Sandbox, SandboxedImport
sandbox = Sandbox()
with SandboxedImport(__import__("math"), __import__("json")):
    r = sandbox.execute("import math; import json; json.dumps(math.sqrt(2))")
print(r.value)  # 1.4142135623730951
```

## API Reference

### `Sandbox(timeout_seconds=5.0, max_output_chars=100000, max_value_display=10000)`

Main sandbox class.

#### `sandbox.execute(code: str) -> SandboxResult`
Execute sandboxed code string. Returns a `SandboxResult`.

#### `sandbox.exec(code: str, globals=None, locals=None) -> SandboxResult`
Drop-in replacement for Python's built-in `exec()`. Same semantics, sandboxed.

#### `sandbox.stats -> SandboxStats`
Access execution stats from the last run.

### `SandboxResult`

| Field | Type | Description |
|---|---|---|
| `.value` | Any | Return value of the last expression |
| `.stdout` | str | Captured stdout |
| `.stderr` | str | Captured stderr |
| `.stats` | SandboxStats | Execution statistics |
| `.error` | Exception | Error if execution failed |
| `.ok` | bool | `True` if no error |

### `SandboxStats`

| Field | Type | Description |
|---|---|---|
| `.execution_time_ms` | float | Wall-clock time in ms |
| `.memory_bytes` | int | Estimated memory usage |
| `.nodes_visited` | int | AST nodes traversed |
| `.blocked_operations` | list[str] | Rejected operations |

### `SandboxedImport(*modules)`

Context manager that temporarily whitelists specific stdlib modules for import:

```python
with SandboxedImport(__import__("math"), __import__("json")):
    sandbox.execute("import math; import json")
```

### `TimeoutException` / `SandboxError`

Custom exceptions raised on timeout or policy violation.

## Security Model

### What's blocked

- **Builtins**: `open`, `eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `locals`, `vars`, `dir`, `breakpoint`, `input`, `exit`, `quit`, `memoryview`, `buffer`, `mmap`, `ctypes`, `subprocess`, `os`, `sys`
- **Language features**: `class`, `import`/`import from` (except whitelisted), `lambda`, `f-string`, `yield`, `yield from`, `async`, comprehensions (list/dict/set), `global`/`nonlocal`, starred expressions, bare `except`
- **Dunder access**: `obj.__class__`, `obj.__dict__`, `obj.__getattribute__`, etc. (except safe ones like `__name__`)
- **Private attributes**: `obj._private`
- **Import of non-whitelisted modules** (even with `SandboxedImport`)

### What's allowed (use with caution)

- Arithmetic, string, list, dict, set, tuple operations
- All whitelisted builtins (see Features)
- User-defined functions (no `global`/`nonlocal`)
- Standard loops (`for`/`while`)
- `try`/`except` with explicit exception types
- Read-only access to `sys.maxsize`, `sys.version_info` via whitelisted `sys` sentinel

### Limitations

> **IMPORTANT**: This sandbox uses Python's `exec()` internally. It is NOT a security-hardened prison. It is designed to prevent _accidental_ misuse and provide a comfortable execution environment — not to safely execute adversarial code. See [SECURITY.md](SECURITY.md) for full details.

## License

MIT License — see [LICENSE](LICENSE).
