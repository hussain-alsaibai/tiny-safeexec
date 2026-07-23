"""
tiny_sandbox - A secure Python code execution sandbox using AST transformation.

MIT License
"""

import ast
import sys
import time
import signal
import io
import contextlib
import builtins
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field


__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class SandboxError(Exception):
    """Raised when the sandbox detects a policy violation."""
    pass


class TimeoutException(SandboxError):
    """Raised when sandboxed code exceeds the timeout limit."""
    pass


# ---------------------------------------------------------------------------
# Safe Builtins whitelist
# ---------------------------------------------------------------------------

SAFE_BUILTINS = {
    "range", "len", "str", "int", "float", "bool", "list", "dict", "set",
    "tuple", "print", "enumerate", "zip", "map", "filter", "sum", "min",
    "max", "abs", "round", "sorted", "reversed", "any", "all", "isinstance",
    "type", "hash", "Exception", "__import__",
}

BLOCKED_BUILTINS = {
    "open", "eval", "exec", "compile", "__import__", "getattr", "setattr",
    "delattr", "globals", "locals", "vars", "dir", "breakpoint", "input",
    "exit", "quit", "memoryview", "buffer", "mmap", "ctypes", "subprocess",
}

ALLOWED_MODULES = {"math", "json", "random", "collections", "collections.abc"}

MAX_ITERATIONS = 100000
MAX_OUTPUT_SIZE = 100000
MAX_VALUE_DISPLAY = 10000


# ---------------------------------------------------------------------------
# SandboxStats
# ---------------------------------------------------------------------------

@dataclass
class SandboxStats:
    """Tracks execution statistics for a sandboxed run."""
    execution_time_ms: float = 0.0
    memory_bytes: int = 0
    nodes_visited: int = 0
    blocked_operations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_time_ms": round(self.execution_time_ms, 3),
            "memory_bytes": self.memory_bytes,
            "nodes_visited": self.nodes_visited,
            "blocked_operations": self.blocked_operations,
        }


# ---------------------------------------------------------------------------
# Sandbox Result
# ---------------------------------------------------------------------------

@dataclass
class SandboxResult:
    """Return value from Sandbox.execute() / Sandbox.exec()."""
    value: Any
    stdout: str
    stderr: str
    stats: SandboxStats
    error: Optional[BaseException] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:
        return (
            f"SandboxResult(ok={self.ok}, value={self.value!r}, "
            f"stdout={self.stdout!r}, stats={self.stats.to_dict()})"
        )


# ---------------------------------------------------------------------------
# AST Validator / Loop-Counter Transformer
# ---------------------------------------------------------------------------

class SafeASTTransformer(ast.NodeVisitor):
    """
    Validates and instruments an AST:
    - Whitelists allowed node types
    - Counts nodes for stats
    - Rejects dangerous patterns (dunder access, forbidden builtins, etc.)
    """

    def __init__(self, allow_imports: bool = False):
        self.nodes_visited = 0
        self.blocked: List[str] = []
        self.allow_imports = allow_imports

    def _block(self, reason: str):
        self.blocked.append(reason)

    def _is_dunder(self, name: str) -> bool:
        return name.startswith("__") and name.endswith("__")

    def check(self, tree: ast.AST) -> bool:
        """Return True if the tree is safe. Fills self.blocked on failure."""
        for node in ast.walk(tree):
            self.nodes_visited += 1
            self.visit(node)
        return not self.blocked

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.nodes_visited += 1
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                self._block(f"FunctionDef contains 'global' declaration: {[n for n in child.names]}")
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._block("ClassDef is not allowed")

    def visit_Import(self, node: ast.Import) -> None:
        if not self.allow_imports:
            self._block("ast.Import is not allowed")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not self.allow_imports:
            self._block("ImportFrom is not allowed")
        elif node.module not in ALLOWED_MODULES and node.module != "typing":
            self._block(f"ImportFrom of non-whitelisted module: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.nodes_visited += 1
        if isinstance(node.func, ast.Name):
            if node.func.id in ("__import__", "eval", "exec", "compile", "open"):
                self._block(f"Blocked call: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in BLOCKED_BUILTINS:
                self._block(f"Blocked attribute call: {node.func.attr}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.nodes_visited += 1
        if self._is_dunder(node.attr):
            safe_dunders = {
                "__name__", "__doc__", "__package__", "__loader__",
                "__spec__", "__builtins__",
            }
            if node.attr not in safe_dunders:
                self._block(f"Dunder attribute access: __{node.attr}__")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.nodes_visited += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.nodes_visited += 1
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.nodes_visited += 1
        for handler in node.handlers:
            if handler.type is None:
                self._block("Bare 'except:' is not allowed")
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.nodes_visited += 1
        if isinstance(node.exc, ast.Name):
            if node.exc.id not in ("SandboxError", "TimeoutException", "Exception", "BaseException"):
                self._block(f"Raising unknown exception: {node.exc.id}")
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self._block(f"'global' statement: {node.names}")

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self._block(f"'nonlocal' statement: {node.names}")

    def visit_Yield(self, node: ast.Yield) -> None:
        self._block("'yield' is not allowed")
        self.generic_visit(node)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self._block("'yield from' is not allowed")
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        self._block("'await' is not allowed")
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        self.nodes_visited += 1
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._block("'lambda' is not allowed")
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        self._block("f-strings are not allowed")
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._block("set comprehensions are not allowed")
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._block("list comprehensions are not allowed")
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._block("dict comprehensions are not allowed")
        self.generic_visit(node)

    def visit_Starred(self, node: ast.Starred) -> None:
        self._block("starred expressions are not allowed")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.nodes_visited += 1
        if node.id in BLOCKED_BUILTINS:
            self._block(f"Blocked Name: {node.id}")
        self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        self.nodes_visited += 1
        super().generic_visit(node)


def _check_syntax(code: str) -> ast.AST:
    try:
        return ast.parse(code)
    except SyntaxError as e:
        raise SandboxError(f"Syntax error: {e}")


def _validate_and_transform(code: str, allow_imports: bool = False) -> ast.AST:
    tree = _check_syntax(code)
    transformer = SafeASTTransformer(allow_imports=allow_imports)
    safe = transformer.check(tree)
    if not safe:
        raise SandboxError(f"Code blocked by sandbox policy: {transformer.blocked[0]}")
    return tree


# ---------------------------------------------------------------------------
# SandboxedImport context manager
# ---------------------------------------------------------------------------

class SandboxedImport(contextlib.ContextDecorator):
    """
    Context manager / decorator that temporarily allows importing specific
    stdlib modules inside the sandbox.

    Usage::

        with SandboxedImport(math, json, random):
            sandbox.execute("import math; print(math.sqrt(2))")

    """

    def __init__(self, *modules, sandbox=None):
        self.modules = modules
        self._original_import = None
        self._saved_modules: Dict[str, Any] = {}
        self._allowed_names: set = set()
        self._sandbox = sandbox

    def __enter__(self):
        import sys
        self._allowed_names = {m.__name__ for m in self.modules}
        # Hide all modules not in the allowed set
        self._saved_modules = {}
        for mod_name in list(sys.modules.keys()):
            root = mod_name.split(".")[0]
            if root not in (ALLOWED_MODULES | self._allowed_names):
                self._saved_modules[mod_name] = sys.modules.pop(mod_name, None)
        self._original_import = builtins.__import__
        def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
            root = name.split(".")[0]
            if root in (ALLOWED_MODULES | self._allowed_names):
                return self._original_import(name, globals, locals, fromlist, level)
            raise SandboxError(f"Import of '{name}' is not allowed in sandboxed context.")
        builtins.__import__ = _safe_import
        if self._sandbox is not None:
            self._sandbox._allow_imports = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        builtins.__import__ = self._original_import
        import sys
        for k, v in self._saved_modules.items():
            if v is not None:
                sys.modules[k] = v
        if self._sandbox is not None:
            self._sandbox._allow_imports = False
        return False


# ---------------------------------------------------------------------------
# Output capture
# ---------------------------------------------------------------------------

class _OutputCapture:
    def __init__(self, max_chars: int = MAX_OUTPUT_SIZE):
        self.max_chars = max_chars
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def __enter__(self):
        self._old_stdout = sys.stdout
        self._old_stderr = sys.stderr
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._old_stdout
        sys.stderr = self._old_stderr
        self.stdout.truncate(self.max_chars)
        self.stderr.truncate(self.max_chars)
        return False

    @property
    def stdout_value(self) -> str:
        return self.stdout.getvalue()

    @property
    def stderr_value(self) -> str:
        return self.stderr.getvalue()


# ---------------------------------------------------------------------------
# Timeout guard
# ---------------------------------------------------------------------------

class _TimeoutGuard:
    """Cross-platform timeout using signal (Unix) or threading (Windows/fallback)."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._is_unix = sys.platform != "win32"
        self._timer = None

    def __enter__(self):
        if self.seconds <= 0:
            return self
        if self._is_unix:
            signal.signal(signal.SIGALRM, self._handler)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
        else:
            import threading
            self._timer = threading.Timer(self.seconds, self._handler)
            self._timer.daemon = True
            self._timer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.seconds <= 0:
            return False
        if self._is_unix:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        else:
            if self._timer is not None:
                self._timer.cancel()
        return False

    def _handler(self, signum=None, frame=None):
        raise TimeoutException(f"Execution exceeded {self.seconds}s")


# ---------------------------------------------------------------------------
# Memory guard
# ---------------------------------------------------------------------------

class _MemoryGuard:
    def __init__(self, max_value_size: int = MAX_VALUE_DISPLAY):
        self.max_value_size = max_value_size
        self.estimated_bytes = 0

    def _estimate_size(self, obj: Any) -> int:
        try:
            if isinstance(obj, (int, float, bool, type(None))):
                return sys.getsizeof(obj)
            elif isinstance(obj, str):
                return sys.getsizeof(obj)
            elif isinstance(obj, (list, tuple, set, frozenset)):
                return sys.getsizeof(obj) + sum(self._estimate_size(i) for i in obj)
            elif isinstance(obj, dict):
                return sys.getsizeof(obj) + sum(
                    self._estimate_size(k) + self._estimate_size(v)
                    for k, v in obj.items()
                )
            else:
                return sys.getsizeof(obj)
        except Exception:
            return 0

    def update_estimate(self, result: Any):
        self.estimated_bytes += self._estimate_size(result)

    def format_result(self, result: Any) -> Any:
        if isinstance(result, str) and len(result) > self.max_value_size:
            return result[: self.max_value_size] + f"... [truncated {len(result) - self.max_value_size} chars]"
        if isinstance(result, list) and len(result) > self.max_value_size:
            return result[: self.max_value_size] + [f"... [{len(result) - self.max_value_size} more items]"]
        return result


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class Sandbox:
    """
    A secure Python code execution sandbox using AST transformation.

    Parameters
    ----------
    timeout_seconds : float
        Maximum execution time (default 5.0).
    max_output_chars : int
        Maximum characters of stdout/stderr to capture (default 100000).
    max_value_display : int
        Maximum length of displayed result values (default 10000).

    Example
    -------
    >>> sandbox = Sandbox()
    >>> result = sandbox.execute("print('Hello from sandbox!'); 2 + 2")
    >>> print(result.stdout)
    Hello from sandbox!
    >>> print(result.value)
    4
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_output_chars: int = MAX_OUTPUT_SIZE,
        max_value_display: int = MAX_VALUE_DISPLAY,
        max_iterations: int = MAX_ITERATIONS,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self.max_value_display = max_value_display
        self.max_iterations = max_iterations
        self._stats: Optional[SandboxStats] = None
        self._allow_imports: bool = False

    def execute(self, code: str) -> SandboxResult:
        """
        Execute sandboxed code and return a SandboxResult.

        Parameters
        ----------
        code : str
            Python code to execute in the sandbox.

        Returns
        -------
        SandboxResult
            Contains value, stdout, stderr, stats, and error.
        """
        return self._run(code, self.timeout_seconds)

    def exec(
        self,
        code: str,
        globals: Optional[Dict[str, Any]] = None,
        locals: Optional[Dict[str, Any]] = None,
    ) -> SandboxResult:
        """
        Safe replacement for the built-in exec().

        Parameters
        ----------
        code : str
            Python code string to execute.
        globals : dict, optional
            Global variables dictionary.
        locals : dict, optional
            Local variables dictionary.

        Returns
        -------
        SandboxResult
        """
        return self._run(code, self.timeout_seconds, globals, locals)

    @property
    def stats(self) -> Optional[SandboxStats]:
        """Last execution stats, or None if no execution yet."""
        return self._stats

    def _run(
        self,
        code: str,
        timeout: float,
        g: Optional[Dict[str, Any]] = None,
        l: Optional[Dict[str, Any]] = None,
    ) -> SandboxResult:
        # 1. Build execution globals/locals (done before try so they exist for result)
        if g is None:
            g = {}
        if l is None:
            l = {}

        safe_globals = dict(g)
        safe_locals = dict(l)

        if isinstance(__builtins__, dict):
            bi = __builtins__
        else:
            bi = vars(__builtins__)
        safe_builtins = {k: bi[k] for k in SAFE_BUILTINS if k in bi}
        safe_globals["__builtins__"] = safe_builtins

        # 2. Start stats (we count nodes even on validation failure)
        start_time = time.perf_counter()
        stats = SandboxStats()
        output = _OutputCapture(max_chars=self.max_output_chars)
        mem_guard = _MemoryGuard(max_value_size=self.max_value_display)

        result_value = None
        error: Optional[BaseException] = None

        tree = None
        last_is_expr = False
        last_stmt = None

        # 3. AST validation - fast-fail on policy violation
        try:
            tree = _validate_and_transform(code, allow_imports=self._allow_imports)

            # Determine if the last statement is a bare expression.
            # If so, we eval() it separately to capture the return value.
            last_stmt = tree.body[-1] if tree.body else None
            last_is_expr = (
                last_stmt is not None
                and isinstance(last_stmt, ast.Expr)
                and not (
                    isinstance(last_stmt.value, ast.Constant)
                    and last_stmt.value.value is None
                )
            )
        except SandboxError as e:
            error = e

        # 4. Execute inside timeout guard
        if error is None:
            with output, _TimeoutGuard(timeout):
                try:
                    if last_is_expr:
                        # Separate leading statements from the final expression
                        stmts = tree.body[:-1]
                        final_expr = last_stmt.value

                        if stmts:
                            exec_tree = ast.Module(body=stmts, type_ignores=[])
                            ast.fix_missing_locations(exec_tree)
                            exec(compile(exec_tree, "<sandbox>", "exec"),
                                 safe_globals, safe_locals)

                        # Evaluate the final expression via eval to capture its value
                        expr_tree = ast.Expression(body=final_expr)
                        ast.fix_missing_locations(expr_tree)
                        result_value = eval(
                            compile(expr_tree, "<sandbox>", "eval"),
                            safe_globals, safe_locals
                        )
                        mem_guard.update_estimate(result_value)
                    else:
                        # Use exec for statement-only sequences
                        exec_code = compile(tree, "<sandbox>", "exec")
                        exec(exec_code, safe_globals, safe_locals)
                except TimeoutException:
                    error = TimeoutException(f"Execution timed out after {timeout}s")
                except SandboxError as e:
                    error = e
                except Exception as e:
                    import traceback
                    tb = traceback.format_exception(type(e), e, e.__traceback__)
                    output.stderr.write("".join(tb))
                    error = SandboxError(f"Runtime error: {e}")

        # 5. Finalise stats
        end_time = time.perf_counter()
        stats.execution_time_ms = (end_time - start_time) * 1000.0
        if tree is not None:
            stats.nodes_visited = len(list(ast.walk(tree)))
        stats.memory_bytes = mem_guard.estimated_bytes
        self._stats = stats

        formatted_result = mem_guard.format_result(result_value)

        return SandboxResult(
            value=formatted_result,
            stdout=output.stdout_value,
            stderr=output.stderr_value,
            stats=stats,
            error=error,
        )

        end_time = time.perf_counter()
        stats.execution_time_ms = (end_time - start_time) * 1000.0
        stats.nodes_visited = len(list(ast.walk(tree)))
        stats.memory_bytes = mem_guard.estimated_bytes

        self._stats = stats

        formatted_result = mem_guard.format_result(result_value)

        return SandboxResult(
            value=formatted_result,
            stdout=output.stdout_value,
            stderr=output.stderr_value,
            stats=stats,
            error=error,
        )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_sandbox: Optional[Sandbox] = None


def execute(code: str, timeout: float = 5.0) -> SandboxResult:
    """
    Execute code in a default sandbox (module-level convenience).

    Parameters
    ----------
    code : str
        Python code to execute.
    timeout : float
        Timeout in seconds (default 5.0).

    Returns
    -------
    SandboxResult
    """
    global _default_sandbox
    if _default_sandbox is None:
        _default_sandbox = Sandbox(timeout_seconds=timeout)
    return _default_sandbox.execute(code)
