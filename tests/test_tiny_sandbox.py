"""
Tests for tiny_sandbox.
Run with: pytest tests/
"""

import pytest
import sys
import ast
import io
import contextlib

import tiny_sandbox as ts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(code: str, timeout: float = 2.0) -> ts.SandboxResult:
    """Execute code in a fresh sandbox, return result."""
    sandbox = ts.Sandbox(timeout_seconds=timeout)
    return sandbox.execute(code)


# ---------------------------------------------------------------------------
# Basic execution
# ---------------------------------------------------------------------------

class TestBasicExecution:
    def test_arithmetic(self):
        r = ok("2 + 2")
        assert r.ok, r.error
        assert r.value == 4

    def test_string_ops(self):
        r = ok("'hello' + ' ' + 'world'")
        assert r.ok, r.error
        assert r.value == "hello world"

    def test_list_ops(self):
        r = ok("[1, 2, 3] + [4, 5]")
        assert r.ok, r.error
        assert r.value == [1, 2, 3, 4, 5]

    def test_dict_ops(self):
        r = ok("{'a': 1, 'b': 2}")
        assert r.ok, r.error
        assert r.value == {"a": 1, "b": 2}

    def test_assignment(self):
        r = ok("x = 10; y = 20; x + y")
        assert r.ok, r.error
        assert r.value == 30

    def test_multiple_lines(self):
        code = "\n".join([
            "result = 0",
            "for i in range(5):",
            "    result += i",
            "result"
        ])
        r = ok(code)
        assert r.ok, r.error
        assert r.value == 10

    def test_function_call_result(self):
        r = ok("len([1, 2, 3])")
        assert r.ok, r.error
        assert r.value == 3

    def test_nested_calls(self):
        r = ok("str(len(range(10)))")
        assert r.ok, r.error
        assert r.value == "10"

    def test_bool_ops(self):
        r = ok("3 > 2 and 1 < 4")
        assert r.ok, r.error
        assert r.value is True


# ---------------------------------------------------------------------------
# Safe builtins
# ---------------------------------------------------------------------------

class TestSafeBuiltins:
    @pytest.mark.parametrize("fn", [
        "range", "len", "str", "int", "float", "bool",
        "list", "dict", "set", "tuple", "enumerate", "zip",
        "map", "filter", "sum", "min", "max", "abs",
        "round", "sorted", "reversed", "any", "all",
        "isinstance", "type", "hash", "print",
    ])
    def test_safe_builtins_available(self, fn):
        # Just calling the builtin shouldn't error
        if fn == "print":
            r = ok(f"{fn}('test')")
        elif fn == "map":
            r = ok(f"list({fn}(str, [1, 2, 3]))")
        elif fn == "filter":
            r = ok(f"list({fn}(str.isdigit, ['a', '1', 'b', '2']))")
        elif fn == "hash":
            r = ok(f"{fn}('test')")
        else:
            r = ok(f"{fn}([1, 2, 3])")
        # If blocked it will be a SandboxError
        assert r.error is None or "blocked" not in str(r.error).lower(), f"{fn} blocked unexpectedly"

    def test_print_captured(self):
        r = ok("print('hello', 'world')")
        assert r.ok, r.error
        assert "hello world" in r.stdout


# ---------------------------------------------------------------------------
# Blocked builtins
# ---------------------------------------------------------------------------

class TestBlockedBuiltins:
    @pytest.mark.parametrize("name", [
        "open", "eval", "exec", "compile", "__import__",
        "getattr", "setattr", "delattr", "globals", "locals",
        "vars", "dir", "breakpoint", "input", "exit", "quit",
        "memoryview", "buffer",
    ])
    def test_blocked_builtins(self, name):
        r = ok(name)
        assert not r.ok, f"{name} should be blocked"
        assert isinstance(r.error, ts.SandboxError)


# ---------------------------------------------------------------------------
# Blocked language features
# ---------------------------------------------------------------------------

class TestBlockedLanguageFeatures:
    def test_classdef_blocked(self):
        r = ok("class Foo: pass")
        assert not r.ok

    def test_import_blocked(self):
        r = ok("import os")
        assert not r.ok

    def test_import_from_os_blocked(self):
        r = ok("from os import path")
        assert not r.ok

    def test_lambda_blocked(self):
        r = ok("f = lambda x: x + 1; f(2)")
        assert not r.ok

    def test_fstring_blocked(self):
        r = ok("x = 'world'; f'hello {x}'")
        assert not r.ok

    def test_yield_blocked(self):
        r = ok("def gen(): yield 1")
        assert not r.ok

    def test_yield_from_blocked(self):
        r = ok("def gen(): yield from [1,2,3]")
        assert not r.ok

    def test_list_comp_blocked(self):
        r = ok("[x for x in range(5)]")
        assert not r.ok

    def test_dict_comp_blocked(self):
        r = ok("{x: x*2 for x in range(3)}")
        assert not r.ok

    def test_set_comp_blocked(self):
        r = ok("{x for x in range(3)}")
        assert not r.ok

    def test_global_statement_blocked(self):
        r = ok("global x")
        assert not r.ok

    def test_nonlocal_statement_blocked(self):
        r = ok("def outer(): x = 1; def inner(): nonlocal x; pass")
        assert not r.ok

    def test_bare_except_blocked(self):
        r = ok("try: 1\nexcept: pass")
        assert not r.ok

    def test_starred_expr_blocked(self):
        r = ok("*a, b = [1, 2, 3]")
        assert not r.ok

    def test_dunder_access_blocked(self):
        r = ok("().__class__")
        assert not r.ok

    def test_private_attr_blocked(self):
        r = ok("().__private")
        assert not r.ok


# ---------------------------------------------------------------------------
# Syntax errors
# ---------------------------------------------------------------------------

class TestSyntaxErrors:
    def test_malformed_code(self):
        r = ok("for i in")
        assert not r.ok
        assert r.error is not None

    def test_invalid_syntax(self):
        r = ok("if if if")
        assert not r.ok


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------

class TestTimeout:
    def test_infinite_loop_hits_timeout(self):
        r = ok("while True: pass", timeout=1.0)
        assert not r.ok
        assert isinstance(r.error, ts.TimeoutException)

    def test_deep_recursion_hits_timeout(self):
        # Very deep recursion should eventually timeout
        r = ok("def f(n): return f(n+1)\nf(0)", timeout=1.0)
        assert not r.ok


# ---------------------------------------------------------------------------
# SandboxedImport
# ---------------------------------------------------------------------------

class TestSandboxedImport:
    def test_math_import_allowed(self):
        sandbox = ts.Sandbox()
        with ts.SandboxedImport(__import__("math"), sandbox=sandbox):
            r = sandbox.execute("import math; math.sqrt(4)")
        assert r.ok, r.error
        assert r.value == 2.0

    def test_json_import_allowed(self):
        sandbox = ts.Sandbox()
        with ts.SandboxedImport(__import__("json"), sandbox=sandbox):
            r = sandbox.execute("import json; json.dumps({'a': 1})")
        assert r.ok, r.error
        assert r.value == '{"a": 1}'

    def test_os_import_blocked_in_context(self):
        sandbox = ts.Sandbox()
        with ts.SandboxedImport(__import__("math")):
            r = sandbox.execute("import os; os.getcwd()")
        assert not r.ok


# ---------------------------------------------------------------------------
# Sandbox.exec()
# ---------------------------------------------------------------------------

class TestExec:
    def test_exec_with_custom_globals(self):
        sandbox = ts.Sandbox()
        g = {"x": 100}
        r = sandbox.exec("y = x * 2; y", globals=g)
        assert r.ok, r.error
        assert r.value == 200

    def test_exec_with_custom_locals(self):
        sandbox = ts.Sandbox()
        l = {"factor": 3}
        r = sandbox.exec("factor * 7", locals=l)
        assert r.ok, r.error
        assert r.value == 21


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_collected(self):
        sandbox = ts.Sandbox()
        r = sandbox.execute("2 + 2")
        assert r.ok, r.error
        assert r.stats is not None
        assert r.stats.execution_time_ms >= 0
        assert r.stats.nodes_visited > 0

    def test_stats_accessible_from_sandbox(self):
        sandbox = ts.Sandbox()
        sandbox.execute("x = 1")
        assert sandbox.stats is not None
        assert sandbox.stats.nodes_visited > 0


# ---------------------------------------------------------------------------
# Output capture
# ---------------------------------------------------------------------------

class TestOutputCapture:
    def test_stdout_captured(self):
        r = ok("print(1); print(2)")
        assert "1" in r.stdout
        assert "2" in r.stdout

    def test_stderr_captured(self):
        r = ok("raise Exception('err')")
        assert "err" in r.stderr

    def test_stdout_and_value(self):
        r = ok("print('printed'); 42")
        assert r.ok, r.error
        assert r.value == 42
        assert "printed" in r.stdout


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

class TestModuleLevelExecute:
    def test_module_execute(self):
        r = ts.execute("2 * 3")
        assert r.ok, r.error
        assert r.value == 6


# ---------------------------------------------------------------------------
# SandboxResult
# ---------------------------------------------------------------------------

class TestSandboxResult:
    def test_ok_property(self):
        r = ok("1 + 1")
        assert r.ok is True

    def test_ok_property_false_on_error(self):
        r = ok("open('/etc/passwd')")
        assert r.ok is False

    def test_repr(self):
        r = ok("42")
        repr_str = repr(r)
        assert "SandboxResult" in repr_str
        assert "ok=True" in repr_str


# ---------------------------------------------------------------------------
# Memory guard
# ---------------------------------------------------------------------------

class TestMemoryGuard:
    def test_large_string_truncated(self):
        sandbox = ts.Sandbox(max_value_display=20)
        r = sandbox.execute("'x' * 1000")
        assert r.ok
        assert "truncated" in str(r.value)


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_string(self):
        assert hasattr(ts, "__version__")
        assert isinstance(ts.__version__, str)
        assert ts.__version__ == "1.0.0"
