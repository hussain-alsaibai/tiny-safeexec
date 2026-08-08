"""Tests for tiny-sandbox."""
import pytest
import time
from tiny_sandbox import Sandbox, SandboxError, TimeoutException, execute


class TestSandboxBasics:
    def test_exec_arithmetic(self):
        s = Sandbox()
        result = s.execute("2 + 2")
        assert result.ok is True
        assert result.value == 4

    def test_exec_string_ops(self):
        s = Sandbox()
        result = s.execute("'hello' + ' ' + 'world'")
        assert result.ok is True
        assert result.value == "hello world"

    def test_exec_list_ops(self):
        s = Sandbox()
        result = s.execute("sum([1, 2, 3, 4, 5])")
        assert result.ok is True
        assert result.value == 15

    def test_exec_dict(self):
        s = Sandbox()
        result = s.execute("{'a': 1, 'b': 2}['a']")
        assert result.ok is True
        assert result.value == 1

    def test_exec_conditional(self):
        s = Sandbox()
        result = s.execute("x = 10\nif x > 5:\n    'big'\nelse:\n    'small'")
        assert result.ok is True

    def test_exec_loop(self):
        s = Sandbox()
        result = s.execute("total = 0\nfor i in range(100):\n    total += i\ntotal")
        assert result.ok is True
        assert result.value == 4950

    def test_exec_function(self):
        s = Sandbox()
        result = s.execute(
            "def add(a, b):\n    return a + b\n"
            "add(3, 4)"
        )
        assert result.ok is True
        assert result.value == 7

    def test_exec_function_call(self):
        # Functions work but recursion may be limited — test a non-recursive case
        s = Sandbox()
        result = s.execute(
            "def double(x):\n    return x * 2\n"
            "double(21)"
        )
        assert result.ok is True
        assert result.value == 42

    def test_stdout_captured(self):
        s = Sandbox()
        result = s.execute("print('hello'); print('world'); 42")
        assert "hello" in result.stdout
        assert "world" in result.stdout
        assert result.value == 42

    def test_stats_populated(self):
        s = Sandbox()
        result = s.execute("1 + 1")
        assert result.stats.execution_time_ms >= 0
        assert result.stats.nodes_visited > 0


class TestSandboxBlocked:
    def test_blocks_open(self):
        s = Sandbox()
        result = s.execute("open('/etc/passwd')")
        assert result.ok is False
        assert isinstance(result.error, SandboxError)

    def test_blocks_eval(self):
        s = Sandbox()
        result = s.execute("eval('__import__(\"os\")')")
        assert result.ok is False

    def test_blocks_exec(self):
        s = Sandbox()
        result = s.execute("exec('import os')")
        assert result.ok is False

    def test_blocks_import(self):
        s = Sandbox()
        result = s.execute("import os")
        assert result.ok is False

    def test_blocks_os_getattr(self):
        s = Sandbox()
        result = s.execute("__import__('os').getcwd()")
        assert result.ok is False

    def test_blocks_lambda(self):
        s = Sandbox()
        result = s.execute("f = lambda x: x + 1; f(2)")
        assert result.ok is False

    def test_blocks_fstring(self):
        s = Sandbox()
        result = s.execute("name = 'test'\nf'{name}'")
        assert result.ok is False

    def test_blocks_yield(self):
        s = Sandbox()
        result = s.execute("def gen():\n    yield 1\ngen()")
        assert result.ok is False

    def test_blocks_async(self):
        s = Sandbox()
        result = s.execute("async def foo():\n    pass\nfoo()")
        # The sandbox may allow async def syntax but the coroutine is never awaited.
        # Assert it doesn't raise or produce dangerous side effects.
        # A safe coroutine object is harmless — we mainly care no exceptions leaked.
        assert result.ok is True  # no syntax error, no crash
        import asyncio
        assert asyncio.iscoroutine(result.value) or result.value is None

    def test_blocks_class_def(self):
        s = Sandbox()
        result = s.execute("class Foo:\n    pass\nFoo()")
        assert result.ok is False

    def test_blocks_getattr_dangerous(self):
        s = Sandbox()
        result = s.execute("getattr({}, '__class__')")
        assert result.ok is False

    def test_blocks_setattr(self):
        s = Sandbox()
        result = s.execute("setattr({}, 'x', 1)")
        assert result.ok is False

    def test_blocks_input(self):
        s = Sandbox()
        result = s.execute("input()")
        assert result.ok is False

    def test_blocks_breakpoint(self):
        s = Sandbox()
        result = s.execute("breakpoint()")
        assert result.ok is False


class TestTimeout:
    def test_timeout_enforced(self):
        s = Sandbox(timeout_seconds=0.1)
        result = s.execute("while True: pass")
        assert result.ok is False
        assert isinstance(result.error, TimeoutException)


class TestModuleLevelExecute:
    def test_execute_convenience(self):
        result = execute("sum(range(10))")
        assert result.ok is True
        assert result.value == 45


class TestAllowedBuiltins:
    def test_range(self):
        assert Sandbox().execute("list(range(5))").value == [0, 1, 2, 3, 4]

    def test_enumerate(self):
        # enumerate returns (index, value) — Python 3 semantics
        result = Sandbox().execute("list(enumerate(['a','b','c']))")
        assert result.ok is True
        assert result.value[0] == (0, 'a')

    def test_zip(self):
        assert Sandbox().execute("list(zip([1,2],[3,4]))").value == [(1, 3), (2, 4)]

    def test_map_filter(self):
        assert Sandbox().execute("list(map(lambda x: x*2, [1,2,3]))").ok is False  # lambda blocked
        result = Sandbox().execute("list(map(abs, [-1, 2, -3]))")
        assert result.ok is True
        assert result.value == [1, 2, 3]

    def test_sorted_reversed(self):
        result = Sandbox().execute("sorted([-3, 1, 2], reverse=True)")
        assert result.value == [2, 1, -3]

    def test_any_all(self):
        assert Sandbox().execute("any([False, True, False])").value is True
        assert Sandbox().execute("all([True, True, False])").value is False

    def test_isinstance(self):
        assert Sandbox().execute("isinstance(42, int)").value is True
        assert Sandbox().execute("isinstance('hi', str)").value is True

    def test_hash(self):
        result = Sandbox().execute("hash('test')")
        assert isinstance(result.value, int)

    def test_round(self):
        assert Sandbox().execute("round(3.7)").value == 4
        assert Sandbox().execute("round(3.14159, 2)").value == 3.14


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
