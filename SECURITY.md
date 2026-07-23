# Security Model & Limitations

> **⚠️ IMPORTANT — READ BEFORE USE**

`tiny-sandbox` uses Python's `exec()` internally. It provides **defense-in-depth** against accidental misuse and is suitable for running **trusted-but-curious** code (e.g., user-submitted scripts in a learning platform). It is **NOT** designed to safely execute adversarial or malicious code in a security-critical context.

---

## What This Sandbox Does Well

1. **Prevents accidental dangerous operations** — Users cannot accidentally call `open()`, `eval()`, `exec()`, `compile()`, or import dangerous modules like `os`, `sys`, `subprocess`, `ctypes`, `mmap`.
2. **Blocks language features that are hard to reason about** — `lambda`, comprehensions, `yield`, `global`/`nonlocal`, `class`, f-strings, starred expressions.
3. **Enforces resource limits** — Timeout (signal/threading), output size limits, value truncation.
4. **Provides AST-level enforcement** — Policy is enforced at parse time, before any code runs.

---

## Known Limitations

### 1. Python's `exec()` is Inherently Unsafe for Adversarial Code

`exec()` runs inside the same Python process with the same Python interpreter. A sophisticated attacker who finds any Python-level escape (see below) gains full access to the process memory, file descriptors, and everything the Python interpreter has access to.

### 2. Potential Escape Vunders

The following are NOT blocked but are also not directly accessible through whitelisted builtins. However, they may be discoverable through introspection:

- **Built-in types' methods**: e.g., `list.__dict__`, `type.__dict__` — could theoretically leak
- **Garbage collector**: `gc.get_objects()` — may allow access to live objects including `__builtins__`
- **`sys.implementation`**: leaking CPython internals
- **`ast` module**: if the user could import `ast`, they could parse new code — currently blocked via `SafeASTTransformer`, but this is a defense-in-depth measure only

### 3. Denial of Service (DoS)

- **Memory exhaustion**: While output is truncated, large intermediate data structures (e.g., `[1]*10_000_000`) may be allocated before truncation
- **CPU exhaustion**: Certain computations (e.g., cryptographic operations, large prime factorization) can consume significant CPU before a timeout kicks in
- **Recursion depth**: Deep recursion can exhaust the Python stack (`RecursionError` will terminate the call, but the stack may already be deep)

### 4. Timing Attacks

- Execution timing is observable and may leak information about data-dependent operations.

### 5. Side Channels

- **Memory pressure**: Allocating large objects may cause observable memory pressure effects
- **CPU cache**: Different code paths may exhibit different CPU cache behavior

### 6. multiprocessing / threading

- `multiprocessing` and threading are not explicitly blocked. However, without access to `os`, `sys`, or `subprocess`, spawning new processes is not trivially possible. Thread creation may be possible through certain built-in types.

### 7. File Descriptor Access

- Without `os` or `open`, direct file descriptor manipulation is not possible. However, this should not be considered a security guarantee.

---

## What to Use Instead for Untrusted/Adversarial Code

For truly adversarial code, use one of:

| Approach | Isolation Level |
|---|---|
| **Docker / container** | Process + filesystem + network isolation |
| **Firecracker microVMs** | Hardware virtualization |
| **gVisor / gKernel** | OS-level virtualization |
| **PyPy sandbox** | Bytecode-level restricted interpreter |
| **Separate machine / VM** | Physical isolation |

---

## Reporting Security Issues

If you discover a security vulnerability in `tiny-sandbox`, please report it responsibly. Do NOT open a public GitHub issue. Contact the maintainer directly.
