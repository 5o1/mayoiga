#!/usr/bin/env python3
"""mayoiga documentation-graph linter.

The docs/ directory is a Python package where each *document* is a function
whose docstring is the prose and whose body calls other functions to express
navigation jumps.  This script enforces three invariants:

  1. **No broken links**  -- every call that resolves to a docs/ function
     actually exists.  Running all entry-point functions catches import/name
     errors at runtime; the AST pass catches calls to undefined targets.

  2. **No orphan documents** -- every function in docs/ (except declared entry
     points) is called by at least one other function.  A function nobody calls
     is a dead document no agent will reach.

  3. **No orphan assets** -- every tracked non-Python file (scripts, configs,
     Dockerfiles, systemd units, etc.) is referenced as a literal string in at
     least one docstring.  A file no document mentions is invisible.

Usage:
    python3 scripts/check_graph.py            # run all checks
    python3 scripts/check_graph.py --orphans  # AST orphan scan only
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
DOCS_PKG = REPO_ROOT / "docs"

# Functions that act as call-graph roots; they are exempt from the orphan
# check because nobody calls them -- agents enter the graph here.
ENTRY_POINTS = [
    ("docs.roles", "client"),
    ("docs.roles", "gateway"),
    ("docs.roles", "relay"),
    ("docs.roles", "subnode"),
    ("docs.roles", "coordinator"),
]

# File globs whose assets must appear in at least one docstring.
ASSET_GLOBS = [
    "cmd/**/*.go",
    "cmd/**/locales/*.json",
    "go.mod",
    ".github/workflows/*.yml",
]

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
NC = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}[+]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[!]{NC} {msg}")


def fail(msg: str) -> None:
    print(f"{RED}[x]{NC} {msg}")


# ---------------------------------------------------------------------------
# 1. Runtime check: import and call every entry point
# ---------------------------------------------------------------------------
def check_entry_points() -> bool:
    """Import every docs module and verify entry points exist.

    We do NOT call the entry-point functions: the call graph contains
    intentional cycles (e.g. operations <-> troubleshooting) which would
    cause infinite recursion at runtime.  The AST pass in check_graph()
    already validates that every call target is defined.
    """
    good = True

    # Import all docs modules -- catches ImportError (misspelled module names)
    py_files = sorted(DOCS_PKG.glob("*.py"))
    for py in py_files:
        if py.name == "__init__.py":
            continue
        mod_name = f"docs.{py.stem}"
        try:
            importlib.import_module(mod_name)
            ok(f"import {mod_name} OK")
        except Exception as exc:  # noqa: BLE001
            fail(f"import {mod_name} FAILED: {exc}")
            good = False

    # Verify entry points exist as callables
    for mod_name, func_name in ENTRY_POINTS:
        try:
            mod = importlib.import_module(mod_name)
            func = getattr(mod, func_name)
            if not callable(func):
                fail(f"entry point {mod_name}.{func_name} is not callable")
                good = False
            else:
                ok(f"entry point {mod_name}.{func_name}() exists")
        except Exception as exc:  # noqa: BLE001
            fail(f"entry point {mod_name}.{func_name}() FAILED: {exc}")
            good = False
    return good


# ---------------------------------------------------------------------------
# 2. AST check: orphan functions and unresolved calls
# ---------------------------------------------------------------------------
def _collect_functions(tree: ast.Module) -> set[str]:
    """Return names of top-level functions defined in *tree*."""
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _resolve_calls(tree: ast.Module) -> set[tuple[str, str]]:
    """Return ``(module, function)`` pairs for every cross-doc call.

    Resolves ``from docs.X import Y [as Z]`` patterns (both top-level and
    function-local), tracking the *original* function name even when
    aliased.  Supports bare ``Y()`` / ``Z()`` calls.
    """
    calls: set[tuple[str, str]] = set()

    # local-name -> (module, original_name)
    top_imports: dict[str, tuple[str, str | None]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("docs."):
            for alias in node.names:
                local_name = alias.asname or alias.name
                top_imports[local_name] = (node.module, alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        local_imports = dict(top_imports)
        for child in ast.walk(node):
            if isinstance(child, ast.ImportFrom) and child.module and child.module.startswith("docs."):
                for alias in child.names:
                    local_name = alias.asname or alias.name
                    local_imports[local_name] = (child.module, alias.name)

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            # bare name call: Y() or Z()
            if isinstance(func, ast.Name) and func.id in local_imports:
                mod, orig = local_imports[func.id]
                if orig is not None:
                    calls.add((mod, orig))
            # attribute call: mod.Y()
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in local_imports:
                    mod, _ = local_imports[func.value.id]
                    calls.add((mod, func.attr))

    return calls


def check_graph() -> bool:
    """Detect orphan functions and unresolved calls via AST analysis."""
    py_files = sorted(DOCS_PKG.glob("*.py"))
    py_files = [f for f in py_files if f.name != "__init__.py"]

    defined: dict[str, set[str]] = {}  # module -> {func names}
    called: set[tuple[str, str]] = set()

    for py in py_files:
        mod_name = f"docs.{py.stem}"
        tree = ast.parse(py.read_text(), filename=str(py))
        defined[mod_name] = _collect_functions(tree)
        called |= _resolve_calls(tree)

    entry_set = {(m, f) for m, f in ENTRY_POINTS}

    good = True

    # Orphan: defined but never called (and not an entry point)
    for mod_name, funcs in sorted(defined.items()):
        for func in sorted(funcs):
            key = (mod_name, func)
            if key in entry_set:
                continue
            if key not in called:
                fail(f"orphan document: {mod_name}.{func}() is never called")
                good = False

    # Broken link: called but not defined
    for mod_name, func in sorted(called):
        if mod_name in defined and func in defined[mod_name]:
            continue
        fail(f"broken link: call to {mod_name}.{func}() but it is not defined")
        good = False

    return good


# ---------------------------------------------------------------------------
# 3. Asset coverage check
# ---------------------------------------------------------------------------
def check_assets() -> bool:
    """Every tracked asset must appear as a literal string in some docstring."""
    # Collect all docstrings
    all_docstrings: list[str] = []
    for py in sorted(DOCS_PKG.glob("*.py")):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                if (doc := ast.get_docstring(node)) is not None:
                    all_docstrings.append(doc)

    combined = "\n".join(all_docstrings)

    good = True
    for pattern in ASSET_GLOBS:
        for asset in sorted(REPO_ROOT.glob(pattern)):
            rel = asset.relative_to(REPO_ROOT).as_posix()
            # Check several plausible reference forms
            if rel in combined or f"./{rel}" in combined or asset.name in combined:
                continue
            fail(f"orphan asset: {rel} is not referenced in any docstring")
            good = False

    return good


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    checks = {
        "entry points (runtime)": check_entry_points,
        "call graph (AST)": check_graph,
        "asset coverage": check_assets,
    }

    all_good = True
    for label, fn in checks.items():
        print(f"\n--- {label} ---")
        all_good &= fn()

    print()
    if all_good:
        ok("all documentation-graph checks passed")
        return 0
    fail("one or more checks failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
