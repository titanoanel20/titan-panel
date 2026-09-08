"""Regression guard for the failure that crash-looped the Railway deploy.

What Railway printed, over and over, with no dashboard to debug against::

    File "/app/app/main.py", line 139
      The (host, port) a user's connection link should point at.
                              ^
    SyntaxError: unterminated string literal (detected at line 139)

Root cause: a bulk "replace unicode characters" cleanup rewrote the closing of a
docstring on line 95 - three quote characters became one. The literal never
terminated, so the tokenizer swallowed everything after it until the next quote
a few dozen lines down, and reported the error at a line that looked innocent.
The module cannot compile, the container command dies at once, and Railway
restarts it forever.

These tests make that class of breakage impossible to merge. Note this file's
own docstring deliberately avoids embedding a triple-quote example: doing that
here reproduces the very bug under test.
"""
import ast
import re
import io
import pathlib
import subprocess
import sys
import tokenize

import pytest

from conftest import REPO, compile_all

SOURCES = sorted(
    list(pathlib.Path(REPO).glob("app/*.py"))
    + list(pathlib.Path(REPO).glob("scripts/*.py"))
    + list(pathlib.Path(REPO).glob("tests/*.py"))
)

# code snippets that must never appear inside a docstring: they mean the
# docstring swallowed the statements that followed it
SWALLOW_MARKERS = ("app.get(", "app.post(", "await request.json()", "HTTPException(")


def _ids(p):
    return f"{p.parent.name}/{p.name}"


@pytest.mark.parametrize("path", SOURCES, ids=_ids)
def test_each_source_file_parses(path):
    """Checked before importing anything, so a broken file reports its own line."""
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        pytest.fail(f"{path.name}:{exc.lineno} {exc.msg}: {exc.text!r}")
    assert tree.body, f"{path.name} parsed to nothing - the whole file was eaten"
    if path.name != "__init__.py":
        top = [n for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        assert top, f"{path.name} exposes no top-level defs - the whole file was eaten"


@pytest.mark.parametrize("path", SOURCES, ids=_ids)
def test_tokenizer_reports_no_unterminated_string(path):
    """tokenize flags the real defect even when ast blames a later line."""
    src = path.read_text(encoding="utf-8")
    try:
        list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        pytest.fail(f"{path.name}: unterminated string / bad tokenisation: {exc}")


@pytest.mark.parametrize("path", SOURCES, ids=_ids)
def test_no_docstring_swallowed_real_code(path):
    """A docstring missing its terminator ends up containing real statements.

    Parsing can still succeed if a later quote happens to close it, so this
    checks the shape of the bug rather than only its syntax error.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = [tree] + [n for n in ast.walk(tree)
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    for node in nodes:
        doc = ast.get_docstring(node, clean=False) or ""
        for marker in SWALLOW_MARKERS:
            if marker in doc:
                name = getattr(node, "name", "<module>")
                pytest.fail(f"{path.name}: docstring of {name!r} contains {marker!r} "
                            f"- a missing closing quote probably swallowed code")


def test_compileall_is_clean():
    r = compile_all(REPO)
    assert r.returncode == 0, r.stdout + r.stderr


def test_app_module_is_importable(tmp_path):
    """The container command is what must survive, not just a local import."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import app.main as m;"
         "assert len([x for x in m.app.routes if getattr(x,'methods',None)]) > 30"],
        cwd=REPO, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "TITAN_DATA_DIR": str(tmp_path)},
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_container_command_targets_a_real_module():
    """A rename or a deleted file breaks the deploy exactly like a typo does."""
    dockerfile = pathlib.Path(REPO, "Dockerfile").read_text(encoding="utf-8")
    script = pathlib.Path(REPO, "entrypoint.sh").read_text(encoding="utf-8")
    assert "entrypoint.sh" in dockerfile
    assert "app.main" in script
    assert pathlib.Path(REPO, "app", "main.py").exists()
    assert "EXPOSE" in dockerfile


def test_the_lines_a_bulk_replace_broke_are_intact():
    """Guards the neighbourhood of the incident against another sweep.

    The broken sentence was the docstring of the helper that decides which host
    a generated link points at, so a regression here means dead configs.
    """
    main = pathlib.Path(REPO, "app", "main.py").read_text(encoding="utf-8")
    tree = ast.parse(main)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_public_host")
    doc = ast.get_docstring(fn) or ""
    assert "public_domain" in doc, doc
    # the helper still strips a :port off the Host header (rewritten when the
    # Railway domain fallback landed, so match the behaviour, not the wording)
    assert re.search(r"host\.split\(\":\"\)", main), "the public-host helper lost its port split"
    for needle in ("def _public_host(request: Request) -> str:",
                   "return port if 1 <= port <= 65535 else 443",
                   "if not db.get_user(uid):"):
        assert needle in main, f"main.py lost: {needle!r}"


def test_no_typographic_operators_in_executable_code():
    """The reason the bad cleanup was attempted at all.

    Arrows and em-dashes are perfectly legal inside strings and comments, and
    that is where they stay; the guard is that they never sit in a token where a
    lossy editor/tool could choke and someone feels obliged to 'fix' it.
    """
    offenders = []
    for path in SOURCES:
        try:
            toks = list(tokenize.generate_tokens(io.StringIO(
                path.read_text(encoding="utf-8")).readline))
        except Exception:  # reported by the tokenizer test above
            continue
        for tok in toks:
            if tok.type in (tokenize.OP, tokenize.NAME) and any(
                    c in tok.string for c in ("\u2192", "\u00d7", "\u2014")):
                offenders.append(f"{path.name}:{tok.start[0]}")
    assert not offenders, f"unicode operators in code at: {offenders}"
