"""Phase 0 checks: the package imports, and the CORE stays free of web/deploy code.

The second test protects a stated requirement: other AI systems must be able
to import the security package without FastAPI or dashboard code.
"""
import pathlib
import subprocess
import sys

REPO_ROOT = str(pathlib.Path(__file__).resolve().parents[2])


def test_package_imports_and_has_version():
    import guardrails

    assert guardrails.__version__


def test_core_import_does_not_load_fastapi():
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import guardrails; "
        "assert 'guardrails' in sys.modules; "
        "sys.exit(1 if 'fastapi' in sys.modules else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code, REPO_ROOT], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
