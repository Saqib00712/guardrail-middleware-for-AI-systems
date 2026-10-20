"""Test-wide helpers.

Why this exists: pytest puts each test's full id into the PYTEST_CURRENT_TEST
environment variable. Windows refuses environment variables over 32,767 characters,
and some of our hostile-input tests are parametrized with 100,000-character strings,
so on Windows they errored at setup ("ValueError: the environment variable is longer
than 32767 characters"). Long string parameters now get a short, stable id, and
collection fails loudly if any test id ever grows large again.
"""
import zlib

import pytest

MAX_ID_CHARS = 400


def pytest_make_parametrize_id(config, val, argname):
    if isinstance(val, str) and len(val) > 40:
        crc = zlib.crc32(val.encode("utf-8", "surrogatepass")) & 0xFFFFFFFF
        return f"{argname}-len{len(val)}-{crc:08x}"
    if isinstance(val, bytes) and len(val) > 40:
        return f"{argname}-bytes{len(val)}-{zlib.crc32(val) & 0xFFFFFFFF:08x}"
    return None  # default id


def pytest_collection_modifyitems(items):
    too_long = [i.nodeid[:120] for i in items if len(i.nodeid) > MAX_ID_CHARS]
    if too_long:
        raise pytest.UsageError(
            f"{len(too_long)} test ids exceed {MAX_ID_CHARS} characters (breaks on Windows); "
            f"pass ids=[...] to parametrize. First: {too_long[0]}")
