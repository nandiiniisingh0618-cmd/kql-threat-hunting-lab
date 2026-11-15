"""Shared harness state.

Lives in its own module so that conftest.py and the test module append to and read
from the SAME list. Importing `conftest` from a test file can yield a second module
object distinct from the one pytest loaded, in which case results collected during
the run are invisible to pytest_sessionfinish and RESULTS.md is never written.
"""
from __future__ import annotations

RESULTS: list[dict] = []
