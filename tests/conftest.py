"""Pytest fixtures and the RESULTS.md collector.

Execution model: each detection runs ONCE over the whole ingested corpus. Hits are
then grouped by DatasetId, which gives three things from a single query:

  * true positives  -- hits in the datasets the detection declares
  * a false-positive proxy -- hits in unrelated datasets
  * cost            -- wall-clock runtime and rows scanned

Every detection must therefore emit a DatasetId column. That is a lab affordance
for provenance; in production you would drop it (see docs/schema-mapping.md).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Collected across the session and written to RESULTS.md at the end.
# Imported from tests._state so conftest and the test module share one list.
from tests._state import RESULTS
from tools import config
from tools.kusto import KustoClient, KustoError
from tools.registry import load_detections


@pytest.fixture(scope="session")
def client() -> KustoClient:
    kusto = KustoClient()
    if not kusto.is_reachable():
        pytest.skip(
            f"Kusto not reachable at {kusto.uri}. Run: python tasks.py up && python tasks.py ingest",
            allow_module_level=True,
        )
    return kusto


@pytest.fixture(scope="session")
def ingested_datasets(client: KustoClient) -> set[str]:
    if not client.table_exists(config.RAW_TABLE):
        pytest.skip("RawEvents table missing. Run: python tasks.py ingest")
    return set(client.query("LabDatasets() | project DatasetId").column("DatasetId"))


@pytest.fixture(scope="session")
def corpus_rows(client: KustoClient) -> int:
    return client.row_count(config.RAW_TABLE)


@pytest.fixture(scope="session")
def detections() -> tuple[dict, ...]:
    found = load_detections()
    if not found:
        pytest.skip("no detections found in detections/")
    return found


def run_detection(client: KustoClient, detection: dict) -> tuple[list[dict], float, str | None]:
    """Execute one detection. Returns (rows, elapsed_seconds, error_or_None)."""
    started = time.perf_counter()
    try:
        result = client.query(detection["query"])
    except KustoError as exc:
        return [], time.perf_counter() - started, str(exc)
    elapsed = time.perf_counter() - started
    if "DatasetId" not in result.columns:
        return [], elapsed, (
            "detection output has no DatasetId column; the harness needs it to "
            f"attribute hits (columns: {result.columns})"
        )
    return result.dicts(), elapsed, None


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001
    """Write RESULTS.md from whatever the run collected."""
    if not RESULTS:
        print("\nno detection results collected; RESULTS.md not written")
        return
    from tools.make_results import write_results
    write_results(RESULTS)
