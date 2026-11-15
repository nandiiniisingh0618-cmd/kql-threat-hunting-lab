"""The detection harness.

Three classes of assertion, per your working rule #2 ("a detection counts as
covered only if its test passes on real dataset events"):

  1. structural -- the YAML is complete and its ATT&CK IDs are current
  2. true positive -- the query returns >= min_hits on the declared datasets,
     and the expected entities really appear in those rows
  3. false-positive proxy -- how often it fires on unrelated datasets
"""
from __future__ import annotations

import pytest

from tests._state import RESULTS
from tests.conftest import run_detection
from tools.registry import attack_model

SEVERITIES = {"Informational", "Low", "Medium", "High"}
STATUSES = {"validated", "experimental"}


def detection_ids(detections) -> list[str]:
    return [d["name"] for d in detections]


# --------------------------------------------------------------------------- #
# 1. Structure
# --------------------------------------------------------------------------- #

def test_detections_exist(detections):
    assert len(detections) >= 20, f"expected at least 20 detections, found {len(detections)}"


def test_detection_structure(detections):
    model = attack_model()
    problems: list[str] = []
    for detection in detections:
        where = detection["_rel_path"]
        if detection["severity"] not in SEVERITIES:
            problems.append(f"{where}: severity {detection['severity']!r} not in {SEVERITIES}")
        if detection["status"] not in STATUSES:
            problems.append(f"{where}: status {detection['status']!r} not in {STATUSES}")
        if str(detection["attack_version"]) != str(model["version"]):
            problems.append(
                f"{where}: attack_version {detection['attack_version']} "
                f"!= pinned {model['version']}"
            )
        if not detection["techniques"]:
            problems.append(f"{where}: no techniques listed")
        if not detection["tests"]:
            problems.append(f"{where}: no tests block")
        if "DatasetId" not in detection["query"]:
            problems.append(f"{where}: query must emit DatasetId for hit attribution")
        for field in ("false_positives", "known_blind_spots"):
            if not detection[field]:
                problems.append(f"{where}: {field} must not be empty")
        if not detection["_tactics"]:
            problems.append(
                f"{where}: no tactic could be derived from techniques "
                f"{detection['techniques']} -- are the IDs valid?"
            )
    assert not problems, "\n".join(problems)


def test_attack_ids_are_current(detections):
    """A revoked or deprecated ID must never reach the coverage pages."""
    model = attack_model()
    problems: list[str] = []
    for detection in detections:
        for technique_id in detection["techniques"]:
            if technique_id in model["revoked"]:
                replacement = model["revoked"][technique_id] or "(no replacement recorded)"
                problems.append(
                    f"{detection['_rel_path']}: {technique_id} is REVOKED in "
                    f"ATT&CK v{model['version']} -> use {replacement}"
                )
            elif technique_id in model["deprecated"]:
                problems.append(
                    f"{detection['_rel_path']}: {technique_id} is DEPRECATED in "
                    f"ATT&CK v{model['version']}"
                )
            elif technique_id not in model["techniques"]:
                problems.append(
                    f"{detection['_rel_path']}: {technique_id} does not exist in "
                    f"ATT&CK v{model['version']}"
                )
    assert not problems, "\n".join(problems)


def test_declared_test_datasets_are_ingested(detections, ingested_datasets):
    """Distinguish 'detection is broken' from 'data was never loaded'."""
    missing: list[str] = []
    for detection in detections:
        for case in detection["tests"]:
            dataset_id = case["dataset_id"]
            if dataset_id not in ingested_datasets:
                missing.append(f"{detection['_rel_path']}: dataset {dataset_id} not ingested")
    if missing:
        pytest.skip("datasets not ingested:\n" + "\n".join(missing))


# --------------------------------------------------------------------------- #
# 2 + 3. Behaviour on real data
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="session")
def executed(client, detections, ingested_datasets, corpus_rows):
    """Run every detection once; share the results across assertions."""
    runs = {}
    for detection in detections:
        rows, elapsed, error = run_detection(client, detection)
        declared = {case["dataset_id"] for case in detection["tests"]}
        hits_by_dataset: dict[str, int] = {}
        for row in rows:
            key = str(row.get("DatasetId"))
            hits_by_dataset[key] = hits_by_dataset.get(key, 0) + 1

        other_datasets = sorted(
            dataset for dataset in hits_by_dataset
            if dataset not in declared and dataset in ingested_datasets
        )
        eligible = len(ingested_datasets - declared) or 1
        runs[detection["id"]] = {
            "rows": rows,
            "elapsed": elapsed,
            "error": error,
            "hits_by_dataset": hits_by_dataset,
            "declared": declared,
            "other_datasets": other_datasets,
            "fp_rate": len(other_datasets) / eligible,
        }
        RESULTS.append(
            {
                "detection": detection,
                "hits_total": len(rows),
                "hits_by_dataset": hits_by_dataset,
                "declared": sorted(declared),
                "other_datasets": other_datasets,
                "fp_rate": len(other_datasets) / eligible,
                "elapsed": elapsed,
                "error": error,
                "corpus_rows": corpus_rows,
                "datasets_total": len(ingested_datasets),
            }
        )
    return runs


def test_queries_execute(detections, executed):
    broken = [
        f"{d['_rel_path']}: {executed[d['id']]['error']}"
        for d in detections if executed[d["id"]]["error"]
    ]
    assert not broken, "\n".join(broken)


def test_true_positives(detections, executed):
    """The core assertion: real hits on real events, with the right entities."""
    failures: list[str] = []
    for detection in detections:
        run = executed[detection["id"]]
        if run["error"]:
            continue  # reported by test_queries_execute
        for case in detection["tests"]:
            dataset_id = case["dataset_id"]
            min_hits = int(case.get("min_hits", 1))
            actual = run["hits_by_dataset"].get(dataset_id, 0)
            if actual < min_hits:
                failures.append(
                    f"{detection['_rel_path']} [{detection['name']}]: "
                    f"dataset {dataset_id} produced {actual} hit(s), expected >= {min_hits}"
                )
                continue

            # Entity assertions are checked only against rows from this dataset.
            expected = case.get("expect") or {}
            if not expected:
                continue
            dataset_rows = [r for r in run["rows"] if str(r.get("DatasetId")) == dataset_id]
            for column, needle in expected.items():
                if column not in (dataset_rows[0] if dataset_rows else {}):
                    failures.append(
                        f"{detection['_rel_path']}: expected column {column!r} not in "
                        f"output {sorted((dataset_rows[0] if dataset_rows else {}).keys())}"
                    )
                    continue
                values = [str(r.get(column, "")) for r in dataset_rows]
                if not any(str(needle).lower() in v.lower() for v in values):
                    failures.append(
                        f"{detection['_rel_path']}: dataset {dataset_id} expected "
                        f"{column} to contain {needle!r}; saw {values[:4]}"
                    )
    assert not failures, "\n".join(failures)


def test_experimental_detections_are_labelled(detections, executed):
    """A detection with no passing true positive must not claim to be validated."""
    wrong: list[str] = []
    for detection in detections:
        run = executed[detection["id"]]
        has_tp = any(
            run["hits_by_dataset"].get(case["dataset_id"], 0) >= int(case.get("min_hits", 1))
            for case in detection["tests"]
        ) and not run["error"]
        if detection["status"] == "validated" and not has_tp:
            wrong.append(
                f"{detection['_rel_path']}: status 'validated' but no test produced "
                "its required hits -- mark it 'experimental' or fix the query"
            )
    assert not wrong, "\n".join(wrong)


def test_false_positive_proxy_is_bounded(detections, executed):
    """Report, and loosely bound, firing on unrelated datasets.

    This is a proxy, not a real FP rate: the other datasets are also attack data,
    so overlap is often legitimate (a Mimikatz dataset really does contain LSASS
    access). A detection may raise its own ceiling with tuning_notes explaining why.
    """
    noisy: list[str] = []
    for detection in detections:
        run = executed[detection["id"]]
        if run["error"]:
            continue
        ceiling = float(detection.get("max_cross_dataset_rate", 0.85))
        if run["fp_rate"] > ceiling:
            noisy.append(
                f"{detection['_rel_path']} [{detection['name']}]: fired on "
                f"{len(run['other_datasets'])} undeclared dataset(s) "
                f"(rate {run['fp_rate']:.2f} > ceiling {ceiling:.2f}): "
                f"{run['other_datasets'][:6]}"
            )
    assert not noisy, "\n".join(noisy)
