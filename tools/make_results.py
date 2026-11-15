"""Render RESULTS.md from harness output. Never hand-written."""
from __future__ import annotations

from datetime import UTC, datetime

from . import config
from .registry import attack_model


def write_results(results: list[dict]) -> None:
    model = attack_model()
    results = sorted(results, key=lambda r: r["detection"]["name"])
    total = len(results)
    passed = sum(1 for r in results if _passed(r))
    corpus_rows = results[0]["corpus_rows"] if results else 0
    datasets_total = results[0]["datasets_total"] if results else 0
    runtime = sum(r["elapsed"] for r in results)

    lines: list[str] = []
    lines.append("# RESULTS.md")
    lines.append("")
    lines.append(
        "**Generated** by `make test` -- do not edit. "
        f"Last run {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')}."
    )
    lines.append("")
    lines.append(f"- ATT&CK version pinned: **v{model['version']}**")
    lines.append(f"- Corpus: **{corpus_rows:,} events** across **{datasets_total} datasets**")
    lines.append(f"- Detections run: **{total}**, with a passing real-data true positive: **{passed}**")
    lines.append(f"- Total query time: **{runtime:.2f}s** (mean {runtime/max(total,1):.3f}s per detection)")
    lines.append("")
    lines.append(
        "> Every detection below is executed once against the **entire** ingested corpus. "
        "Hits are then attributed by `DatasetId`. \"Cross-dataset\" counts datasets the "
        "detection fired on that it does not declare as a true-positive source -- a "
        "false-positive *proxy*, not a production FP rate. These are all attack datasets, "
        "so some overlap is genuinely correct (a Mimikatz capture really does contain "
        "LSASS access)."
    )
    lines.append("")

    # ---- main table ----
    lines.append("## Detection results")
    lines.append("")
    lines.append("| Detection | Techniques | Status | TP hits | Cross-dataset | Rate | Time (s) |")
    lines.append("|---|---|---|---:|---:|---:|---:|")
    for result in results:
        detection = result["detection"]
        tp_hits = sum(
            result["hits_by_dataset"].get(dataset, 0) for dataset in result["declared"]
        )
        mark = "pass" if _passed(result) else ("ERROR" if result["error"] else "no TP")
        status = detection["status"]
        label = f"{status}" if status != "validated" else "validated"
        lines.append(
            f"| {detection['name']} | {', '.join(detection['techniques'])} | "
            f"{label} / {mark} | {tp_hits} | {len(result['other_datasets'])} | "
            f"{result['fp_rate']:.2f} | {result['elapsed']:.3f} |"
        )
    lines.append("")

    # ---- per-detection detail ----
    lines.append("## Per-detection detail")
    lines.append("")
    for result in results:
        detection = result["detection"]
        lines.append(f"### {detection['name']}")
        lines.append("")
        lines.append(f"- File: `{detection['_rel_path']}`")
        lines.append(
            f"- Techniques: {', '.join(detection['techniques'])} "
            f"-> tactics {', '.join(t['name'] for t in detection['_tactics'])}"
        )
        lines.append(f"- Severity: {detection['severity']} | Status: {detection['status']}")
        if result["error"]:
            lines.append(f"- **QUERY ERROR:** `{result['error'].splitlines()[0]}`")
        lines.append(f"- Runtime: {result['elapsed']:.3f}s | total hits: {result['hits_total']}")
        lines.append("")
        lines.append("| Dataset | Hits | Declared true positive |")
        lines.append("|---|---:|---|")
        for dataset in sorted(result["hits_by_dataset"], key=lambda d: -result["hits_by_dataset"][d]):
            declared = "yes" if dataset in result["declared"] else "no"
            lines.append(f"| {dataset} | {result['hits_by_dataset'][dataset]} | {declared} |")
        for dataset in result["declared"]:
            if dataset not in result["hits_by_dataset"]:
                lines.append(f"| {dataset} | 0 | yes (**MISSED**) |")
        lines.append("")

    path = config.REPO_ROOT / "RESULTS.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {path.name}: {passed}/{total} detections with a passing true positive")


def _passed(result: dict) -> bool:
    if result["error"]:
        return False
    for case in result["detection"]["tests"]:
        required = int(case.get("min_hits", 1))
        if result["hits_by_dataset"].get(case["dataset_id"], 0) >= required:
            return True
    return False
