"""Fail the build on any technique ID that is missing, revoked or deprecated.

This is a hard gate, not a formality. When this repo was planned, two of the 27
hand-picked technique IDs were already stale: ATT&CK v20.1 revoked T1070.001 in
favour of T1685.005, and the whole T1562 "Impair Defenses" tree in favour of T1685
under the new Defense Impairment tactic (TA0112). Both would have shipped as
plausible-looking nonsense without this check.
"""
from __future__ import annotations

import sys

from . import config
from .registry import attack_model, ensure_stix, load_detections


def main(argv: list[str] | None = None) -> int:
    argv = argv or []
    ensure_stix()
    model = attack_model()
    detections = load_detections()

    print(f"ATT&CK Enterprise v{model['version']} "
          f"({len(model['techniques'])} live techniques, {len(model['tactics'])} tactics)")
    print(f"Pinned in tools/config.py as ATTACK_VERSION = {config.ATTACK_VERSION!r}")
    print(f"Detections: {len(detections)}\n")

    errors: list[str] = []
    warnings: list[str] = []
    technique_use: dict[str, list[str]] = {}

    for detection in detections:
        where = detection["_rel_path"]

        if str(detection["attack_version"]) != str(model["version"]):
            errors.append(
                f"{where}: attack_version is {detection['attack_version']!r} but the "
                f"pinned bundle is v{model['version']}"
            )

        for technique_id in detection["techniques"]:
            technique_use.setdefault(technique_id, []).append(where)

            if technique_id in model["revoked"]:
                replacement = model["revoked"][technique_id] or "(none recorded)"
                errors.append(
                    f"{where}: {technique_id} is REVOKED in v{model['version']} "
                    f"-> replaced by {replacement}"
                )
            elif technique_id in model["deprecated"]:
                errors.append(
                    f"{where}: {technique_id} is DEPRECATED in v{model['version']}"
                )
            elif technique_id not in model["techniques"]:
                errors.append(
                    f"{where}: {technique_id} does not exist in v{model['version']}"
                )

        if not detection["_tactics"]:
            errors.append(
                f"{where}: no tactic could be derived from {detection['techniques']}"
            )

        folder = detection["_folder"]
        derived = {t["shortname"].replace("-", "_") for t in detection["_tactics"]}
        if folder not in derived:
            warnings.append(
                f"{where}: directory {folder!r} is not among the tactics derived from "
                f"STIX ({', '.join(sorted(derived))}). The directory is only a label; "
                "coverage uses the derived tactics."
            )

    # ---- report ----
    print("Technique usage:")
    for technique_id in sorted(technique_use):
        technique = model["techniques"].get(technique_id)
        name = technique["name"] if technique else "???"
        tactics = ", ".join(
            model["tactics"][s]["name"] for s in (technique["tactics"] if technique else [])
            if s in model["tactics"]
        )
        print(f"  {technique_id:12s} {name[:42]:44s} [{tactics}]")

    tactics_covered = sorted({
        tactic["name"] for detection in detections for tactic in detection["_tactics"]
    })
    print(f"\nTactics covered ({len(tactics_covered)}): {', '.join(tactics_covered)}")

    if warnings:
        print(f"\n{len(warnings)} warning(s):")
        for warning in warnings:
            print(f"  WARN  {warning}")

    if errors:
        print(f"\n{len(errors)} ERROR(S):")
        for error in errors:
            print(f"  FAIL  {error}")
        print("\nvalidate-attack FAILED")
        return 1

    print(f"\nvalidate-attack PASSED: all {len(technique_use)} technique IDs are current "
          f"in ATT&CK v{model['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
