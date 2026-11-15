"""Export each detection as a Microsoft Sentinel analytics-rule YAML file.

The detection format in detections/ was modelled on Sentinel's scheduled-rule schema
precisely so this is a transform rather than a rewrite.

IMPORTANT: the exported rules are UNTESTED. They are not deployed or validated
against a live workspace by this repo, and their queries reference THIS LAB's
normalization functions, which do not exist in a Sentinel workspace. Read
docs/sentinel-export.md before attempting to deploy anything.
"""
from __future__ import annotations

import sys

from . import config
from .registry import attack_model, load_detections

OUT_DIR = config.REPO_ROOT / "export" / "sentinel"

# Sentinel expects tactic names in PascalCase with no spaces.
#
# UNVERIFIED COMPATIBILITY RISK: ATT&CK v20.1 renamed TA0005 "Defense Evasion" to
# "Stealth" and added TA0112 "Defense Impairment". Sentinel's analytics-rule schema
# carries a fixed tactic enum, and at the time of writing it could not be checked
# (learn.microsoft.com was unreachable from the build environment), so it may still
# expect the legacy "DefenseEvasion" and reject the new names. If a rule is rejected
# on upload, substitute the legacy name below and re-export. The v20.1 name is always
# recorded in the rule's metadata.attackTactics so nothing is lost.
LEGACY_TACTIC_EQUIVALENT = {
    "Stealth": "DefenseEvasion",
    "DefenseImpairment": "DefenseEvasion",
}
def pascal(name: str) -> str:
    return "".join(part for part in name.replace("-", " ").split())


def yaml_quote(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def block(text: str, indent: str = "    ") -> list[str]:
    return [indent + line if line.strip() else "" for line in text.splitlines()]


def main(argv: list[str] | None = None) -> int:
    argv = argv or []
    model = attack_model()
    detections = load_detections()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    severity_map = {"Informational": "Informational", "Low": "Low",
                    "Medium": "Medium", "High": "High"}
    entity_map = {"Host": ("Host", "HostName"), "Account": ("Account", "FullName"),
                  "Process": ("Process", "CommandLine"), "IP": ("IP", "Address"),
                  "RegistryKey": ("RegistryKey", "Key")}

    written = []
    for detection in detections:
        tactics = sorted({pascal(t["name"]) for t in detection["_tactics"]})
        # Sentinel wants sub-technique parents listed too.
        techniques = sorted({t.split(".")[0] for t in detection["techniques"]})
        sub_techniques = sorted(t for t in detection["techniques"] if "." in t)

        lines: list[str] = []
        lines.append(f"id: {detection['id']}")
        lines.append(f"name: {yaml_quote(detection['name'])}")
        lines.append("description: |")
        lines.extend(block(detection["description"].strip()))
        lines.append(f"severity: {severity_map.get(detection['severity'], 'Medium')}")
        lines.append("status: Available")
        lines.append("requiredDataConnectors:")
        lines.append("  - connectorId: SecurityEvents")
        lines.append("    dataTypes:")
        lines.append("      - SecurityEvent")
        lines.append("  - connectorId: WindowsForwardedEvents")
        lines.append("    dataTypes:")
        lines.append("      - WindowsEvent")
        lines.append("queryFrequency: 1h")
        lines.append("queryPeriod: 1h")
        lines.append("triggerOperator: gt")
        lines.append("triggerThreshold: 0")
        lines.append("tactics:")
        for tactic in tactics:
            lines.append(f"  - {tactic}")
            if tactic in LEGACY_TACTIC_EQUIVALENT:
                lines.append(f"  # if rejected on upload, use: "
                             f"{LEGACY_TACTIC_EQUIVALENT[tactic]} (pre-v19 name)")
        lines.append("relevantTechniques:")
        for technique in techniques:
            lines.append(f"  - {technique}")
        if sub_techniques:
            lines.append("subTechniques:")
            for technique in sub_techniques:
                lines.append(f"  - {technique}")
        lines.append("query: |")
        lines.extend(block(detection["query"].strip()))
        lines.append("entityMappings:")
        for mapping in detection["entity_mappings"]:
            kind, identifier = entity_map.get(
                mapping["entity_type"], (mapping["entity_type"], "Name")
            )
            lines.append(f"  - entityType: {kind}")
            lines.append("    fieldMappings:")
            lines.append(f"      - identifier: {identifier}")
            lines.append(f"        columnName: {mapping['identifier']}")
        lines.append("incidentConfiguration:")
        lines.append("  createIncident: true")
        lines.append("  groupingConfiguration:")
        lines.append("    enabled: true")
        lines.append("    reopenClosedIncident: false")
        lines.append("    lookbackDuration: PT5H")
        lines.append("    matchingMethod: AllEntities")
        lines.append("version: 1.0.0")
        lines.append("kind: Scheduled")
        lines.append("metadata:")
        lines.append(f"  attackVersion: {yaml_quote(model['version'])}")
        lines.append(f"  attackTactics: {yaml_quote(', '.join(t['name'] for t in detection['_tactics']))}")
        lines.append(f"  sourceRule: {yaml_quote(detection['_rel_path'])}")
        lines.append("  validation: >-")
        lines.append("    UNTESTED IN A LIVE WORKSPACE. Generated by tools/export_sentinel.py")
        lines.append("    from a rule validated only against the local Kusto emulator and the")
        lines.append("    pinned public datasets. The query references this lab's normalization")
        lines.append("    functions, which do NOT exist in a Sentinel workspace: see")
        lines.append("    docs/schema-mapping.md for the table and parser each one maps to.")
        lines.append("falsePositives:")
        for item in detection["false_positives"]:
            lines.append(f"  - {yaml_quote(item)}")
        lines.append("knownBlindSpots:")
        for item in detection["known_blind_spots"]:
            lines.append(f"  - {yaml_quote(item)}")

        slug = detection["_path"].stem
        out = OUT_DIR / f"{slug}.yaml"
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(out)

    readme = OUT_DIR / "README.md"
    readme.write_text(
        "# Sentinel analytics-rule export\n"
        "\n"
        "**Generated** by `make export-sentinel` -- do not edit by hand.\n"
        "\n"
        "## These rules are UNTESTED\n"
        "\n"
        "Nothing here has been deployed to a live Microsoft Sentinel workspace by this\n"
        "repository, and the author makes no claim that it works there. Two concrete\n"
        "reasons they will NOT run as-is:\n"
        "\n"
        "1. **The queries call this lab's normalization functions** "
        "(`SysmonProcessCreate()`, `SecurityLogon()`, ...). Those are stored functions in\n"
        "   the lab database and do not exist in a Sentinel workspace. Each one maps to a\n"
        "   Sentinel-native table or ASIM parser -- see `docs/schema-mapping.md`.\n"
        "2. **`DatasetId` has no meaning in production.** It is a lab provenance column\n"
        "   used by the test harness to attribute hits, and every rule projects it.\n"
        "\n"
        "Treat these files as a faithful structural translation of the rule logic, not as\n"
        "deployable content. See `docs/sentinel-export.md` for what porting actually\n"
        "involves.\n"
        "\n"
        "## Tactic-name compatibility (unverified)\n"
        "\n"
        "ATT&CK v20.1 renamed TA0005 `Defense Evasion` to **Stealth** and added TA0112\n"
        "**Defense Impairment**. Sentinel validates `tactics:` against a fixed enum, and\n"
        "that enum could NOT be checked when this repo was built, so the new names may be\n"
        "rejected on upload. Where a rule uses one, the export emits the v20.1 name and\n"
        "adds an inline comment naming the legacy `DefenseEvasion` fallback. The full\n"
        "v20.1 tactic list is preserved in each rule's `metadata.attackTactics`.\n"
        f"\nExported {len(written)} rules against ATT&CK v{model['version']}. "
        "Regenerate with `make export-sentinel`.\n",
        encoding="utf-8",
    )

    print(f"wrote {len(written)} Sentinel rule(s) to export/sentinel/")
    print("  all are labelled UNTESTED: see export/sentinel/README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
