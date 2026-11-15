"""Load and validate detection YAML files and the ATT&CK STIX bundle.

Tactics are NEVER read from a detection file: they are derived from the pinned
ATT&CK bundle using the technique IDs. That keeps a stale hand-typed tactic from
ever reaching the coverage pages.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import config

REQUIRED_FIELDS = (
    "id", "name", "description", "severity", "status", "attack_version",
    "techniques", "data_sources", "query", "entity_mappings",
    "false_positives", "tuning_notes", "known_blind_spots", "references", "tests",
)


# --------------------------------------------------------------------------- #
# ATT&CK
# --------------------------------------------------------------------------- #

def stix_path() -> Path:
    return config.STIX_DIR / f"enterprise-attack-{config.ATTACK_VERSION}.json"


def ensure_stix(quiet: bool = False) -> Path:
    """Download the pinned STIX bundle once; it is gitignored, never committed."""
    path = stix_path()
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    url = config.ATTACK_STIX_URL.format(v=config.ATTACK_VERSION)
    if not quiet:
        print(f"downloading ATT&CK v{config.ATTACK_VERSION} STIX bundle ...")
    request = urllib.request.Request(url, headers={"User-Agent": "kql-threat-hunting-lab"})
    with urllib.request.urlopen(request, timeout=600) as response:
        path.write_bytes(response.read())
    if not quiet:
        print(f"  saved {path.name} ({path.stat().st_size/1048576:.1f} MB)")
    return path


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


@lru_cache(maxsize=1)
def attack_model() -> dict[str, Any]:
    """Parse the STIX bundle into the few lookups this repo needs.

    Deliberately stdlib-only: `mitreattack-python` is excellent but heavy, and the
    only things needed here are technique validity, tactic mapping and revocations.
    """
    path = ensure_stix(quiet=True)
    objects = json.loads(path.read_text(encoding="utf-8"))["objects"]

    tactics: dict[str, dict[str, str]] = {}
    techniques: dict[str, dict[str, Any]] = {}
    revoked: dict[str, str] = {}
    deprecated: set[str] = set()
    stix_id_to_attack_id: dict[str, str] = {}
    collection_version = config.ATTACK_VERSION

    for obj in objects:
        kind = obj.get("type")
        if kind == "x-mitre-collection":
            collection_version = obj.get("x_mitre_version", collection_version)
        elif kind == "x-mitre-tactic":
            tactic_id = _external_id(obj)
            if tactic_id:
                tactics[obj["x_mitre_shortname"]] = {
                    "id": tactic_id,
                    "name": obj["name"],
                    "shortname": obj["x_mitre_shortname"],
                }
        elif kind == "attack-pattern":
            attack_id = _external_id(obj)
            if not attack_id:
                continue
            stix_id_to_attack_id[obj["id"]] = attack_id
            if obj.get("revoked"):
                revoked[attack_id] = ""
                continue
            if obj.get("x_mitre_deprecated"):
                deprecated.add(attack_id)
                continue
            techniques[attack_id] = {
                "id": attack_id,
                "name": obj["name"],
                "tactics": [
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase["kill_chain_name"] == "mitre-attack"
                ],
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "url": next(
                    (r.get("url") for r in obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), ""
                ),
            }

    # Resolve "this ID was replaced by that ID".
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            src = stix_id_to_attack_id.get(obj.get("source_ref", ""))
            dst = stix_id_to_attack_id.get(obj.get("target_ref", ""))
            if src in revoked and dst:
                revoked[src] = dst

    return {
        "version": collection_version,
        "tactics": tactics,
        "techniques": techniques,
        "revoked": revoked,
        "deprecated": deprecated,
    }


def tactics_for(technique_ids: list[str]) -> list[dict[str, str]]:
    """Derive tactic objects for a set of technique IDs, in ATT&CK matrix order."""
    model = attack_model()
    shortnames: list[str] = []
    for technique_id in technique_ids:
        technique = model["techniques"].get(technique_id)
        if not technique:
            continue
        for shortname in technique["tactics"]:
            if shortname not in shortnames:
                shortnames.append(shortname)
    order = list(model["tactics"].keys())
    shortnames.sort(key=lambda s: order.index(s) if s in order else 999)
    return [model["tactics"][s] for s in shortnames if s in model["tactics"]]


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=1)
def load_detections() -> tuple[dict[str, Any], ...]:
    detections: list[dict[str, Any]] = []
    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}

    for path in sorted(config.DETECTIONS_DIR.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            sys.exit(f"{path}: not a YAML mapping")

        missing = [f for f in REQUIRED_FIELDS if f not in data]
        if missing:
            sys.exit(f"{path}: missing required field(s): {', '.join(missing)}")

        if data["id"] in seen_ids:
            sys.exit(f"{path}: duplicate id {data['id']} (also in {seen_ids[data['id']]})")
        seen_ids[data["id"]] = str(path)
        if data["name"] in seen_names:
            sys.exit(f"{path}: duplicate name {data['name']!r}")
        seen_names[data["name"]] = str(path)

        data["_path"] = path
        data["_rel_path"] = path.relative_to(config.REPO_ROOT).as_posix()
        # The directory is a label for humans; the real tactics come from STIX.
        data["_folder"] = path.parent.name
        data["_tactics"] = tactics_for(data["techniques"])
        detections.append(data)

    return tuple(detections)


def detection_by_id(detection_id: str) -> dict[str, Any] | None:
    for detection in load_detections():
        if detection["id"] == detection_id:
            return detection
    return None
