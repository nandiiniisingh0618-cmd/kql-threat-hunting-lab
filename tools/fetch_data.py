"""Download the pinned datasets, verify SHA-256, write data/MANIFEST.json.

Raw data is never committed. This script is the only thing that touches the network
for datasets, and it refuses to proceed on a hash mismatch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

from . import config


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_registry() -> dict:
    registry_path = config.DATA_DIR / "sources.yml"
    if not registry_path.exists():
        sys.exit(f"missing {registry_path}")
    return yaml.safe_load(registry_path.read_text(encoding="utf-8"))


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "kql-threat-hunting-lab"})
    with urllib.request.urlopen(request, timeout=300) as response:
        dest.write_bytes(response.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch pinned lab datasets.")
    parser.add_argument("--force", action="store_true", help="re-download even if present")
    args = parser.parse_args(argv)

    registry = load_registry()
    source = registry["source"]
    template = source["raw_url_template"]
    commit = source["pinned_commit"]
    datasets = registry["datasets"]

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    manifest_entries = []
    failures: list[tuple[str, str]] = []
    total_bytes = 0

    print(f"Source       : {source['name']}")
    print(f"Pinned commit: {commit} ({source['pinned_commit_date']})")
    print(f"Datasets     : {len(datasets)}\n")

    for index, entry in enumerate(datasets, start=1):
        dataset_id = entry["dataset_id"]
        dest = config.DATA_DIR / "archives" / entry["file"]
        url = template.format(commit=commit, path=entry["repo_path"])

        if dest.exists() and not args.force:
            status = "cached"
        else:
            try:
                download(url, dest)
                status = "downloaded"
            except (urllib.error.URLError, urllib.error.HTTPError) as exc:
                failures.append((dataset_id, f"download failed: {exc}"))
                print(f"[{index:3d}/{len(datasets)}] {dataset_id:22s} FAILED  {exc}")
                continue

        actual = sha256_file(dest)
        if actual != entry["sha256"]:
            failures.append(
                (dataset_id, f"SHA-256 mismatch\n    expected {entry['sha256']}\n    actual   {actual}")
            )
            print(f"[{index:3d}/{len(datasets)}] {dataset_id:22s} HASH MISMATCH")
            continue

        total_bytes += dest.stat().st_size
        manifest_entries.append(
            {
                "dataset_id": dataset_id,
                "title": entry["title"],
                "kind": entry["kind"],
                "file": entry["file"],
                "sha256": actual,
                "bytes": dest.stat().st_size,
                "source_url": url,
                "techniques_meta": entry.get("techniques_meta", []),
                "verified": True,
            }
        )
        print(f"[{index:3d}/{len(datasets)}] {dataset_id:22s} {status:10s} "
              f"{dest.stat().st_size/1048576:6.2f} MB  sha256 ok")

    manifest = {
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "name": source["name"],
            "repo": source["repo"],
            "pinned_commit": commit,
            "pinned_commit_date": str(source["pinned_commit_date"]),
            "licence_note": source["licence_note"].strip(),
        },
        "redistributed": False,
        "dataset_count": len(manifest_entries),
        "total_bytes": total_bytes,
        "datasets": manifest_entries,
    }
    manifest_path = config.DATA_DIR / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\nVerified {len(manifest_entries)}/{len(datasets)} datasets "
          f"({total_bytes/1048576:.1f} MB). Wrote {manifest_path.relative_to(config.REPO_ROOT)}")

    if failures:
        print("\nFAILURES:")
        for dataset_id, reason in failures:
            print(f"  {dataset_id}: {reason}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
