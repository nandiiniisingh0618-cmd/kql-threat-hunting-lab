"""Extract the pinned archives and ingest them into Kusto.

Design: every event lands verbatim in a single dynamic column `raw`, tagged with
`dataset_id` and `source_file`. Typed, stable columns are produced later by the KQL
stored functions in kql/functions/ -- detections never read `raw` directly.

A named ingestion mapping is MANDATORY. Without one, Kusto maps JSON fields to
columns by name; since no incoming field is called `raw`, you get the correct row
count with every column silently NULL and no error reported.
"""
from __future__ import annotations

import argparse
import json
import sys
import tarfile
import zipfile
from pathlib import Path

from . import config
from .kusto import KustoClient, KustoError

CONTAINER_DATA_DIR = "/data"


def extract_archive(archive: Path, target_dir: Path) -> list[Path]:
    """Extract one archive, returning the JSON event files it contained."""
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []

    def _safe(name: str) -> bool:
        # Treat archive contents as untrusted: no absolute paths, no traversal.
        candidate = Path(name)
        return not candidate.is_absolute() and ".." not in candidate.parts

    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as handle:
            for name in handle.namelist():
                if name.endswith("/") or not _safe(name):
                    continue
                out = target_dir / Path(name).name
                out.write_bytes(handle.read(name))
                extracted.append(out)
    elif archive.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle.getmembers():
                if not member.isfile() or not _safe(member.name):
                    continue
                source = handle.extractfile(member)
                if source is None:
                    continue
                out = target_dir / Path(member.name).name
                out.write_bytes(source.read())
                extracted.append(out)
    else:
        raise ValueError(f"unsupported archive type: {archive.name}")

    return [p for p in extracted if p.suffix.lower() == ".json"]


def apply_kql_dir(client: KustoClient, directory: Path) -> int:
    """Run every .kql file in a directory, in filename order.

    Files are split on lines that contain only `//---` so one file can hold several
    commands.
    """
    applied = 0
    for path in sorted(directory.glob("*.kql")):
        text = path.read_text(encoding="utf-8")
        for chunk in text.split("//---"):
            # Kusto requires an admin command to begin with '.' as the first
            # non-whitespace character, so leading comment lines must go.
            # Comments *inside* the command body are fine and are preserved.
            lines = chunk.splitlines()
            while lines and (not lines[0].strip() or lines[0].strip().startswith("//")):
                lines.pop(0)
            body = "\n".join(lines).strip()
            if not body:
                continue
            client.mgmt(body)
            applied += 1
        print(f"  applied {path.name}")
    return applied


def ensure_database(client: KustoClient) -> None:
    """Create the lab database on the emulator if a fresh container lacks it.

    Only attempted for the no-auth emulator target. On a real ADX cluster the
    database is created once in the portal (see docs/setup-free-cluster.md).
    """
    if config.auth_mode() != "none":
        return
    bootstrap = KustoClient(database="NetDefaultDB")
    existing = [row[0] for row in bootstrap.mgmt(".show databases | project DatabaseName").rows]
    if client.database in existing:
        return
    name = client.database
    print(f"creating database {name} on the emulator ...")
    bootstrap.mgmt(
        f'.create database {name} persist '
        f'( @"/kustodata/dbs/{name}/md", @"/kustodata/dbs/{name}/data" )'
    )
    print(f"  database {name} created")


def ensure_schema(client: KustoClient) -> None:
    print("Applying schema (kql/schema/):")
    apply_kql_dir(client, config.KQL_DIR / "schema")
    print("Applying normalization functions (kql/functions/):")
    apply_kql_dir(client, config.KQL_DIR / "functions")


def mapping_for(dataset_id: str, source_file: str) -> str:
    mapping = [
        {"column": "raw", "datatype": "dynamic", "Properties": {"Path": "$"}},
        {"column": "dataset_id", "datatype": "string",
         "Properties": {"ConstValue": dataset_id}},
        {"column": "source_file", "datatype": "string",
         "Properties": {"ConstValue": source_file}},
    ]
    return json.dumps(mapping)


def ingest_file(client: KustoClient, dataset_id: str, json_path: Path) -> int:
    """Ingest one JSON-lines file, returning rows added."""
    mapping_name = f"map_{dataset_id.replace('-', '_')}"
    container_path = f"{CONTAINER_DATA_DIR}/{json_path.parent.name}/{json_path.name}"

    # create-or-alter: .create alone fails with BadRequest if the mapping exists,
    # which would make `make ingest` non-idempotent.
    client.mgmt(
        f".create-or-alter table {config.RAW_TABLE} ingestion json mapping "
        f"'{mapping_name}' @'{mapping_for(dataset_id, json_path.stem)}'"
    )
    before = client.row_count(config.RAW_TABLE)
    client.mgmt(
        f'.ingest into table {config.RAW_TABLE} (@"{container_path}") '
        f'with (format="multijson", ingestionMappingReference="{mapping_name}")'
    )
    return client.row_count(config.RAW_TABLE) - before


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest pinned datasets into Kusto.")
    parser.add_argument("--only", help="ingest a single dataset_id")
    parser.add_argument("--reset", action="store_true",
                        help="drop and recreate the raw table first")
    parser.add_argument("--schema-only", action="store_true",
                        help="apply schema and functions, ingest nothing")
    args = parser.parse_args(argv)

    manifest_path = config.DATA_DIR / "MANIFEST.json"
    if not manifest_path.exists():
        sys.exit("data/MANIFEST.json missing -- run `make data` (or `python tasks.py data`) first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    client = KustoClient()
    try:
        probe = KustoClient(database="NetDefaultDB") if config.auth_mode() == "none" else client
        print(f"Kusto   : {client.uri} (db={client.database})")
        print(f"Engine  : {probe.engine_version()}\n")
    except KustoError as exc:
        sys.exit(f"{exc}")

    ensure_database(client)

    if args.reset:
        print(f"Dropping {config.RAW_TABLE} ...")
        client.mgmt(f".drop table {config.RAW_TABLE} ifexists")

    ensure_schema(client)
    if args.schema_only:
        print("\nSchema and functions applied; skipping ingestion (--schema-only).")
        return 0

    datasets = manifest["datasets"]
    if args.only:
        datasets = [d for d in datasets if d["dataset_id"] == args.only]
        if not datasets:
            sys.exit(f"dataset_id {args.only!r} not in MANIFEST.json")

    print(f"\nIngesting {len(datasets)} datasets:")
    already = (
        set(client.query(f"{config.RAW_TABLE} | distinct dataset_id").column("dataset_id"))
        if client.table_exists(config.RAW_TABLE)
        else set()
    )

    total_rows = 0
    skipped = 0
    problems: list[str] = []

    for index, entry in enumerate(datasets, start=1):
        dataset_id = entry["dataset_id"]
        if dataset_id in already and not args.reset:
            print(f"[{index:3d}/{len(datasets)}] {dataset_id:22s} already ingested, skipping")
            skipped += 1
            continue

        archive = config.DATA_DIR / "archives" / entry["file"]
        if not archive.exists():
            problems.append(f"{dataset_id}: archive missing ({entry['file']})")
            continue

        target = config.EXTRACT_DIR / dataset_id
        try:
            json_files = extract_archive(archive, target)
        except (zipfile.BadZipFile, tarfile.TarError, ValueError) as exc:
            problems.append(f"{dataset_id}: extract failed: {exc}")
            continue

        if not json_files:
            problems.append(f"{dataset_id}: archive contained no .json event file")
            continue

        rows_here = 0
        for json_path in json_files:
            try:
                rows_here += ingest_file(client, dataset_id, json_path)
            except KustoError as exc:
                problems.append(f"{dataset_id}/{json_path.name}: {exc}")
        total_rows += rows_here
        print(f"[{index:3d}/{len(datasets)}] {dataset_id:22s} {rows_here:7,d} events  "
              f"({len(json_files)} file(s))")

    print(f"\nIngested {total_rows:,} events; {skipped} dataset(s) already present.")
    print(f"{config.RAW_TABLE} now holds {client.row_count(config.RAW_TABLE):,} rows.")

    if problems:
        print("\nPROBLEMS:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
