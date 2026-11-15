#!/usr/bin/env python3
"""Cross-platform task runner. Works on Windows without make.

    python tasks.py up              start the local Kusto emulator (localhost only)
    python tasks.py data            download pinned datasets, verify SHA-256
    python tasks.py ingest          apply schema + functions, ingest datasets
    python tasks.py test            run the pytest detection harness
    python tasks.py validate-attack validate technique IDs against pinned ATT&CK
    python tasks.py coverage        generate ATT&CK layer, COVERAGE.md, GAPS.md
    python tasks.py export-sentinel export detections as Sentinel analytics rules
    python tasks.py docs            regenerate docs/HOW_IT_WORKS.md
    python tasks.py all             data + ingest + test + validate + coverage + docs
    python tasks.py down            stop and remove the emulator container
    python tasks.py status          show emulator / table / detection status
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from tools import config

IMAGE = "mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest"
CONTAINER = "kustainer-kqllab"


def run(cmd: list[str], **kwargs) -> int:
    print("$ " + " ".join(cmd))
    return subprocess.call(cmd, **kwargs)


def python_module(module: str, *args: str) -> int:
    return run([sys.executable, "-m", module, *args])


def _docker() -> str:
    exe = shutil.which("docker")
    if not exe:
        sys.exit(
            "docker not found on PATH.\n"
            "  Windows/macOS: install Docker Desktop and make sure it is running.\n"
            "  The emulator needs x86_64 Linux containers (there is no arm64 image)."
        )
    return exe


def task_up() -> int:
    docker = _docker()
    if subprocess.call([docker, "info"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
        sys.exit("the Docker daemon is not responding. Start Docker Desktop and retry.")

    existing = subprocess.run(
        [docker, "ps", "-aq", "-f", f"name=^{CONTAINER}$"],
        capture_output=True, text=True,
    ).stdout.strip()
    if existing:
        running = subprocess.run(
            [docker, "ps", "-q", "-f", f"name=^{CONTAINER}$"],
            capture_output=True, text=True,
        ).stdout.strip()
        if running:
            print(f"{CONTAINER} is already running.")
            return 0
        print(f"starting existing container {CONTAINER} ...")
        code = run([docker, "start", CONTAINER])
        if code != 0:
            return code
        return _wait_ready()

    mount = config.EXTRACT_DIR
    mount.mkdir(parents=True, exist_ok=True)
    port = config.kustainer_port()
    # 127.0.0.1 binding is deliberate: the emulator has no auth and no TLS.
    code = run([
        docker, "run", "-d",
        "--name", CONTAINER,
        "-m", config.kustainer_memory(),
        "-p", f"127.0.0.1:{port}:8080",
        "-v", f"{mount.as_posix()}:/data:ro",
        "-e", "ACCEPT_EULA=Y",
        IMAGE,
    ])
    if code != 0:
        return code

    return _wait_ready()


def _wait_ready(attempts: int = 90) -> int:
    """Block until the engine answers a management command.

    The container reports "running" well before the engine accepts queries, and a
    request sent in that window is reset by the peer -- so `up` must wait here or
    the very next `ingest` fails with a transport error.
    """
    import time

    from tools.kusto import KustoClient

    # Probe the always-present default database: the lab database may not exist yet.
    probe = KustoClient(database="NetDefaultDB") if config.auth_mode() == "none" else KustoClient()
    print("waiting for the engine to accept queries ...")
    for attempt in range(1, attempts + 1):
        if probe.is_reachable():
            print(f"ready after ~{attempt * 2}s -- engine {probe.engine_version()}")
            print(f"emulator listening on http://127.0.0.1:{config.kustainer_port()} "
                  "(localhost only)")
            return 0
        time.sleep(2)
    print(f"engine did not become ready in {attempts * 2}s. Check: docker logs {CONTAINER}")
    return 1


def task_down() -> int:
    docker = _docker()
    run([docker, "rm", "-f", CONTAINER])
    return 0


def task_status() -> int:
    from tools.kusto import KustoClient, KustoError
    from tools.registry import load_detections

    client = KustoClient()
    print(f"Kusto URI : {client.uri}")
    print(f"Database  : {client.database}")
    try:
        print(f"Engine    : {client.engine_version()}")
        reachable = True
    except KustoError as exc:
        print(f"Engine    : UNREACHABLE ({exc})")
        reachable = False

    manifest = config.DATA_DIR / "MANIFEST.json"
    print(f"Manifest  : {'present' if manifest.exists() else 'missing (run: data)'}")

    if reachable and client.table_exists(config.RAW_TABLE):
        rows = client.row_count(config.RAW_TABLE)
        datasets = client.query(f"{config.RAW_TABLE} | summarize dcount(dataset_id)").scalar()
        print(f"RawEvents : {rows:,} rows across {datasets} dataset(s)")
    elif reachable:
        print("RawEvents : table missing (run: ingest)")

    detections = load_detections()
    validated = [d for d in detections if d.get("status") != "experimental"]
    print(f"Detections: {len(detections)} total, {len(validated)} validated, "
          f"{len(detections) - len(validated)} experimental")
    return 0


def task_all() -> int:
    for task in ("data", "ingest", "validate-attack", "test", "coverage", "docs"):
        code = TASKS[task]()
        if code != 0:
            print(f"\n'{task}' failed with exit code {code}; stopping.")
            return code
    return 0


TASKS = {
    "up": task_up,
    "down": task_down,
    "status": task_status,
    "data": lambda: python_module("tools.fetch_data"),
    "ingest": lambda: python_module("tools.ingest"),
    "test": lambda: run([sys.executable, "-m", "pytest", "-q", "tests"]),
    "validate-attack": lambda: python_module("tools.validate_attack"),
    "coverage": lambda: python_module("tools.make_layer"),
    "export-sentinel": lambda: python_module("tools.export_sentinel"),
    "docs": lambda: python_module("tools.make_docs"),
    "all": task_all,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    name = sys.argv[1]
    if name not in TASKS:
        print(f"unknown task {name!r}\n")
        print(__doc__)
        return 2
    extra = sys.argv[2:]
    if extra and name in ("data", "ingest", "test", "validate-attack", "coverage",
                          "export-sentinel", "docs"):
        module_map = {
            "data": "tools.fetch_data", "ingest": "tools.ingest",
            "validate-attack": "tools.validate_attack", "coverage": "tools.make_layer",
            "export-sentinel": "tools.export_sentinel", "docs": "tools.make_docs",
        }
        if name == "test":
            return run([sys.executable, "-m", "pytest", *extra])
        return python_module(module_map[name], *extra)
    return TASKS[name]()


if __name__ == "__main__":
    raise SystemExit(main())
