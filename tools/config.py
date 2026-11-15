"""Environment-driven configuration. The same code runs against either target."""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
EXTRACT_DIR = DATA_DIR / "extracted"
STIX_DIR = REPO_ROOT / "attack-stix"
COVERAGE_DIR = REPO_ROOT / "coverage"
DETECTIONS_DIR = REPO_ROOT / "detections"
KQL_DIR = REPO_ROOT / "kql"

# Pinned ATT&CK release. Bump deliberately, never implicitly.
ATTACK_VERSION = "20.1"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-{v}.json"
)

RAW_TABLE = "RawEvents"


def _load_dotenv() -> None:
    """Minimal .env loader; real environment variables always win."""
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()


def kusto_uri() -> str:
    return os.environ.get("KUSTO_URI", "http://127.0.0.1:8080")


def kusto_db() -> str:
    return os.environ.get("KUSTO_DB", "KqlLab")


def auth_mode() -> str:
    return os.environ.get("KUSTO_AUTH_MODE", "none").lower()


def kustainer_port() -> str:
    return os.environ.get("KUSTAINER_PORT", "8080")


def kustainer_memory() -> str:
    return os.environ.get("KUSTAINER_MEMORY", "4g")


def include_attack_data() -> bool:
    return os.environ.get("INCLUDE_ATTACK_DATA", "0") not in ("0", "", "false", "False")
