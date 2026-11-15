# Setup on Windows (Core i5 / x86_64)

This is the primary supported path. Everything runs locally; no Azure account needed.

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| **Docker Desktop** with the WSL 2 backend, running | hosts the Kusto emulator | `docker version` |
| **Linux containers** mode (the default) | the emulator image is Linux-only | Docker Desktop tray → should NOT say "Switch to Linux containers" |
| **x86_64 CPU** | there is **no arm64 emulator image** (verified: the `:latest` manifest lists only `linux/amd64`) | a Core i5 is fine |
| **~6 GB free RAM** | 4 GB is allocated to the emulator container | Task Manager |
| **~10 GB free disk** | the emulator image alone is 4.45 GB | — |
| **Python 3.11+** | tooling | `python --version` |
| **Git** | cloning | `git --version` |

`make` is **not** required. Every target has an identical `python tasks.py` equivalent.

## First run

```powershell
git clone <your-fork-url> kql-threat-hunting-lab
```

```powershell
cd kql-threat-hunting-lab
```

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

```powershell
pip install -r requirements.txt
```

```powershell
copy .env.example .env
```

Then the pipeline — about 10 minutes end to end, most of it the image pull:

```powershell
python tasks.py up
```

```powershell
python tasks.py data
```

```powershell
python tasks.py ingest
```

```powershell
python tasks.py test
```

```powershell
python tasks.py validate-attack
```

```powershell
python tasks.py coverage
```

Or all of it after `up`:

```powershell
python tasks.py all
```

## What each step does

| Step | Time | Effect |
|---|---|---|
| `up` | 5–10 min first time | pulls `kustainer-linux` (4.45 GB), starts it bound to **127.0.0.1 only**, waits for the engine to accept queries |
| `data` | ~1 min | downloads 39 archives (~30.5 MB) at a pinned commit, verifies SHA-256, writes `data/MANIFEST.json` |
| `ingest` | ~2 min | creates the database, applies schema + 26 normalization functions, extracts and ingests ~421k events |
| `test` | ~5 s | runs 24 detections against the whole corpus, asserts true positives and entities, writes `RESULTS.md` |
| `validate-attack` | ~20 s first time | downloads the pinned ATT&CK v20.1 STIX bundle (53 MB), fails on any revoked/missing technique ID |
| `coverage` | ~2 s | writes `coverage/attack-layer.json`, `COVERAGE.md`, `GAPS.md` from test results |

## Security note on the emulator

The Kusto emulator has **no authentication and no TLS**. `tasks.py up` therefore publishes
it as `-p 127.0.0.1:8080:8080`, which binds to loopback only — it is not reachable from
your network. Do not change that to `-p 8080:8080`.

## Troubleshooting

**`docker not found on PATH`** — Docker Desktop is not installed, or its CLI integration
is off. Settings → Resources → WSL Integration.

**`the Docker daemon is not responding`** — Docker Desktop is installed but not started.
Launch it and wait for the whale icon to stop animating.

**`transport error ... Connection reset by peer` right after `up`** — the container is
running but the engine is still starting. `tasks.py up` waits for readiness, so this
should not happen; if it does, wait 30 seconds and re-run `python tasks.py ingest`.

**`cannot reach Kusto at http://127.0.0.1:8080`** — check `docker ps`. If the container
exited, inspect `docker logs kustainer-kqllab`. The most common cause is insufficient
memory; raise `KUSTAINER_MEMORY` in `.env` or give Docker Desktop more RAM.

**`no space left on device`** — the emulator image is 4.45 GB and extracted data another
~150 MB. Free space, or run `docker system prune`.

**A test fails after you edit a detection** — that is the harness doing its job. Read the
assertion: it names the dataset, the expected hits and what it actually saw. Run
`python tasks.py status` to confirm data is loaded.

**Line endings** — not an issue. Verified: the `.kql` files were converted to CRLF and
applied through the normal `ingest` code path, and all 29 commands were accepted with the
functions working afterwards. Kusto tolerates `\r`, so Git's `autocrlf` default on Windows
is fine and needs no change.

## Shutting down

```powershell
python tasks.py down
```

The container is removed; downloaded archives under `data/archives/` are kept, so the
next `up` + `ingest` is fast. To reclaim the 4.45 GB image as well:

```powershell
docker rmi mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
```
