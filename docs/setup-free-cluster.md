# Setup on an Azure Data Explorer free cluster (fallback)

Use this only if you cannot run the emulator — most commonly on **ARM hardware**
(Apple Silicon, Snapdragon), since there is no arm64 emulator image.

> **These steps are UNVERIFIED.** They could not be checked while this repo was built:
> `dataexplorer.azure.com` and `learn.microsoft.com` were unreachable from the build
> environment. Treat the portal navigation below as a sketch, confirm the current quota
> and terms yourself, and expect names to have moved. The *code* path is real and
> tested — only the portal walkthrough is unverified.

## What you need to check first

Before ingesting anything, read the current terms and quota in the ADX web UI:

1. **The quota table** — a free cluster has fixed storage and a cap on hot-cache size.
   This lab's footprint is ~30 MB of source data expanding to roughly 421k rows, which
   should sit far inside any free tier, but confirm rather than assume.
2. **The inactivity-deletion rule** — free clusters are deleted after a period with no
   activity. Check the current window so you are not surprised.
3. **The terms on personal data** — free clusters are not intended for personal or
   production data. Everything in this lab is synthetic attack telemetry from public
   research datasets, which is fine, but do not add anything else.

## Create the cluster

1. Go to the Azure Data Explorer web UI (`dataexplorer.azure.com`) and sign in with a
   Microsoft account. **No Azure subscription is required** for a free cluster.
2. Find the free-cluster creation entry point (historically "My cluster" / "Create free
   cluster"), pick a region, and create it.
3. Create a database named **`KqlLab`**.
4. Copy the cluster's query URI — it looks like
   `https://<name>.<region>.kusto.windows.net`.

## Point the lab at it

Edit `.env`:

```bash
KUSTO_URI=https://<your-cluster>.<region>.kusto.windows.net
KUSTO_DB=KqlLab
KUSTO_AUTH_MODE=device
```

`KUSTO_AUTH_MODE=device` triggers an interactive device-code sign-in on first use.
`azure_cli` is also supported if you have `az login` working.

Install the SDK (not needed for the emulator path):

```bash
pip install -r requirements.txt
```

## Run the pipeline

```bash
python tasks.py data
```

```bash
python tasks.py ingest
```

```bash
python tasks.py test
```

`tasks.py up` and `down` are emulator-only and are not used here.

## What differs from the emulator path

| Aspect | Emulator | Free cluster |
|---|---|---|
| Auth | none | AAD device code or Azure CLI |
| Transport | plain HTTP on loopback | HTTPS |
| Client | stdlib `urllib` (`tools/kusto.py`) | `azure-kusto-data` SDK |
| Database creation | automatic (`tools/ingest.py`) | **you create it in the portal** |
| File ingestion | `.ingest into table (@"/data/...")` from a bind mount | **will not work** — there is no local filesystem to read from |

### The ingestion difference is the one that matters

The emulator ingests directly from a mounted folder. A real cluster cannot see your disk.
`tools/ingest.py` uses the mounted-file command, so on a free cluster you need one of:

- **`azure-kusto-ingest` queued ingestion** — add `azure-kusto-ingest==6.0.4` and extend
  `tools/ingest.py` with a managed-streaming or queued ingest client. This is the clean
  fix and is the reason `requirements.txt` notes the package as conditional.
- **One-click ingestion in the web UI** — workable for a one-off: upload the extracted
  JSON files from `data/extracted/<dataset_id>/` and map `$` to the `raw` column, then set
  `dataset_id` and `source_file` manually per file. Tedious across 39 datasets.
- **Blob ingestion** — upload the extracted JSON to a storage container and ingest from
  its URI.

This path is **not implemented or tested** in this repo. If you need it, the schema and
mapping commands in `kql/schema/` and `tools/ingest.py` are unchanged — only the
transport differs.

## Tearing down

Delete the database or the cluster from the ADX web UI when finished. Free clusters are
also removed automatically after the inactivity window.
