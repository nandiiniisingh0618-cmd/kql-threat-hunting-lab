# Thin wrapper over tasks.py so `make` and `python tasks.py` behave identically.
# On Windows (no make), use: python tasks.py <target>
PY ?= python

.PHONY: help doctor up down status data ingest test validate-attack coverage export-sentinel docs site all clean

help:
	@$(PY) tasks.py help

doctor:           ## check this machine can run the lab (run this first)
	@$(PY) tasks.py doctor

up:               ## start the local Kusto emulator (bound to 127.0.0.1)
	@$(PY) tasks.py up

down:             ## stop and remove the emulator container
	@$(PY) tasks.py down

status:           ## show emulator / data / detection status
	@$(PY) tasks.py status

data:             ## download pinned datasets and verify SHA-256
	@$(PY) tasks.py data

ingest:           ## apply schema + functions and ingest datasets
	@$(PY) tasks.py ingest

test:             ## run the pytest detection harness, write RESULTS.md
	@$(PY) tasks.py test

validate-attack:  ## fail on missing/revoked/deprecated ATT&CK technique IDs
	@$(PY) tasks.py validate-attack

coverage:         ## generate attack-layer.json, COVERAGE.md, GAPS.md
	@$(PY) tasks.py coverage

export-sentinel:  ## export detections as Sentinel analytics-rule YAML
	@$(PY) tasks.py export-sentinel

docs:             ## regenerate docs/HOW_IT_WORKS.md
	@$(PY) tasks.py docs

site:             ## regenerate public/index.html (the deployed status page)
	@$(PY) tasks.py site

all:              ## data + ingest + validate + test + coverage + docs + site
	@$(PY) tasks.py all

clean:            ## remove extracted data and generated artefacts (keeps archives)
	@$(PY) -c "import shutil,pathlib; shutil.rmtree('data/extracted',ignore_errors=True); [pathlib.Path(p).unlink(missing_ok=True) for p in ['RESULTS.md','coverage/COVERAGE.md','coverage/GAPS.md','coverage/attack-layer.json']]"
	@echo "cleaned"
