# Sentinel analytics-rule export

**Generated** by `make export-sentinel` -- do not edit by hand.

## These rules are UNTESTED

Nothing here has been deployed to a live Microsoft Sentinel workspace by this
repository, and the author makes no claim that it works there. Two concrete
reasons they will NOT run as-is:

1. **The queries call this lab's normalization functions** (`SysmonProcessCreate()`, `SecurityLogon()`, ...). Those are stored functions in
   the lab database and do not exist in a Sentinel workspace. Each one maps to a
   Sentinel-native table or ASIM parser -- see `docs/schema-mapping.md`.
2. **`DatasetId` has no meaning in production.** It is a lab provenance column
   used by the test harness to attribute hits, and every rule projects it.

Treat these files as a faithful structural translation of the rule logic, not as
deployable content. See `docs/sentinel-export.md` for what porting actually
involves.

## Tactic-name compatibility (unverified)

ATT&CK v20.1 renamed TA0005 `Defense Evasion` to **Stealth** and added TA0112
**Defense Impairment**. Sentinel validates `tactics:` against a fixed enum, and
that enum could NOT be checked when this repo was built, so the new names may be
rejected on upload. Where a rule uses one, the export emits the v20.1 name and
adds an inline comment naming the legacy `DefenseEvasion` fallback. The full
v20.1 tactic list is preserved in each rule's `metadata.attackTactics`.

Exported 24 rules against ATT&CK v20.1 on 2026-11-15.
