# Hunt 02 — Rarity: which parent/child process pairs are unusual?

**Scope:** whole corpus (420,977 events, 39 datasets)
**Outcome:** hypothesis **supported**, with an important caveat about what "rare" means here

---

## 1. Hypothesis

> Attacker tradecraft shows up as *unusual process lineage* rather than as unusual
> binaries. Signed Windows components spawning interpreters is the shape. If I rank
> parent/child pairs by rarity across the corpus and keep only the pairs whose child is
> an interpreter or LOLBin, the rare tail should be dominated by attack technique and
> the common head by ordinary Windows behaviour — without me writing a single
> technique-specific rule.

This is the one hunt in this repo that uses the corpus as its own baseline rather than
a hand-written allowlist.

## 2. Data needed

Only `SysmonProcessCreate()` (Sysmon EventID 1). The rarity measure needs the whole
corpus, not one dataset, so this cannot be answered from a single capture.

## 3. Queries

Build a frequency table of pairs, then filter to interesting children and take the
rare tail:

```kusto
let interesting_children = dynamic(["powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe",
                                    "mshta.exe","cscript.exe","wscript.exe","wmic.exe",
                                    "net.exe","schtasks.exe","sc.exe"]);
let pairs =
    SysmonProcessCreate()
    | where isnotempty(ParentProcess) and isnotempty(Process)
    | summarize Occurrences = count(),
                Datasets    = dcount(DatasetId),
                Hosts       = dcount(Computer)
      by ParentProcess = tolower(ParentProcess), Process = tolower(Process);
pairs
| where Process in~ (interesting_children)
| where Datasets <= 2                      // the rare tail
| order by Occurrences asc, Datasets asc
```

## 4. Findings

33 rare pairs surfaced. The tail is genuinely dense with tradecraft — these are all
`Occurrences = 1, Datasets = 1, Hosts = 1`:

| Parent → child | What it indicates |
|---|---|
| `fodhelper.exe` → `powershell.exe` | **UAC bypass** via the ms-settings handler hijack (T1548.002) |
| `wscript.exe` → `powershell.exe` | script-host staging a PowerShell payload (T1059.005 → T1059.001) |
| `regsvr32.exe` → `powershell.exe` | scriptlet proxy execution chaining to PowerShell (T1218.010) |
| `netsh.exe` → `cscript.exe` | netsh helper-DLL abuse — a technique **this repo has no detection for** |
| `msbuild.exe` → `powershell.exe` | trusted-developer-utility proxy execution (T1127.001, no detection here) |
| `payload.exe` → `cmd.exe` | an unsigned binary in a user path shelling out |
| `wmiprvse.exe` → `cmd.exe` / `powershell.exe` | WMI remote execution (T1047) |
| `compattelrunner.exe` → `rundll32.exe` / `powershell.exe` | Windows telemetry runner, **benign** |
| `monitoringhost.exe` → `cscript.exe` | SCOM agent, **benign** |
| `services.exe` → `powershell.exe` | a service whose image is PowerShell — suspicious, but also how some legitimate agents work |

So: roughly 7 of the 10 most notable rare pairs map to a real technique, and three
(`compattelrunner.exe`, `monitoringhost.exe`, and arguably `services.exe`) are
legitimate software that is simply uncommon in this corpus.

**The caveat that matters.** "Rare" here means *rare across 39 attack-simulation
captures*, which is not the same as rare in an enterprise. In this corpus almost
everything is rare: the datasets are short, single-purpose recordings, so
`Occurrences = 1` is the norm rather than a signal. Of the 33 rare pairs surfaced,
**22 occur exactly once** — two thirds of the result set has the minimum possible
count, which tells you the threshold is not discriminating much. A real rarity baseline needs weeks of production telemetry
from the estate you are defending, where `cmd.exe` under `explorer.exe` has a count in
the millions and `powershell.exe` under `fodhelper.exe` has a count of zero.

What this hunt genuinely demonstrates is the *method* and that the method surfaces real
tradecraft. It does not demonstrate that the thresholds transfer.

## 5. Pivots

Two pairs pointed at techniques with **no detection in this repo**:

- `netsh.exe` → `cscript.exe` — netsh helper DLL persistence (T1546.007)
- `msbuild.exe` → `powershell.exe` — trusted developer utility proxy execution (T1127.001)

Both were checked against the available data. Each appears exactly once, in one dataset,
on one host. That is below the bar this repo sets for shipping a detection (a rule needs
a test that proves it fires on real events, and a single event is a very thin basis for
claiming a technique is "covered"), so neither became a rule. Both are recorded here as
known gaps instead.

The `fodhelper.exe` → `powershell.exe` pair independently corroborates the shipped
`T1548.002` UAC-bypass rule, which detects the *registry write* that sets the hijack up.
This hunt caught the *consequence* — the elevated child. Those are two different events
for one technique, and having both is a useful confirmation path during triage.

## 6. Resulting detection

No new rule shipped. Deliberately:

- A rarity rule tuned on 39 short captures would encode this corpus's shape, not real
  anomalousness, and would mislead anyone who deployed it.
- The two uncovered techniques found here each have one event of evidence — not enough.

What did change: this hunt is the documented argument for *why* the repo's detections
use explicit allowlists and thresholds rather than rarity scoring, and it is referenced
from `README.md` under limitations. The `fodhelper` → `powershell` corroboration is noted
in the `T1548.002` rule's `tuning_notes` as the recommended confirmation pivot.

## 7. Gaps

- **Baseline validity.** The central limitation, above: corpus rarity ≠ production rarity.
- **Parent spoofing.** `ParentImage` comes from the kernel but can be manipulated via
  PPID spoofing, so a rare pair can be manufactured — or a common one faked to hide in.
- **Depth of one.** Only immediate parent/child is considered. `wscript.exe` →
  `powershell.exe` → `rundll32.exe` is three separate pairs here, not one chain.
- **Sysmon 1 volume.** Only 1,114 process-create events exist in the whole corpus, which
  is tiny; these datasets are heavy on Sysmon 10/12/13 instead. A process-lineage hunt is
  therefore working with the thinnest telemetry available here.
- **Interpreter list is hand-written.** Filtering to `interesting_children` reintroduces
  exactly the kind of hand-maintained list the rarity method was meant to avoid.
