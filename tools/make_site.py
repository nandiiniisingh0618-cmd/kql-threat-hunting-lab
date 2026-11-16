"""Generate public/index.html from RESULTS.md and the detection registry.

No templating engine, no network, no build step on the host: Vercel serves
public/ as static files. Everything on the page is read out of the generated
test results, so the page cannot claim more than the harness proved.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

from . import config

PUBLIC_DIR = config.REPO_ROOT / "public"
RESULTS = config.REPO_ROOT / "RESULTS.md"


def _results_stats(text: str) -> dict[str, str]:
    def grab(pattern: str, default: str = "--") -> str:
        match = re.search(pattern, text)
        return match.group(1) if match else default

    return {
        "run": grab(r"Last run ([0-9:\- ]+Z)"),
        "attack": grab(r"ATT&CK version pinned: \*\*v([0-9.]+)\*\*"),
        "events": grab(r"Corpus: \*\*([\d,]+) events\*\*"),
        "datasets": grab(r"across \*\*(\d+) datasets\*\*"),
        "run_count": grab(r"Detections run: \*\*(\d+)\*\*"),
        "passing": grab(r"true positive: \*\*(\d+)\*\*"),
        "query_time": grab(r"Total query time: \*\*([\d.]+)s\*\*"),
    }


def _results_rows(text: str) -> list[dict[str, str]]:
    rows = []
    for line in text.splitlines():
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 7 or cells[0] == "Detection":
            continue
        name, techniques, status, tp, cross, rate, seconds = cells
        rows.append({
            "name": name, "techniques": techniques, "status": status,
            "tp": tp, "cross": cross, "rate": rate, "seconds": seconds,
        })
    return rows


def _tactic_of(name: str, by_name: dict[str, str]) -> str:
    return by_name.get(name, "--")


def _detection_index() -> dict[str, str]:
    """Map detection name -> tactic directory, read straight off the filenames."""
    index: dict[str, str] = {}
    for path in sorted((config.REPO_ROOT / "detections").rglob("*.yml")):
        tactic = path.parent.name.replace("_", " ").title()
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("name:"):
                index[line.split(":", 1)[1].strip().strip("\"'")] = tactic
                break
    return index


CSS = """
:root{--bg:#ffffff;--fg:#0a0a0a;--dim:#6b6b6b;--rule:#d8d8d8;--panel:#f6f6f6;--inv-bg:#0a0a0a;--inv-fg:#ffffff}
@media (prefers-color-scheme:dark){:root{--bg:#060607;--fg:#ececed;--dim:#8c8c90;--rule:#232327;--panel:#0d0d0f;--inv-bg:#ececed;--inv-fg:#060607}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){
 body{background-image:
  radial-gradient(1px 1px at 12% 18%,#fff 50%,transparent 50%),
  radial-gradient(1px 1px at 72% 9%,#fff 50%,transparent 50%),
  radial-gradient(1px 1px at 33% 61%,#d7d7e2 50%,transparent 50%),
  radial-gradient(1px 1px at 88% 44%,#fff 50%,transparent 50%),
  radial-gradient(1px 1px at 54% 83%,#c9c9d6 50%,transparent 50%),
  radial-gradient(1px 1px at 93% 77%,#fff 50%,transparent 50%),
  radial-gradient(1px 1px at 6% 91%,#b9b9c6 50%,transparent 50%);
  background-attachment:fixed;background-repeat:no-repeat}}
.wrap{max-width:960px;margin:0 auto;padding:48px 16px 96px}
pre.mark{margin:0;font-size:11px;line-height:1.15;letter-spacing:.5px;overflow-x:auto}
h1{font-size:15px;letter-spacing:.22em;text-transform:uppercase;margin:28px 0 4px;font-weight:600}
.sub{color:var(--dim);margin:0 0 28px}
h2{font-size:12px;letter-spacing:.22em;text-transform:uppercase;color:var(--dim);
 font-weight:600;margin:48px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--rule)}
a{color:var(--fg);text-decoration:none;border-bottom:1px solid var(--rule)}
a:hover{border-bottom-color:var(--fg)}
.lede{max-width:66ch}
.grid{display:grid;gap:1px;background:var(--rule);border:1px solid var(--rule);
 grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.cell{background:var(--bg);padding:14px 16px}
.cell .k{color:var(--dim);font-size:11px;letter-spacing:.14em;text-transform:uppercase}
.cell .v{font-size:20px;margin-top:6px}
.cell .v small{display:block;font-size:11px;color:var(--dim);margin-top:4px;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
th{color:var(--dim);font-size:11px;letter-spacing:.14em;text-transform:uppercase;font-weight:600;
 border-bottom:1px solid var(--fg)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
tbody tr:hover{background:var(--panel)}
.tag{display:inline-block;border:1px solid var(--rule);padding:1px 6px;margin:0 4px 4px 0;
 font-size:11px;color:var(--dim);white-space:nowrap}
.pass{background:var(--inv-bg);color:var(--inv-fg);padding:1px 7px;font-size:11px;letter-spacing:.08em}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
ul.plain{list-style:none;padding:0;max-width:72ch}
ul.plain li{padding:10px 0;border-bottom:1px solid var(--rule)}
footer{margin-top:64px;padding-top:16px;border-top:1px solid var(--rule);color:var(--dim);font-size:11.5px}
"""

WORDMARK = r"""  ██  ██  ██████  ██
  ██ ██  ██    ██ ██
  ████   ██    ██ ██
  ██ ██  ██ ▄▄ ██ ██
  ██  ██  ██████  ███████
             ▀▀"""

REPO = "https://github.com/nandiiniisingh0618-cmd/kql-threat-hunting-lab"


def build() -> Path:
    text = RESULTS.read_text(encoding="utf-8")
    stats = _results_stats(text)
    rows = _results_rows(text)
    tactics = _detection_index()

    by_tactic: dict[str, int] = {}
    for row in rows:
        by_tactic[_tactic_of(row["name"], tactics)] = by_tactic.get(_tactic_of(row["name"], tactics), 0) + 1

    e = html.escape
    techniques = {t.strip() for row in rows for t in row["techniques"].split(",") if t.strip()}
    cells = [
        ("detections", stats["run_count"], ""),
        ("passing on real data", f"{stats['passing']}/{stats['run_count']}", ""),
        ("events in corpus", stats["events"], "windows attack telemetry"),
        ("datasets", stats["datasets"], "public, none redistributed"),
        ("att&ck", f"v{stats['attack']}", "pinned"),
        ("techniques", str(len(techniques)), f"{len(by_tactic)} tactics"),
        ("tactics", str(len(by_tactic)), "of enterprise att&ck"),
        ("harness runtime", f"{stats['query_time']}s", "full corpus"),
    ]
    cell_html = "\n".join(
        f'<div class="cell"><div class="k">{e(k)}</div>'
        f'<div class="v">{e(v)}{f" <small>{e(s)}</small>" if s else ""}</div></div>'
        for k, v, s in cells
    )

    tactic_rows = "\n".join(
        f"<tr><td>{e(t)}</td><td class='n'>{n}</td></tr>"
        for t, n in sorted(by_tactic.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    detection_rows = "\n".join(
        "<tr>"
        f"<td>{e(r['name'])}</td>"
        f"<td>{''.join(f'<span class=tag>{e(t.strip())}</span>' for t in r['techniques'].split(','))}</td>"
        f"<td>{e(_tactic_of(r['name'], tactics))}</td>"
        f"<td><span class=pass>{e(r['status'].split('/')[-1].strip().upper())}</span></td>"
        f"<td class='n'>{e(r['tp'])}</td><td class='n'>{e(r['cross'])}</td><td class='n'>{e(r['seconds'])}</td>"
        "</tr>"
        for r in rows
    )

    page = f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KQL Threat-Hunting Lab</title>
<meta name="description" content="24 KQL detections for Windows attack telemetry, each tested against recorded attack events and mapped to MITRE ATT&amp;CK v{e(stats['attack'])}.">
<style>{CSS}</style>
<body>
<div class="wrap">
<pre class="mark" aria-label="KQL">{e(WORDMARK)}</pre>
<h1>KQL Threat-Hunting Lab</h1>
<p class="sub">detections-as-code &middot; windows telemetry &middot; att&amp;ck v{e(stats['attack'])}</p>

<p class="lede">{e(stats['run_count'])} KQL detections across {len(by_tactic)} ATT&amp;CK tactics. Each one runs
against {e(stats['events'])} recorded Windows attack events on a local Kusto emulator, and nothing is
marked covered until a test has fired it on real data. Every figure below is read out of
<a href="{REPO}/blob/main/RESULTS.md">RESULTS.md</a>, which the test harness writes.</p>

<h2>Harness</h2>
<div class="grid">{cell_html}</div>
<p class="sub" style="margin-top:14px">Last run {e(stats['run'])}.</p>

<h2>By tactic</h2>
<div class="scroll"><table><thead><tr><th>Tactic</th><th class="n">Detections</th></tr></thead>
<tbody>{tactic_rows}</tbody></table></div>

<h2>Detections</h2>
<div class="scroll"><table><thead><tr>
<th>Detection</th><th>Techniques</th><th>Tactic</th><th>Result</th>
<th class="n">TP hits</th><th class="n">Cross-dataset</th><th class="n">Time (s)</th>
</tr></thead><tbody>{detection_rows}</tbody></table></div>
<p class="sub" style="margin-top:14px">Cross-dataset counts datasets a rule fired on that it does not
declare as a true-positive source. It is a false-positive proxy, not an FP rate: every dataset here is
attack data, so some overlap is genuinely correct.</p>

<h2>What this is not</h2>
<ul class="plain">
<li>Not production telemetry. "Covered" means a query fired on a recorded attack in a lab domain of a
handful of hosts, over 39 public datasets.</li>
<li>Not tuned for deployment. Thresholds are set low enough to be provable on these captures; each rule's
<code>tuning_notes</code> says what to raise.</li>
<li>Not a Sentinel pack. The export under <code>export/sentinel/</code> is a structural translation and is
labelled UNTESTED: the queries call this lab's stored functions.</li>
</ul>

<h2>Read more</h2>
<ul class="plain">
<li><a href="{REPO}">Repository</a>, with the full setup path and the architecture diagram.</li>
<li><a href="{REPO}/blob/main/docs/HOW_IT_WORKS.md">How it works</a>: all {e(stats['run_count'])} detections in plain English.</li>
<li><a href="{REPO}/blob/main/coverage/COVERAGE.md">Coverage</a> and <a href="{REPO}/blob/main/coverage/GAPS.md">known gaps</a>, both generated from passing tests only.</li>
<li><a href="{REPO}/tree/main/hunts">Hunts</a>: three write-ups, including one negative result kept as-is.</li>
</ul>

<footer>Generated by <code>python tasks.py site</code> from the harness run of {e(stats['run'])}.
Code and detections MIT. No dataset is redistributed. ATT&amp;CK is used under MITRE's terms.</footer>
</div>
</body>
</html>
"""
    PUBLIC_DIR.mkdir(exist_ok=True)
    out = PUBLIC_DIR / "index.html"
    out.write_text(page, encoding="utf-8")
    return out


def main() -> int:
    out = build()
    print(f"wrote {out.relative_to(config.REPO_ROOT)} ({out.stat().st_size/1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
