"""Generate docs/HOW_IT_WORKS.md: a plain-English page per detection.

Each entry answers four questions: what the attacker does, what telemetry shows it,
why the query catches it, and how an attacker could evade it. The content comes from
the detection YAML, so the page cannot drift from the rules.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime

from . import config
from .registry import attack_model, load_detections


def main(argv: list[str] | None = None) -> int:
    argv = argv or []
    model = attack_model()
    detections = load_detections()
    docs_dir = config.REPO_ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append("# How it works: every detection in plain English")
    lines.append("")
    lines.append("**Generated** by `make docs` from the detection YAML -- do not edit.")
    lines.append(f"Last generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')}.")
    lines.append("")
    lines.append(f"ATT&CK Enterprise **v{model['version']}** - {len(detections)} detections.")
    lines.append("")
    lines.append("Each entry covers the same four things, because those are the four things "
                 "worth being able to explain about a detection:")
    lines.append("")
    lines.append("1. **The behaviour** - what the attacker is actually doing.")
    lines.append("2. **The telemetry** - which events make it visible.")
    lines.append("3. **Why the query catches it** - the logic, and what makes it specific.")
    lines.append("4. **How to evade it** - the honest limits.")
    lines.append("")

    # ---- index ----
    by_tactic: dict[str, list[dict]] = {}
    for detection in detections:
        for tactic in detection["_tactics"]:
            by_tactic.setdefault(tactic["name"], []).append(detection)

    lines.append("## Index")
    lines.append("")
    for tactic_name in sorted(by_tactic):
        lines.append(f"**{tactic_name}**")
        lines.append("")
        for detection in sorted(by_tactic[tactic_name], key=lambda d: d["name"]):
            # GitHub anchors: lowercase, spaces -> hyphens, punctuation dropped.
            anchor = detection["name"].lower()
            anchor = "".join(
                "-" if ch in " _" else ch
                for ch in anchor
                if ch.isalnum() or ch in " _-"
            )
            while "--" in anchor:
                anchor = anchor.replace("--", "-")
            lines.append(f"- [{detection['name']}](#{anchor.strip('-')}) "
                         f"({', '.join(detection['techniques'])})")
        lines.append("")

    # ---- per detection ----
    for detection in sorted(detections, key=lambda d: d["name"]):
        lines.append("---")
        lines.append("")
        lines.append(f"## {detection['name']}")
        lines.append("")
        technique_links = ", ".join(
            f"[{tid}]({model['techniques'][tid]['url']})" if tid in model["techniques"] else tid
            for tid in detection["techniques"]
        )
        lines.append(f"- **Techniques:** {technique_links}")
        lines.append(f"- **Tactics:** {', '.join(t['name'] for t in detection['_tactics'])}")
        lines.append(f"- **Severity:** {detection['severity']} | "
                     f"**Status:** {detection['status']}")
        lines.append(f"- **Rule file:** `{detection['_rel_path']}`")
        lines.append(f"- **Validated against:** "
                     f"{', '.join(t['dataset_id'] for t in detection['tests'])}")
        lines.append("")

        lines.append("**1. The behaviour**")
        lines.append("")
        lines.append(detection["description"].strip())
        lines.append("")

        lines.append("**2. The telemetry**")
        lines.append("")
        for source in detection["data_sources"]:
            lines.append(f"- {source}")
        lines.append("")

        lines.append("**3. Why the query catches it**")
        lines.append("")
        lines.append(detection["tuning_notes"].strip())
        lines.append("")
        lines.append("Known false positives:")
        lines.append("")
        for item in detection["false_positives"]:
            lines.append(f"- {item}")
        lines.append("")

        lines.append("**4. How to evade it**")
        lines.append("")
        for item in detection["known_blind_spots"]:
            lines.append(f"- {item}")
        lines.append("")

        if detection.get("references"):
            lines.append("References: " + ", ".join(f"<{r}>" for r in detection["references"]))
            lines.append("")

    path = docs_dir / "HOW_IT_WORKS.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote docs/HOW_IT_WORKS.md ({len(detections)} detections, "
          f"{len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
