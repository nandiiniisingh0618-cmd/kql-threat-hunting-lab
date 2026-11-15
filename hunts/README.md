# Hunts

Three hypothesis-driven hunts. Each one follows the same structure:

1. **Hypothesis** — a falsifiable statement about attacker behaviour.
2. **Data needed** — which telemetry would confirm or refute it.
3. **Queries** — what was actually run.
4. **Findings** — what the data said, including when it said "no".
5. **Pivots** — where the findings led next.
6. **Resulting detection** — what shipped, or why nothing did.
7. **Gaps** — what this hunt could not answer.

Every number and row in these write-ups came from running the query against the
ingested corpus (420,977 events, 39 datasets). Two of the three hunts returned
**negative or partially negative** results, which are kept rather than quietly
replaced with a success story — a hunt that finds nothing is still a hunt, and the
reason it found nothing is usually the most useful output.
