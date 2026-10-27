# Bismillah ir-Rahman ir-Rahim

# HABL -- Honesty-Attested Binding Ledger

> *From* حبل *(habl, "rope") -- "And hold firmly to the rope of Allah all together and do not become divided." (Ali 'Imran 3:103)*

HABL is the shared finding protocol for the **Entourage Effect Software Safety Suite**. It is the mycorrhizal network -- the connective tissue through which [furqan-lint](https://github.com/BayyinahEnterprise/furqan-lint), [FATIMA](https://github.com/bismillahbilalarfeenbismillah/Bismillah-Divine-Protection-Encoder-Bismillah), and Bayyinah Scanner exchange structural-honesty findings in a common, append-only format.

## What it does

Every tool in the suite emits **findings** -- structured envelopes that record what was checked, what was found, and where. HABL defines:

- **The Finding envelope** -- a validated dataclass with source_tool, severity, category, location, summary, and correlation/provenance fields (`Location` is frozen; `Finding` is not)
- **The append-only ledger** -- `.habl/findings.jsonl`, one JSON object per line, append-only by contract. Appends are locked (POSIX `flock`) so concurrent writers using HABL do not interleave. v0.1 is not tamper-evident: nothing yet detects an edit made outside HABL. A hash chain is planned for v0.2.
- **Correlation and provenance** -- `correlation_id` groups related findings across tools; `parent_id` chains cause-and-effect
- **Query helpers** -- read by source, by correlation, or walk the full provenance chain. A walk that meets a cycle or a duplicated `finding_id` raises a typed `LedgerIntegrityError` instead of looping or silently picking one.

## The Entourage Effect

HABL is one of five components that work together like cannabinoids in a landrace sativa:

| Component | Role | Analogy |
|-----------|------|---------|
| **Furqan** | The programming language | THC -- primary cannabinoid |
| **FATIMA** | Encoder/sealer | CBD -- balancing cannabinoid |
| **furqan-lint** | Structural linter | Myrcene -- dominant terpene |
| **Bayyinah Scanner** | Anomaly detector | Limonene -- secondary terpene |
| **HABL** | Finding protocol | Cannaflavin A -- the mycorrhizae |

No single tool is the safety story. The entourage effect is.

## Install

```bash
pip install -e .
```

Requires Python 3.10+.

## Usage

```python
from habl import Finding, Severity, Category, Location
from habl import append_finding, read_ledger, new_correlation_id

# Create a finding
finding = Finding(
    source_tool="furqan-lint",
    severity=Severity.HIGH,
    category=Category.STRUCTURAL,
    summary="Function declares int return but path at line 42 returns None",
    location=Location(file="app.py", line=42, function="process")
)

# Append to the ledger (project_root is the directory that holds .habl/)
append_finding(finding, ".")

# Query
for f in read_ledger("."):
    print(f.summary)
```

## Command line (v0.1.1)

```bash
habl stats                                   # counts + ledger health
habl query --min-severity high               # filter findings
habl query --source fatima --format jsonl    # machine-readable
habl correlate                               # groups by declared correlation_id
habl correlate --infer-location              # + cross-tool file/line overlap
```

All commands take `--root DIR` (default `.`) and `--strict`.

- **Nothing is silently dropped.** Malformed ledger lines are listed on stderr with line numbers. `--strict` turns them into exit code 1. Usage errors exit 2.
- **Declared and inferred links stay distinct.** A shared `correlation_id` is a link a tool *declared*. Location overlap is a link `correlate` *inferred*, and it is labelled that way. Inference only covers findings from two or more different tools, and it never writes back to the ledger.
- **A group is not a verdict.** Correlation marks findings for joint inspection. Each finding remains attributable to the tool that emitted it.
- **Output is deterministic** for a given ledger and arguments. `query` preserves ledger (append) order. `stats` keys are sorted.

`python -m habl ...` works as well.

## Known limits in v0.1.1

These are deliberate, documented behaviours, not hidden ones:

- **Missing parents give partial chains.** If a `parent_id` names a finding that is not in the ledger, `read_provenance_chain` returns the chain up to that point and stops. It does not raise. `habl stats` lists every such reference under `health.dangling_parents`.
- **Duplicate `finding_id`s are detected, not refused.** Append accepts a repeated id. It is caught when a provenance walk reaches it (`DuplicateFindingIdError`) and is listed by `habl stats` under `health.duplicate_ids`.
- **Unknown fields are rejected.** A ledger line with a field this version does not know is reported as malformed, not partly read.
- **Locking is POSIX-only and cooperative.** `flock` keeps HABL writers from interleaving on Linux and macOS. It does not stop a writer that bypasses HABL, does not make a multi-line batch crash-atomic, and does nothing on Windows.
- **Bytes are stable, not canonical.** Keys are sorted and output is compact strict JSON (no NaN or Infinity, no duplicate keys), but there is no full canonical form yet.

## Planned for v0.2

Design work, not yet decided:

1. Canonical serialization (for example RFC 8785 JCS) as the input to a hash chain
2. Stronger writer coordination: crash recovery and a Windows implementation
3. Forward compatibility for unknown fields, tied to schema-version rules
4. Duplicate prevention at append time
5. Whether a missing parent should fail closed in provenance-sensitive uses

## Schema version

Current: `0.1.0` (package `0.1.1`; v0.1.1 adds read-side tooling only, no schema change)

## License

MIT

# Bismillah ir-Rahman ir-Rahim
