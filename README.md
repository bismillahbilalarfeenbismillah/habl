# Bismillah ir-Rahman ir-Rahim

# HABL -- Honesty-Attested Binding Ledger

> *From* حبل *(habl, "rope") -- "And hold firmly to the rope of Allah all together and do not become divided." (Ali 'Imran 3:103)*

HABL is the shared finding protocol for the **Entourage Effect Software Safety Suite**. It is the mycorrhizal network -- the connective tissue through which [furqan-lint](https://github.com/BayyinahEnterprise/furqan-lint), [FATIMA](https://github.com/bismillahbilalarfeenbismillah/Bismillah-Divine-Protection-Encoder-Bismillah), and Bayyinah Scanner exchange structural-honesty findings in a common, append-only format.

## What it does

Every tool in the suite emits **findings** -- structured envelopes that record what was checked, what was found, and where. HABL defines:

- **The Finding envelope** -- a frozen dataclass with source_tool, severity, category, location, summary, and correlation/provenance fields
- **The append-only ledger** -- `.habl/findings.jsonl`, one JSON object per line, append-only by contract
- **Correlation and provenance** -- `correlation_id` groups related findings across tools; `parent_id` chains cause-and-effect
- **Query helpers** -- read by source, by correlation, or walk the full provenance chain

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

## Schema version

Current: `0.1.0` (package `0.1.1`; v0.1.1 adds read-side tooling only, no schema change)

## License

MIT

# Bismillah ir-Rahman ir-Rahim
