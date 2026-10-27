# Bismillah ir-Rahman ir-Rahim
"""HABL v0.1.1 -- query, stats, and correlate over the ledger.

The read side of the rope. Three operations:

    query      -- filter findings by source, severity, category, file,
                  correlation, and time window
    stats      -- counts plus ledger-health observations (malformed
                  lines, duplicate ids, dangling parent references)
    correlate  -- group findings that relate to one another

Two disciplines govern this module:

1. Nothing is silently dropped. A line that does not parse, or parses
   but does not form a valid Finding, is reported with its line number
   and the reason. The caller decides whether that is fatal (--strict).

2. Declared links and inferred links stay distinct. A shared
   correlation_id is a link some tool *declared*. Two findings touching
   the same file and line is a link this module *inferred*. Each group
   carries its basis, and neither kind is a verdict: correlation
   surfaces co-occurrence for inspection. A scanner finding and a seal
   anomaly remain separately attributable evidence.

Schema version read: 0.1.0
"""
# Bismillah ir-Rahman ir-Rahim

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from habl.envelope import Category, Finding, Severity, ledger_path

# Ordering used by --min-severity and by sorted output.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.ADVISORY: 0,
}


# ---------------------------------------------------------------------------
# Tolerant ledger load -- every line accounted for
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """A successfully parsed finding and the ledger line it came from."""

    line_no: int
    finding: Finding


@dataclass(frozen=True, slots=True)
class MalformedLine:
    """A non-blank ledger line that did not yield a valid Finding."""

    line_no: int
    reason: str
    raw: str  # truncated to 200 chars for display


@dataclass(slots=True)
class LedgerLoad:
    """Result of reading a ledger: what parsed, and what did not."""

    path: Path
    exists: bool
    entries: list[LedgerEntry] = field(default_factory=list)
    malformed: list[MalformedLine] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [e.finding for e in self.entries]


def load_ledger(project_root: str | Path) -> LedgerLoad:
    """Read the ledger line by line, keeping a record of every failure.

    Unlike envelope.read_ledger (which raises on the first bad line),
    this returns everything that parsed together with an account of
    everything that did not. Blank lines are ignored, not reported.
    """
    path = ledger_path(project_root)
    load = LedgerLoad(path=path, exists=path.exists())
    if not load.exists:
        return load

    with open(path, encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                load.malformed.append(
                    MalformedLine(line_no, f"invalid JSON: {exc.msg}", line[:200])
                )
                continue
            if not isinstance(data, dict):
                load.malformed.append(
                    MalformedLine(
                        line_no,
                        f"expected JSON object, got {type(data).__name__}",
                        line[:200],
                    )
                )
                continue
            try:
                finding = Finding.from_dict(data)
            except (TypeError, ValueError, KeyError) as exc:
                load.malformed.append(
                    MalformedLine(line_no, f"invalid finding: {exc}", line[:200])
                )
                continue
            load.entries.append(LedgerEntry(line_no, finding))
    return load


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------

def _parse_time(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. Naive values are rejected so that
    comparisons never mix aware and naive datetimes."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        msg = f"timestamp {value!r} has no timezone offset"
        raise ValueError(msg)
    return dt


def filter_findings(
    entries: Iterable[LedgerEntry],
    *,
    sources: Sequence[str] = (),
    severities: Sequence[Severity] = (),
    min_severity: Severity | None = None,
    categories: Sequence[Category] = (),
    file: str | None = None,
    correlation_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[LedgerEntry]:
    """Return entries matching every supplied criterion (logical AND).

    Within a repeatable criterion (sources, severities, categories)
    values are OR-ed. Ledger order is preserved: the append order is
    the ledger's own record of sequence.

    since / until compare against each finding's timestamp; a finding
    whose timestamp cannot be parsed does not match a time filter.
    """
    since_dt = _parse_time(since) if since else None
    until_dt = _parse_time(until) if until else None
    min_rank = SEVERITY_RANK[min_severity] if min_severity else None

    out: list[LedgerEntry] = []
    for entry in entries:
        f = entry.finding
        if sources and f.source_tool not in sources:
            continue
        if severities and f.severity not in severities:
            continue
        if min_rank is not None and SEVERITY_RANK[f.severity] < min_rank:
            continue
        if categories and f.category not in categories:
            continue
        if file is not None and f.location.file != file:
            continue
        if correlation_id is not None and f.correlation_id != correlation_id:
            continue
        if since_dt or until_dt:
            try:
                ts = _parse_time(f.timestamp)
            except (ValueError, TypeError, AttributeError):
                continue
            if since_dt and ts < since_dt:
                continue
            if until_dt and ts > until_dt:
                continue
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

def compute_stats(load: LedgerLoad) -> dict[str, Any]:
    """Counts by source/severity/category plus ledger-health observations.

    Health observations are reported, not repaired:
        malformed_lines     -- lines that did not yield a Finding
        duplicate_ids       -- finding_ids appearing more than once
        dangling_parents    -- parent_ids naming no finding in the ledger
        schema_versions     -- every schema_version seen, with counts
    All key orderings in the result are deterministic.
    """
    findings = load.findings
    ids = Counter(f.finding_id for f in findings)
    known = set(ids)
    dangling = sorted(
        {f.parent_id for f in findings if f.parent_id and f.parent_id not in known}
    )

    def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
        return {k: counter[k] for k in sorted(counter)}

    severity_counts = Counter(f.severity.value for f in findings)
    return {
        "ledger": str(load.path),
        "ledger_exists": load.exists,
        "total_findings": len(findings),
        "by_source": _sorted_counts(Counter(f.source_tool for f in findings)),
        # Severity listed in rank order, highest first, zeros included.
        "by_severity": {
            s.value: severity_counts.get(s.value, 0)
            for s in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True)
        },
        "by_category": _sorted_counts(Counter(f.category.value for f in findings)),
        "correlation_groups": len({f.correlation_id for f in findings if f.correlation_id}),
        "schema_versions": _sorted_counts(Counter(f.schema_version for f in findings)),
        "health": {
            "malformed_lines": len(load.malformed),
            "duplicate_ids": sorted(k for k, n in ids.items() if n > 1),
            "dangling_parents": dangling,
        },
    }


# ---------------------------------------------------------------------------
# correlate
# ---------------------------------------------------------------------------

BASIS_DECLARED = "declared"   # shared correlation_id
BASIS_INFERRED = "inferred"   # same file, overlapping lines


@dataclass(slots=True)
class CorrelationGroup:
    """Findings grouped for joint inspection.

    basis is either 'declared' (a tool attached a shared correlation_id)
    or 'inferred' (this module observed location overlap). key is the
    correlation_id for declared groups, or 'file:start-end' for inferred.
    A group is a pointer for a human to look, not a conclusion.
    """

    basis: str
    key: str
    entries: list[LedgerEntry]

    @property
    def sources(self) -> list[str]:
        return sorted({e.finding.source_tool for e in self.entries})

    @property
    def max_severity(self) -> Severity:
        return max((e.finding.severity for e in self.entries), key=SEVERITY_RANK.get)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _line_span(f: Finding) -> tuple[int, int] | None:
    """Line span of a finding, or None if it has no usable integer line.
    The envelope does not type-check location fields, so this does."""
    start = f.location.line
    if not _is_int(start):
        return None
    end = f.location.end_line if _is_int(f.location.end_line) else start
    return (min(start, end), max(start, end))


def correlate(
    entries: Sequence[LedgerEntry],
    *,
    correlation_id: str | None = None,
    infer_location: bool = False,
    min_sources: int = 1,
) -> list[CorrelationGroup]:
    """Group findings by declared correlation_id, and optionally by
    inferred location overlap.

    Declared groups: every correlation_id with its findings, in ledger
    order. If correlation_id is given, only that group.

    Inferred groups (infer_location=True): findings in the same file
    whose line spans overlap, merged transitively, and only where the
    group spans at least two distinct source tools. Findings without a
    file or line do not participate. Inference never assigns or edits a
    correlation_id; it only reports.

    min_sources drops groups touching fewer distinct source tools.
    Output order: declared groups first (by first ledger appearance),
    then inferred groups (by file, then start line).
    """
    groups: list[CorrelationGroup] = []

    declared: dict[str, list[LedgerEntry]] = {}
    for e in entries:
        cid = e.finding.correlation_id
        if cid and (correlation_id is None or cid == correlation_id):
            declared.setdefault(cid, []).append(e)
    for cid, members in declared.items():
        groups.append(CorrelationGroup(BASIS_DECLARED, cid, members))

    if infer_location and correlation_id is None:
        by_file: dict[str, list[tuple[int, int, LedgerEntry]]] = {}
        for e in entries:
            span = _line_span(e.finding)
            if isinstance(e.finding.location.file, str) and e.finding.location.file and span:
                by_file.setdefault(e.finding.location.file, []).append((*span, e))
        inferred: list[CorrelationGroup] = []
        for file_name in sorted(by_file):
            spans = sorted(by_file[file_name], key=lambda t: (t[0], t[1], t[2].line_no))
            cluster: list[LedgerEntry] = []
            c_start = c_end = 0
            for start, end, e in spans:
                if cluster and start <= c_end:
                    cluster.append(e)
                    c_end = max(c_end, end)
                    continue
                if cluster:
                    inferred.append(
                        CorrelationGroup(BASIS_INFERRED, f"{file_name}:{c_start}-{c_end}", cluster)
                    )
                cluster, c_start, c_end = [e], start, end
            if cluster:
                inferred.append(
                    CorrelationGroup(BASIS_INFERRED, f"{file_name}:{c_start}-{c_end}", cluster)
                )
        # Location overlap within one tool is just that tool's own
        # findings; only cross-tool overlap is reported.
        groups.extend(g for g in inferred if len(g.sources) >= 2)

    return [g for g in groups if len(g.sources) >= min_sources]


# Bismillah ir-Rahman ir-Rahim
