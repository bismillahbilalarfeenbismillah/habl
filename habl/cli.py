# Bismillah ir-Rahman ir-Rahim
"""HABL command line -- habl query | stats | correlate.

Exit codes:
    0  success
    1  --strict was given and the ledger has malformed lines
    2  usage error (bad argument value)

Malformed ledger lines are always reported on stderr with line numbers,
whatever the exit code. Output on stdout is deterministic for a given
ledger and arguments.
"""
# Bismillah ir-Rahman ir-Rahim

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any, TextIO

from habl.envelope import VALID_SOURCES, Category, Severity, __version__
from habl.query import (
    BASIS_DECLARED,
    CorrelationGroup,
    LedgerEntry,
    LedgerLoad,
    compute_stats,
    correlate,
    filter_findings,
    load_ledger,
)

EXIT_OK = 0
EXIT_MALFORMED = 1
EXIT_USAGE = 2


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _entry_dict(entry: LedgerEntry) -> dict[str, Any]:
    d = entry.finding.to_dict()
    d["_ledger_line"] = entry.line_no
    return d


def _format_location(entry: LedgerEntry) -> str:
    loc = entry.finding.location
    parts: list[str] = []
    if loc.file:
        where = str(loc.file)
        if loc.line is not None:
            where += f":{loc.line}"
            if loc.end_line is not None and loc.end_line != loc.line:
                where += f"-{loc.end_line}"
        parts.append(where)
    if loc.function:
        parts.append(f"in {loc.function}")
    if loc.section:
        parts.append(f"section {loc.section}")
    if loc.seal_layer is not None:
        parts.append(f"seal layer {loc.seal_layer}")
    return " ".join(parts) if parts else "(no location)"


def _format_entry_text(entry: LedgerEntry) -> str:
    f = entry.finding
    head = (
        f"[{f.severity.value.upper():8}] {f.source_tool:12} "
        f"{f.category.value:13} {f.finding_id}"
    )
    lines = [head, f"    {_format_location(entry)}", f"    {f.summary}"]
    links = []
    if f.correlation_id:
        links.append(f"correlation={f.correlation_id}")
    if f.parent_id:
        links.append(f"parent={f.parent_id}")
    if links:
        lines.append("    " + " ".join(links))
    return "\n".join(lines)


def _report_malformed(load: LedgerLoad, err: TextIO) -> None:
    if not load.malformed:
        return
    err.write(
        f"habl: {len(load.malformed)} malformed line(s) in {load.path} "
        "(not included in results):\n"
    )
    for m in load.malformed:
        err.write(f"  line {m.line_no}: {m.reason}\n")


def _finish(load: LedgerLoad, args: argparse.Namespace, err: TextIO) -> int:
    _report_malformed(load, err)
    if args.strict and load.malformed:
        return EXIT_MALFORMED
    return EXIT_OK


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_query(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    load = load_ledger(args.root)
    try:
        results = filter_findings(
            load.entries,
            sources=args.source or (),
            severities=[Severity(s) for s in args.severity or ()],
            min_severity=Severity(args.min_severity) if args.min_severity else None,
            categories=[Category(c) for c in args.category or ()],
            file=args.file,
            correlation_id=args.correlation,
            since=args.since,
            until=args.until,
        )
    except ValueError as exc:
        err.write(f"habl query: {exc}\n")
        return EXIT_USAGE

    if args.limit is not None:
        results = results[: args.limit]

    if args.format == "jsonl":
        for e in results:
            out.write(json.dumps(_entry_dict(e), sort_keys=True) + "\n")
    elif args.format == "json":
        out.write(json.dumps([_entry_dict(e) for e in results], indent=2, sort_keys=True) + "\n")
    else:
        if not load.exists:
            out.write(f"No ledger at {load.path}\n")
        for e in results:
            out.write(_format_entry_text(e) + "\n")
        out.write(f"{len(results)} finding(s)\n")
    return _finish(load, args, err)


def cmd_stats(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    load = load_ledger(args.root)
    stats = compute_stats(load)

    if args.format == "json":
        out.write(json.dumps(stats, indent=2) + "\n")
        return _finish(load, args, err)

    w = out.write
    w(f"Ledger: {stats['ledger']}" + ("" if stats["ledger_exists"] else "  (does not exist)") + "\n")
    w(f"Findings: {stats['total_findings']}\n")
    for title, key in (("By source", "by_source"), ("By severity", "by_severity"),
                       ("By category", "by_category"), ("Schema versions", "schema_versions")):
        w(f"\n{title}:\n")
        if not stats[key]:
            w("  (none)\n")
        for name, n in stats[key].items():
            w(f"  {name:16} {n}\n")
    w(f"\nCorrelation groups (declared): {stats['correlation_groups']}\n")
    h = stats["health"]
    w("\nLedger health:\n")
    w(f"  malformed lines   {h['malformed_lines']}\n")
    w(f"  duplicate ids     {len(h['duplicate_ids'])}"
      + (f"  {', '.join(h['duplicate_ids'])}" if h["duplicate_ids"] else "") + "\n")
    w(f"  dangling parents  {len(h['dangling_parents'])}"
      + (f"  {', '.join(h['dangling_parents'])}" if h["dangling_parents"] else "") + "\n")
    return _finish(load, args, err)


def _group_dict(g: CorrelationGroup) -> dict[str, Any]:
    return {
        "basis": g.basis,
        "key": g.key,
        "sources": g.sources,
        "max_severity": g.max_severity.value,
        "findings": [_entry_dict(e) for e in g.entries],
    }


def cmd_correlate(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    load = load_ledger(args.root)
    if args.min_sources < 1:
        err.write("habl correlate: --min-sources must be >= 1\n")
        return EXIT_USAGE
    if args.id and args.infer_location:
        err.write("habl correlate: --id and --infer-location are mutually exclusive\n")
        return EXIT_USAGE

    groups = correlate(
        load.entries,
        correlation_id=args.id,
        infer_location=args.infer_location,
        min_sources=args.min_sources,
    )

    if args.format == "json":
        out.write(json.dumps([_group_dict(g) for g in groups], indent=2, sort_keys=True) + "\n")
        return _finish(load, args, err)

    for g in groups:
        label = "declared correlation" if g.basis == BASIS_DECLARED else "inferred location overlap"
        out.write(
            f"== {label}: {g.key}  "
            f"[{len(g.entries)} finding(s), sources: {', '.join(g.sources)}, "
            f"max severity: {g.max_severity.value}]\n"
        )
        for e in g.entries:
            out.write(_format_entry_text(e) + "\n")
        out.write("\n")
    out.write(f"{len(groups)} group(s)\n")
    if groups:
        out.write(
            "Note: a group marks findings for joint inspection. It is not a "
            "verdict, and each finding stays attributable to its own tool.\n"
        )
    return _finish(load, args, err)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    severities = [s.value for s in Severity]
    categories = [c.value for c in Category]

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=".",
                        help="project root containing .habl/ (default: current directory)")
    common.add_argument("--strict", action="store_true",
                        help="exit 1 if the ledger contains malformed lines")

    parser = argparse.ArgumentParser(
        prog="habl",
        description="HABL -- Honesty-Attested Binding Ledger: read and inspect findings.",
    )
    parser.add_argument("--version", action="version", version=f"habl {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    q = sub.add_parser("query", parents=[common], help="filter findings")
    q.add_argument("--source", action="append", choices=sorted(VALID_SOURCES),
                   help="source tool (repeatable)")
    q.add_argument("--severity", action="append", choices=severities,
                   help="exact severity (repeatable)")
    q.add_argument("--min-severity", choices=severities,
                   help="this severity or higher")
    q.add_argument("--category", action="append", choices=categories,
                   help="category (repeatable)")
    q.add_argument("--file", help="exact location.file match")
    q.add_argument("--correlation", help="correlation_id")
    q.add_argument("--since", help="ISO-8601 timestamp with offset, inclusive")
    q.add_argument("--until", help="ISO-8601 timestamp with offset, inclusive")
    q.add_argument("--limit", type=int, help="maximum findings to print")
    q.add_argument("--format", choices=["text", "json", "jsonl"], default="text")
    q.set_defaults(func=cmd_query)

    s = sub.add_parser("stats", parents=[common], help="counts and ledger health")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.set_defaults(func=cmd_stats)

    c = sub.add_parser("correlate", parents=[common],
                       help="group related findings for joint inspection")
    c.add_argument("--id", help="show only this correlation_id")
    c.add_argument("--infer-location", action="store_true",
                   help="also group cross-tool findings with overlapping file/line spans "
                        "(reported as inferred, never written back)")
    c.add_argument("--min-sources", type=int, default=1,
                   help="only groups spanning at least N distinct source tools (default 1)")
    c.add_argument("--format", choices=["text", "json"], default="text")
    c.set_defaults(func=cmd_correlate)

    return parser


def main(
    argv: Sequence[str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "limit", None) is not None and args.limit < 0:
        err.write("habl query: --limit must be >= 0\n")
        return EXIT_USAGE
    return int(args.func(args, out, err))


if __name__ == "__main__":
    raise SystemExit(main())

# Bismillah ir-Rahman ir-Rahim
