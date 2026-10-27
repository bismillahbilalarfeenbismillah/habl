# Bismillah ir-Rahman ir-Rahim
"""Tests for HABL v0.1.1 query / stats / correlate (library and CLI).

Runs under pytest or directly: python3 test_cli.py
"""
# Bismillah ir-Rahman ir-Rahim

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from habl.cli import EXIT_MALFORMED, EXIT_OK, EXIT_USAGE, main
from habl.envelope import (
    Category,
    Finding,
    Location,
    Severity,
    append_findings,
    ledger_path,
)
from habl.query import compute_stats, correlate, filter_findings, load_ledger


def _seed(root: Path) -> dict[str, Finding]:
    """A small mixed ledger: three tools, one declared correlation,
    one cross-tool location overlap, one same-tool overlap, one orphan
    parent reference."""
    f = {
        "lint_a": Finding(
            source_tool="furqan-lint", severity=Severity.HIGH,
            category=Category.STRUCTURAL, summary="D24: path returns None",
            location=Location(file="app.py", line=10, function="get"),
            finding_id="lint_a", correlation_id="habl-c1",
            timestamp="2026-10-27T10:00:00+00:00",
        ),
        "bay_a": Finding(
            source_tool="bayyinah", severity=Severity.MEDIUM,
            category=Category.ADVERSARIAL, summary="pattern near get()",
            location=Location(file="app.py", line=8, end_line=12),
            finding_id="bay_a", correlation_id="habl-c1",
            timestamp="2026-10-27T11:00:00+00:00",
        ),
        "fat_a": Finding(
            source_tool="fatima", severity=Severity.CRITICAL,
            category=Category.SEAL, summary="seal mismatch",
            location=Location(file="app.py", line=12, seal_layer=7),
            finding_id="fat_a",
            timestamp="2026-10-27T12:00:00+00:00",
        ),
        "lint_b": Finding(
            source_tool="furqan-lint", severity=Severity.ADVISORY,
            category=Category.STRUCTURAL, summary="advisory elsewhere",
            location=Location(file="other.py", line=3),
            finding_id="lint_b", parent_id="missing_parent",
            timestamp="2026-10-27T13:00:00+00:00",
        ),
        "lint_c": Finding(
            source_tool="furqan-lint", severity=Severity.ADVISORY,
            category=Category.STRUCTURAL, summary="same-tool overlap",
            location=Location(file="other.py", line=3),
            finding_id="lint_c",
            timestamp="2026-10-27T14:00:00+00:00",
        ),
    }
    append_findings(list(f.values()), root)
    return f


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out, err)
    return code, out.getvalue(), err.getvalue()


# --- library: load ---------------------------------------------------------

def test_load_missing_ledger():
    with tempfile.TemporaryDirectory() as d:
        load = load_ledger(d)
        assert not load.exists and load.entries == [] and load.malformed == []


def test_load_reports_every_malformed_line():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _seed(root)
        path = ledger_path(root)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("{not json\n")                                  # bad JSON
            fh.write("[1, 2]\n")                                      # not an object
            fh.write('{"source_tool": "evil", "severity": "high", "category": "seal",'
                     ' "summary": "x", "location": {}}\n')            # bad source
            fh.write('{"source_tool": "habl", "severity": "high", "category": "seal",'
                     ' "summary": "x", "location": {"future_field": 1}}\n')  # unknown key
            fh.write('{"source_tool": "habl", "severity": "high", "category": "seal",'
                     ' "summary": "x", "location": {}, "v2_field": true}\n')  # unknown top key
            fh.write("\n   \n")                                      # blanks: ignored
        load = load_ledger(root)
        assert len(load.entries) == 5
        assert [m.line_no for m in load.malformed] == [6, 7, 8, 9, 10]
        assert "invalid JSON" in load.malformed[0].reason
        assert "expected JSON object" in load.malformed[1].reason


def test_entries_keep_ledger_line_numbers():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        assert [e.line_no for e in load_ledger(d).entries] == [1, 2, 3, 4, 5]


# --- library: query --------------------------------------------------------

def test_filter_and_semantics():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        entries = load_ledger(d).entries
        ids = lambda es: [e.finding.finding_id for e in es]  # noqa: E731
        assert ids(filter_findings(entries, sources=["furqan-lint"])) == ["lint_a", "lint_b", "lint_c"]
        assert ids(filter_findings(entries, sources=["furqan-lint", "fatima"],
                                   file="app.py")) == ["lint_a", "fat_a"]
        assert ids(filter_findings(entries, min_severity=Severity.HIGH)) == ["lint_a", "fat_a"]
        assert ids(filter_findings(entries, categories=[Category.SEAL])) == ["fat_a"]
        assert ids(filter_findings(entries, correlation_id="habl-c1")) == ["lint_a", "bay_a"]


def test_time_window_inclusive_and_z_suffix():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        entries = load_ledger(d).entries
        got = filter_findings(entries, since="2026-10-27T11:00:00Z",
                              until="2026-10-27T12:00:00+00:00")
        assert [e.finding.finding_id for e in got] == ["bay_a", "fat_a"]
        # Same instant expressed in another offset.
        got = filter_findings(entries, since="2026-10-27T07:00:00-05:00")
        assert [e.finding.finding_id for e in got] == ["fat_a", "lint_b", "lint_c"]


def test_naive_time_filter_rejected():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        try:
            filter_findings(load_ledger(d).entries, since="2026-10-27T11:00:00")
        except ValueError as exc:
            assert "no timezone" in str(exc)
        else:
            raise AssertionError("naive timestamp accepted")


def test_unparseable_timestamp_reported_as_malformed():
    """Since F5, a bad timestamp is rejected at parse time and reported,
    rather than sitting in the ledger and quietly failing time filters."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _seed(root)
        with open(ledger_path(root), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"source_tool": "habl", "severity": "advisory",
                                 "category": "binding", "summary": "bad ts",
                                 "location": {}, "timestamp": "yesterday"}) + "\n")
        load = load_ledger(root)
        assert len(load.entries) == 5
        assert [m.line_no for m in load.malformed] == [6]
        assert "not ISO-8601" in load.malformed[0].reason


# --- library: stats --------------------------------------------------------

def test_stats_counts_and_health():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        f = _seed(root)
        append_findings([f["fat_a"]], root)  # duplicate id
        with open(ledger_path(root), "a", encoding="utf-8") as fh:
            fh.write("garbage\n")
        s = compute_stats(load_ledger(root))
        assert s["total_findings"] == 6
        assert s["by_source"] == {"bayyinah": 1, "fatima": 2, "furqan-lint": 3}
        assert list(s["by_severity"]) == ["critical", "high", "medium", "advisory"]
        assert s["by_severity"] == {"critical": 2, "high": 1, "medium": 1, "advisory": 2}
        assert s["correlation_groups"] == 1
        assert s["health"] == {"malformed_lines": 1, "duplicate_ids": ["fat_a"],
                               "dangling_parents": ["missing_parent"]}


def test_stats_deterministic_across_append_order():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        f = _seed(Path(d1))
        append_findings(list(reversed(list(f.values()))), Path(d2))
        a = json.dumps(compute_stats(load_ledger(d1)) | {"ledger": ""})
        b = json.dumps(compute_stats(load_ledger(d2)) | {"ledger": ""})
        assert a == b


# --- library: correlate ----------------------------------------------------

def test_correlate_declared_only_by_default():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        groups = correlate(load_ledger(d).entries)
        assert [(g.basis, g.key) for g in groups] == [("declared", "habl-c1")]
        assert groups[0].sources == ["bayyinah", "furqan-lint"]
        assert groups[0].max_severity == Severity.HIGH


def test_correlate_inferred_is_labelled_and_cross_tool_only():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        groups = correlate(load_ledger(d).entries, infer_location=True)
        inferred = [g for g in groups if g.basis == "inferred"]
        # app.py lines 8-12 cover lint_a(10), bay_a(8-12), fat_a(12).
        # other.py:3 has two furqan-lint findings only -> not reported.
        assert [(g.key, g.sources) for g in inferred] == [
            ("app.py:8-12", ["bayyinah", "fatima", "furqan-lint"])
        ]


def test_correlate_does_not_mutate_ledger():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        before = ledger_path(d).read_bytes()
        correlate(load_ledger(d).entries, infer_location=True)
        assert ledger_path(d).read_bytes() == before


def test_correlate_min_sources_and_non_int_lines():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _seed(root)
        with open(ledger_path(root), "a", encoding="utf-8") as fh:
            # Since F5 the envelope type-checks line: reported, not grouped.
            fh.write(json.dumps({"source_tool": "habl", "severity": "advisory",
                                 "category": "binding", "summary": "str line",
                                 "location": {"file": "app.py", "line": "10"}}) + "\n")
        load = load_ledger(root)
        assert "Location.line must be int" in load.malformed[0].reason
        entries = load.entries
        assert correlate(entries, min_sources=3) == []
        groups = correlate(entries, infer_location=True, min_sources=3)
        assert [g.key for g in groups] == ["app.py:8-12"]


# --- CLI -------------------------------------------------------------------

def test_cli_query_jsonl_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        code, out, err = _run(["query", "--root", d, "--format", "jsonl", "--source", "fatima"])
        assert code == EXIT_OK and err == ""
        rows = [json.loads(line) for line in out.splitlines()]
        assert [r["finding_id"] for r in rows] == ["fat_a"]
        assert rows[0]["_ledger_line"] == 3


def test_cli_output_is_deterministic():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        for cmd in (["query"], ["stats"], ["correlate", "--infer-location"]):
            for fmt in ("text", "json"):
                a = _run([*cmd, "--root", d, "--format", fmt])
                b = _run([*cmd, "--root", d, "--format", fmt])
                assert a == b, (cmd, fmt)


def test_cli_strict_exit_and_stderr_report():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        with open(ledger_path(d), "a", encoding="utf-8") as fh:
            fh.write("{oops\n")
        code, out, err = _run(["stats", "--root", d])
        assert code == EXIT_OK and "line 6: invalid JSON" in err
        code, _, err = _run(["stats", "--root", d, "--strict"])
        assert code == EXIT_MALFORMED and "line 6" in err


def test_cli_usage_errors():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        assert _run(["query", "--root", d, "--since", "2026-10-27"])[0] == EXIT_USAGE
        assert _run(["query", "--root", d, "--limit", "-1"])[0] == EXIT_USAGE
        assert _run(["correlate", "--root", d, "--min-sources", "0"])[0] == EXIT_USAGE
        assert _run(["correlate", "--root", d, "--id", "x", "--infer-location"])[0] == EXIT_USAGE


def test_cli_correlate_text_carries_non_verdict_note():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        code, out, _ = _run(["correlate", "--root", d, "--infer-location"])
        assert code == EXIT_OK
        assert "declared correlation: habl-c1" in out
        assert "inferred location overlap: app.py:8-12" in out
        assert "not a verdict" in out


def test_cli_missing_ledger_is_not_an_error():
    with tempfile.TemporaryDirectory() as d:
        code, out, err = _run(["query", "--root", d])
        assert code == EXIT_OK and "No ledger" in out and "0 finding(s)" in out


def test_python_dash_m_entry_point():
    with tempfile.TemporaryDirectory() as d:
        _seed(Path(d))
        proc = subprocess.run([sys.executable, "-m", "habl", "stats", "--root", d,
                               "--format", "json"], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout)["total_findings"] == 5


if __name__ == "__main__":
    tests = [(n, fn) for n, fn in sorted(globals().items())
             if n.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS: {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL: {name}: {exc!r}")
    print("=" * 40)
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)

# Bismillah ir-Rahman ir-Rahim
