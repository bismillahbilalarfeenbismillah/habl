# Bismillah ir-Rahman ir-Rahim
"""Smoke tests for the HABL v0.1 finding envelope."""
# Bismillah ir-Rahman ir-Rahim

import json
import tempfile
from pathlib import Path

from habl.envelope import (
    Category,
    Finding,
    Location,
    Severity,
    append_finding,
    append_findings,
    new_correlation_id,
    read_by_correlation,
    read_by_source,
    read_ledger,
    read_provenance_chain,
)


def test_finding_creation():
    """A finding can be created with all required fields."""
    f = Finding(
        source_tool="furqan-lint",
        severity=Severity.HIGH,
        category=Category.STRUCTURAL,
        summary="Function returns None on one branch without annotation",
        location=Location(file="app.py", line=42, function="get_user"),
        payload={"check": "return_none_mismatch", "marad": "D24"},
    )
    assert f.source_tool == "furqan-lint"
    assert f.severity == Severity.HIGH
    assert f.category == Category.STRUCTURAL
    assert f.location.file == "app.py"
    assert f.location.line == 42
    assert len(f.finding_id) == 16
    assert f.parent_id is None
    assert f.correlation_id is None
    print("  PASS: finding_creation")


def test_string_coercion():
    """Severity and category accept raw strings."""
    f = Finding(
        source_tool="bayyinah",
        severity="critical",
        category="mode_collapse",
        summary="Repetition score exceeds threshold",
        location=Location(file="model_output.txt", section="response_3"),
        payload={"mc_score": 0.87},
    )
    assert f.severity is Severity.CRITICAL
    assert f.category is Category.MODE_COLLAPSE
    print("  PASS: string_coercion")


def test_invalid_source_raises():
    """An unknown source_tool is rejected."""
    try:
        Finding(
            source_tool="unknown-tool",
            severity=Severity.ADVISORY,
            category=Category.BINDING,
            summary="test",
            location=Location(),
        )
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
    print("  PASS: invalid_source_raises")


def test_json_roundtrip():
    """A finding survives JSON serialization and deserialization."""
    original = Finding(
        source_tool="fatima",
        severity=Severity.MEDIUM,
        category=Category.SEAL,
        summary="Seal layer 77 hash mismatch after re-encoding",
        location=Location(file="document.md", seal_layer=77, domain=11),
        parent_id="abc123",
        correlation_id="habl-def456",
        payload={"expected_hash": "aaa", "actual_hash": "bbb"},
    )
    json_line = original.to_json()
    restored = Finding.from_json(json_line)

    assert restored.source_tool == original.source_tool
    assert restored.severity == original.severity
    assert restored.category == original.category
    assert restored.summary == original.summary
    assert restored.location.seal_layer == 77
    assert restored.location.domain == 11
    assert restored.parent_id == "abc123"
    assert restored.correlation_id == "habl-def456"
    assert restored.payload["expected_hash"] == "aaa"
    # JSON line is a single line, no newlines
    assert "\n" not in json_line
    print("  PASS: json_roundtrip")


def test_ledger_append_and_read():
    """Findings can be appended to and read from the ledger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = Finding(
            source_tool="furqan-lint",
            severity=Severity.HIGH,
            category=Category.STRUCTURAL,
            summary="Finding one",
            location=Location(file="a.py", line=10),
        )
        f2 = Finding(
            source_tool="bayyinah",
            severity=Severity.CRITICAL,
            category=Category.ADVERSARIAL,
            summary="Finding two",
            location=Location(file="b.py", line=20),
        )

        append_finding(f1, tmpdir)
        append_finding(f2, tmpdir)

        ledger = read_ledger(tmpdir)
        assert len(ledger) == 2
        assert ledger[0].summary == "Finding one"
        assert ledger[1].summary == "Finding two"

        # Verify the file is JSONL
        ledger_file = Path(tmpdir) / ".habl" / "findings.jsonl"
        lines = ledger_file.read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # each line is valid JSON
    print("  PASS: ledger_append_and_read")


def test_batch_append():
    """Multiple findings can be appended in one call."""
    with tempfile.TemporaryDirectory() as tmpdir:
        findings = [
            Finding(
                source_tool="fatima",
                severity=Severity.ADVISORY,
                category=Category.SEMANTIC,
                summary=f"Batch finding {i}",
                location=Location(file="doc.md"),
            )
            for i in range(5)
        ]
        append_findings(findings, tmpdir)
        ledger = read_ledger(tmpdir)
        assert len(ledger) == 5
    print("  PASS: batch_append")


def test_correlation_queries():
    """Findings can be queried by correlation ID."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cid = new_correlation_id()
        assert cid.startswith("habl-")

        f1 = Finding(
            source_tool="furqan-lint",
            severity=Severity.HIGH,
            category=Category.STRUCTURAL,
            summary="Lint found structural gap",
            location=Location(file="x.py", line=5),
            correlation_id=cid,
        )
        f2 = Finding(
            source_tool="bayyinah",
            severity=Severity.HIGH,
            category=Category.MODE_COLLAPSE,
            summary="Scanner found related collapse",
            location=Location(file="x.py", section="output"),
            correlation_id=cid,
        )
        f3 = Finding(
            source_tool="fatima",
            severity=Severity.ADVISORY,
            category=Category.SEAL,
            summary="Unrelated seal note",
            location=Location(file="y.py"),
        )

        append_findings([f1, f2, f3], tmpdir)

        correlated = read_by_correlation(cid, tmpdir)
        assert len(correlated) == 2
        assert all(f.correlation_id == cid for f in correlated)

        bayyinah_findings = read_by_source("bayyinah", tmpdir)
        assert len(bayyinah_findings) == 1
        assert bayyinah_findings[0].summary == "Scanner found related collapse"
    print("  PASS: correlation_queries")


def test_provenance_chain():
    """The retrograde signal chain can be walked backwards."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Root cause: furqan-lint finds a structural issue
        root = Finding(
            source_tool="furqan-lint",
            severity=Severity.HIGH,
            category=Category.STRUCTURAL,
            summary="Missing error return path",
            location=Location(file="handler.py", line=30, function="process"),
            finding_id="root0001",
        )
        # Bayyinah notices it correlates with a pattern
        child = Finding(
            source_tool="bayyinah",
            severity=Severity.HIGH,
            category=Category.ADVERSARIAL,
            summary="Missing path matches known adversarial pattern",
            location=Location(file="handler.py", line=30),
            finding_id="child002",
            parent_id="root0001",
        )
        # FATIMA flags the seal impact
        grandchild = Finding(
            source_tool="fatima",
            severity=Severity.CRITICAL,
            category=Category.SEAL,
            summary="Seal integrity compromised by unhandled path",
            location=Location(file="handler.py", seal_layer=42),
            finding_id="grand003",
            parent_id="child002",
        )

        append_findings([root, child, grandchild], tmpdir)

        chain = read_provenance_chain("grand003", tmpdir)
        assert len(chain) == 3
        assert chain[0].finding_id == "root0001"   # root cause first
        assert chain[1].finding_id == "child002"
        assert chain[2].finding_id == "grand003"
    print("  PASS: provenance_chain")


def test_empty_ledger():
    """Reading a non-existent ledger returns an empty list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = read_ledger(tmpdir)
        assert ledger == []
    print("  PASS: empty_ledger")


if __name__ == "__main__":
    print("HABL v0.1 -- Finding Envelope Tests")
    print("=" * 40)
    test_finding_creation()
    test_string_coercion()
    test_invalid_source_raises()
    test_json_roundtrip()
    test_ledger_append_and_read()
    test_batch_append()
    test_correlation_queries()
    test_provenance_chain()
    test_empty_ledger()
    print("=" * 40)
    print("All tests passed. The spore germinates.")


# Bismillah ir-Rahman ir-Rahim
