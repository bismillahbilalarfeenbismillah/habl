# Bismillah ir-Rahman ir-Rahim
"""Regression tests for GPT-6's Round 1 audit findings (F1-F8) on 0d743ff.

Each test names the finding it closes. Runs under pytest or directly:
python3 test_hardening.py
"""
# Bismillah ir-Rahman ir-Rahim

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from habl import (
    Category,
    DuplicateFindingIdError,
    Finding,
    LedgerIntegrityError,
    Location,
    LedgerParseError,
    ProvenanceCycleError,
    SchemaVersionError,
    Severity,
    append_finding,
    append_findings,
    ledger_path,
    read_ledger,
    read_provenance_chain,
)

REPO = Path(__file__).resolve().parent


def _f(fid: str, parent: str | None = None, summary: str = "s") -> Finding:
    return Finding(source_tool="habl", severity=Severity.ADVISORY,
                   category=Category.BINDING, summary=summary,
                   location=Location(file="x.py"), finding_id=fid, parent_id=parent)


def _expect(exc_type: type[BaseException], fn, *args):
    try:
        fn(*args)
    except exc_type as exc:
        return exc
    raise AssertionError(f"{exc_type.__name__} not raised")


# --- F2: cycles terminate -------------------------------------------------

def test_f2_cycle_walk_is_bounded_in_subprocess():
    """Guard against regression hanging the suite: run in a child with a timeout."""
    code = textwrap.dedent("""
        import sys, tempfile
        sys.path.insert(0, sys.argv[1])
        from habl import Finding, Location, append_findings, read_provenance_chain
        from habl import ProvenanceCycleError
        mk = lambda i, p: Finding(source_tool="habl", severity="advisory",
            category="binding", summary=i, location=Location(), finding_id=i, parent_id=p)
        with tempfile.TemporaryDirectory() as r:
            append_findings([mk("a", "b"), mk("b", "a")], r)
            try:
                read_provenance_chain("a", r)
            except ProvenanceCycleError as e:
                print("CYCLE", e.cycle)
    """)
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(REPO)],
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stderr
    assert "CYCLE ['a', 'b', 'a']" in proc.stdout


def test_f2_self_parent_raises_typed_error():
    with tempfile.TemporaryDirectory() as r:
        append_finding(_f("loop", "loop"), r)
        exc = _expect(ProvenanceCycleError, read_provenance_chain, "loop", r)
        assert exc.cycle == ["loop", "loop"]
        assert isinstance(exc, LedgerIntegrityError) and isinstance(exc, ValueError)


def test_f2_cycle_above_a_valid_tail():
    with tempfile.TemporaryDirectory() as r:
        append_findings([_f("x", "y"), _f("y", "z"), _f("z", "y"), _f("leaf", "x")], r)
        exc = _expect(ProvenanceCycleError, read_provenance_chain, "leaf", r)
        assert exc.cycle == ["y", "z", "y"]


# --- F3: duplicate ids are ambiguity, not a silent pick --------------------

def test_f3_duplicate_on_walk_raises():
    with tempfile.TemporaryDirectory() as r:
        append_findings([_f("dup", summary="first"), _f("dup", summary="second")], r)
        exc = _expect(DuplicateFindingIdError, read_provenance_chain, "dup", r)
        assert exc.finding_id == "dup" and exc.count == 2


def test_f3_duplicate_parent_raises():
    with tempfile.TemporaryDirectory() as r:
        append_findings([_f("p"), _f("p"), _f("child", "p")], r)
        _expect(DuplicateFindingIdError, read_provenance_chain, "child", r)


def test_f3_duplicate_off_the_walk_is_irrelevant():
    with tempfile.TemporaryDirectory() as r:
        append_findings([_f("other"), _f("other"), _f("root"), _f("leaf", "root")], r)
        assert [f.finding_id for f in read_provenance_chain("leaf", r)] == ["root", "leaf"]


def test_f2_f3_normal_chain_and_dangling_unchanged():
    with tempfile.TemporaryDirectory() as r:
        append_findings([_f("a", "elsewhere"), _f("b", "a"), _f("c", "b")], r)
        assert [f.finding_id for f in read_provenance_chain("c", r)] == ["a", "b", "c"]
        assert read_provenance_chain("missing", r) == []


# --- F1: deserialization does not mutate input -----------------------------

def test_f1_from_dict_leaves_input_intact():
    d = {"source_tool": "habl", "severity": "advisory", "category": "binding",
         "summary": "t", "location": {"file": "x.py", "line": 3}}
    snapshot = repr(d)
    f = Finding.from_dict(d)
    assert repr(d) == snapshot
    assert f.location.line == 3
    # Parsing the same dict twice gives the same location both times.
    assert Finding.from_dict(d).location == f.location


def test_f1_non_object_location_rejected():
    d = {"source_tool": "habl", "severity": "advisory", "category": "binding",
         "summary": "t", "location": "x.py:3"}
    _expect(TypeError, Finding.from_dict, d)


# --- F4: fail-stop read names the line -------------------------------------

def test_f4_truncated_final_record_names_line():
    with tempfile.TemporaryDirectory() as r:
        append_findings([_f("a"), _f("b")], r)
        with open(ledger_path(r), "a", encoding="utf-8") as fh:
            fh.write('{"source_tool":')
        exc = _expect(LedgerParseError, read_ledger, r)
        assert exc.line_no == 3 and "invalid JSON" in exc.reason
        assert isinstance(exc, ValueError)  # old `except ValueError` still catches


def test_f4_bad_field_type_names_line():
    with tempfile.TemporaryDirectory() as r:
        append_finding(_f("a"), r)
        with open(ledger_path(r), "a", encoding="utf-8") as fh:
            fh.write('{"source_tool":"habl","severity":"advisory","category":"binding",'
                     '"summary":"t","location":{"line":"7"}}\n')
        exc = _expect(LedgerParseError, read_ledger, r)
        assert exc.line_no == 2 and "Location.line must be int" in exc.reason


def test_f4_bom_reported_not_silently_stripped():
    with tempfile.TemporaryDirectory() as r:
        path = ledger_path(r)
        path.parent.mkdir(parents=True)
        path.write_bytes(b"\xef\xbb\xbf" + _f("a").to_json().encode() + b"\n")
        exc = _expect(LedgerParseError, read_ledger, r)
        assert exc.line_no == 1


def test_f4_crlf_lines_read_normally():
    with tempfile.TemporaryDirectory() as r:
        path = ledger_path(r)
        path.parent.mkdir(parents=True)
        path.write_bytes((_f("a").to_json() + "\r\n" + _f("b").to_json() + "\r\n").encode())
        assert [f.finding_id for f in read_ledger(r)] == ["a", "b"]


# --- F5: schema version, timestamp, field types ----------------------------

def test_f5_unsupported_schema_version_rejected():
    exc = _expect(SchemaVersionError, Finding, "habl", "advisory", "binding", "t",
                  Location(), "id1", "99.0.0")
    assert "99.0.0" in str(exc)


def test_f5_timestamp_must_be_iso_with_offset():
    for bad in ("not-a-time", "2026-10-27T10:00:00", "", "27/10/2026"):
        _expect(ValueError, lambda ts: Finding("habl", "advisory", "binding", "t",
                                               Location(), timestamp=ts), bad)
    ok = Finding("habl", "advisory", "binding", "t", Location(),
                 timestamp="2026-10-27T10:00:00Z")
    assert ok.timestamp.endswith("Z")  # stored as given, not rewritten


def test_f5_field_types_checked():
    _expect(TypeError, lambda: Finding("habl", "advisory", "binding", 5, Location()))
    _expect(TypeError, lambda: Finding("habl", "advisory", "binding", "t", Location(),
                                       parent_id=7))
    _expect(TypeError, lambda: Finding("habl", "advisory", "binding", "t", Location(),
                                       payload=[1]))
    _expect(TypeError, lambda: Location(line=True))
    _expect(TypeError, lambda: Location(file=3))


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
