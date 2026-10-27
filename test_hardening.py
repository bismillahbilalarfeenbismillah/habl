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
    LedgerParseError,
    Location,
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


def test_f5_mutation_after_construction_caught_at_append():
    with tempfile.TemporaryDirectory() as r:
        append_finding(_f("a"), r)
        before = ledger_path(r).read_bytes()
        for field_name, value in (("timestamp", "not-a-time"), ("schema_version", "99.0.0"),
                                  ("severity", "loud"), ("source_tool", "evil")):
            bad = _f("b")
            setattr(bad, field_name, value)
            try:
                append_findings([_f("c"), bad], r)
            except (TypeError, ValueError):
                pass
            else:
                raise AssertionError(f"mutated {field_name} was written")
        assert ledger_path(r).read_bytes() == before


# --- F6: concurrent batch appends do not interleave ------------------------

def test_f6_concurrent_batches_stay_whole():
    code = textwrap.dedent("""
        import sys, tempfile, json, multiprocessing as mp
        sys.path.insert(0, sys.argv[1])
        from habl import Finding, Location, append_findings, ledger_path
        def w(root, tag):
            for i in range(15):
                append_findings([Finding(source_tool="habl", severity="advisory",
                    category="binding", summary=f"{tag}{i}.{j}", location=Location(),
                    payload={"pad": "x" * 1500}) for j in range(20)], root)
        if __name__ == "__main__":
            with tempfile.TemporaryDirectory() as root:
                ps = [mp.Process(target=w, args=(root, t)) for t in "ABCDEF"]
                [p.start() for p in ps]; [p.join() for p in ps]
                lines = open(ledger_path(root), encoding="utf-8").read().splitlines()
                bad = sum(1 for ln in lines if not ln.startswith("{") or not ln.endswith("}"))
                for ln in lines: json.loads(ln)
                print(len(lines), bad)
    """)
    with tempfile.TemporaryDirectory() as d:
        script = Path(d) / "stress.py"
        script.write_text(code)
        proc = subprocess.run([sys.executable, "-I", str(script), str(REPO)],
                              capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.split() == ["1800", "0"]


def test_f6_failed_serialization_leaves_ledger_unchanged():
    class Unserializable:
        pass
    with tempfile.TemporaryDirectory() as r:
        append_finding(_f("a"), r)
        before = ledger_path(r).read_bytes()
        bad = _f("b")
        bad.payload = {"obj": Unserializable()}
        _expect(TypeError, append_findings, [_f("c"), bad], r)
        assert ledger_path(r).read_bytes() == before


# --- F7: equal findings give equal bytes -----------------------------------

def test_f7_payload_key_order_does_not_change_bytes():
    a, b = _f("o"), _f("o")
    a.timestamp = b.timestamp = "2026-01-01T00:00:00+00:00"
    a.payload = {"one": 1, "two": {"y": 2, "x": 1}}
    b.payload = {"two": {"x": 1, "y": 2}, "one": 1}
    assert a.to_json() == b.to_json()
    assert Finding.from_json(a.to_json()).to_json() == a.to_json()


# --- F9 (GPT-6 re-audit): strict JSON in and out ---------------------------

def test_f9_non_finite_numbers_refused():
    for bad in (float("nan"), float("inf"), float("-inf")):
        _expect(ValueError, lambda v: Finding("habl", "advisory", "binding", "t",
                                              Location(), payload={"s": v}), bad)
        _expect(ValueError, lambda v: Finding("habl", "advisory", "binding", "t",
                                              Location(), payload={"a": [{"b": v}]}), bad)


def test_f9_nan_mutated_in_after_construction_not_written():
    with tempfile.TemporaryDirectory() as r:
        f = _f("a")
        f.payload["score"] = float("nan")
        _expect(ValueError, append_finding, f, r)
        assert not ledger_path(r).exists() or ledger_path(r).read_bytes() == b""


def test_f9_values_json_would_silently_change_are_refused():
    for payload in ({1: "a"}, {"t": (1, 2)}, {"s": {1}}, {"o": object()}):
        _expect(TypeError, lambda p: Finding("habl", "advisory", "binding", "t",
                                             Location(), payload=p), payload)


def test_f9_strict_payload_round_trips_exactly():
    p = {"n": None, "b": True, "i": -3, "f": 1.5, "s": "x", "l": [1, [2, {"k": "v"}]]}
    f = Finding("habl", "advisory", "binding", "t", Location(), payload=p)
    assert Finding.from_json(f.to_json()).payload == p


def test_f9_reader_rejects_nan_constant_and_duplicate_keys():
    good = _f("a").to_json()
    nan_line = good.replace('"payload":{}', '"payload":{"s":NaN}')
    dup_line = good.replace('"summary":"s"', '"summary":"first","summary":"second"')
    assert nan_line != good and dup_line != good
    for line, word in ((nan_line, "NaN"), (dup_line, "duplicate key 'summary'")):
        with tempfile.TemporaryDirectory() as r:
            path = ledger_path(r)
            path.parent.mkdir(parents=True)
            path.write_text(good + "\n" + line + "\n", encoding="utf-8")
            exc = _expect(LedgerParseError, read_ledger, r)
            assert exc.line_no == 2 and "invalid JSON" in exc.reason and word in exc.reason
            from habl.query import load_ledger
            load = load_ledger(r)
            assert len(load.entries) == 1 and load.malformed[0].line_no == 2
            assert word in load.malformed[0].reason


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
