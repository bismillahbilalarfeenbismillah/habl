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
    ProvenanceCycleError,
    Severity,
    append_finding,
    append_findings,
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
