# Bismillah ir-Rahman ir-Rahim
"""Independent adversarial probes for HABL PR #1 at f1595aa.

Execute from repository root: python -m pytest -q /path/to/test_gpt_habl_pr1.py
Requires HABL installed (`pip install -e .`) or PYTHONPATH set to checkout root.
Written by GPT-6 (independent audit of f1595aa). Committed by Claude with one change,
requested by GPT-6 at 02d67a8: the NaN characterization test now asserts refusal.
"""
from __future__ import annotations

import json
import multiprocessing as mp
from pathlib import Path

import pytest

from habl import (Category, Finding, Location, Severity, append_finding,
                  append_findings, ledger_path, read_ledger, read_provenance_chain)
from habl.envelope import (DuplicateFindingIdError, LedgerParseError,
                            ProvenanceCycleError, SchemaVersionError)


def finding(name='x', **kwargs):
    return Finding(source_tool='habl', severity=Severity.ADVISORY,
                   category=Category.BINDING, summary=name, location=Location(file='a.py'),
                   finding_id=name, **kwargs)


def test_f1_decode_does_not_mutate_input():
    d = finding('f1').to_dict()
    copy = json.loads(json.dumps(d))
    assert Finding.from_dict(d).finding_id == 'f1'
    assert d == copy


def test_f2_self_and_multinode_cycles_raise(tmp_path):
    append_finding(finding('self', parent_id='self'), tmp_path)
    with pytest.raises(ProvenanceCycleError):
        read_provenance_chain('self', tmp_path)
    second = tmp_path / 'other'
    append_findings([finding('a', parent_id='b'), finding('b', parent_id='a')], second)
    with pytest.raises(ProvenanceCycleError):
        read_provenance_chain('a', second)


def test_f3_duplicate_id_is_ambiguous_not_last_write_wins(tmp_path):
    append_findings([finding('dup'), finding('dup')], tmp_path)
    with pytest.raises(DuplicateFindingIdError):
        read_provenance_chain('dup', tmp_path)
    assert len(read_ledger(tmp_path)) == 2


def test_f4_truncated_jsonl_gives_line_context(tmp_path):
    append_finding(finding('good'), tmp_path)
    with ledger_path(tmp_path).open('a', encoding='utf-8') as fd:
        fd.write('{"incomplete":')
    with pytest.raises(LedgerParseError) as err:
        read_ledger(tmp_path)
    assert err.value.line_no == 2


def test_f5_schema_timestamp_type_policy(tmp_path):
    with pytest.raises(SchemaVersionError):
        finding('badversion', schema_version='9.9.9')
    with pytest.raises(ValueError):
        finding('badtime', timestamp='yesterday')
    with pytest.raises(ValueError):
        finding('naive', timestamp='2026-10-27T08:00:00')
    with pytest.raises(TypeError):
        Location(line='12')


def test_append_mutation_revalidated_and_batch_unwritten(tmp_path):
    first = finding('okay')
    last = finding('changed')
    last.schema_version = '9.9.9'
    with pytest.raises(SchemaVersionError):
        append_findings([first, last], tmp_path)
    assert not ledger_path(tmp_path).exists() or ledger_path(tmp_path).read_bytes() == b''


def test_f7_stable_nested_payload_key_order():
    a = finding('stable', payload={'z': {'y': 1, 'x': 2}, 'a': 3},
                timestamp='2026-10-27T04:00:00+00:00')
    b = finding('stable', payload={'a': 3, 'z': {'x': 2, 'y': 1}},
                timestamp='2026-10-27T04:00:00+00:00')
    assert a.to_json().encode('utf-8') == b.to_json().encode('utf-8')


def _worker(root: str, worker: int, count: int, size: int):
    payload = 'x' * size
    for j in range(count):
        append_findings([finding(f'{worker}-{j}', payload={'blob': payload})], root)


@pytest.mark.parametrize('size', [32, 16_000])
def test_f6_eight_processes_no_corrupt_jsonl(tmp_path, size):
    # POSIX-only contract; do not infer Windows safety from these results.
    import os
    if os.name != 'posix':
        pytest.skip('POSIX flock only')
    ctx = mp.get_context('spawn')
    procs = [ctx.Process(target=_worker, args=(str(tmp_path), i, 100, size))
             for i in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        if p.is_alive():
            p.terminate()
            p.join(timeout=10)
            pytest.fail('writer timed out')
        assert p.exitcode == 0
    raw = ledger_path(tmp_path).read_bytes().splitlines()
    assert len(raw) == 800
    assert len([json.loads(x) for x in raw]) == 800
    assert len(read_ledger(tmp_path)) == 800


@pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf')])
def test_nonfinite_float_payload_refused(tmp_path, value):
    # Was a characterization test of the pre-F9 behaviour (NaN written to
    # the ledger). Since 02d67a8 non-finite numbers are refused, at
    # construction and again at append, and nothing reaches the ledger.
    with pytest.raises(ValueError):
        finding('nan_payload', payload={'score': value})
    f = finding('nan_later')
    f.payload['score'] = value
    with pytest.raises(ValueError):
        append_finding(f, tmp_path)
    assert not ledger_path(tmp_path).exists() or ledger_path(tmp_path).read_bytes() == b''

# Bismillah ir-Rahman ir-Rahim
