# Bismillah ir-Rahman ir-Rahim
"""HABL v0.1 -- Honesty-Attested Binding Ledger.

The finding envelope: the mycorrhizal spore that every tool in the
Bayyinah structural-honesty stack emits into and consumes from.

    Furqan (the language)    -- THC   -- structural grammar
    FATIMA (the encoder)     -- CBD   -- protection / sealing
    furqan-lint (the linter) -- Myrcene -- path verification
    Bayyinah Scanner         -- Limonene -- anomaly detection
    HABL (this)              -- Cannaflavin A -- connective tissue

Reference: Ali 'Imran 3:103
    "And hold firmly to the rope of Allah all together
     and do not become divided."

Schema version: 0.1.0
"""
# Bismillah ir-Rahman ir-Rahim

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import IO, Any, Iterator

try:  # POSIX advisory locking; absent on Windows
    import fcntl as _fcntl
except ImportError:  # pragma: no cover
    _fcntl = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants -- the seven values from the du'as
# ---------------------------------------------------------------------------

__version__ = "0.1.1"

HABL_SCHEMA_VERSION = "0.1.0"

# Schema versions this reader can interpret. A finding declaring any
# other version is rejected with SchemaVersionError rather than read as
# if it meant the same thing. Forward-compatibility policy (whether a
# reader should accept newer minors and preserve unknown fields) is an
# open decision for v0.2.
SUPPORTED_SCHEMA_VERSIONS = frozenset({HABL_SCHEMA_VERSION})

# The five source tools in the entourage
VALID_SOURCES = frozenset({
    "furqan",        # the language       (THC)
    "furqan-lint",   # the linter         (Myrcene)
    "fatima",        # the encoder/sealer (CBD)
    "bayyinah",      # the scanner        (Limonene)
    "habl",          # self-findings      (Cannaflavin A)
})


class Severity(str, Enum):
    """Finding severity -- mirrors the Class A/B/C/D taxonomy
    from the XZ Protocol audit rounds, compressed to four levels."""

    CRITICAL = "critical"   # Class A -- structural break
    HIGH = "high"           # Class B -- significant gap
    MEDIUM = "medium"       # Class C -- notable concern
    ADVISORY = "advisory"   # Class D -- informational


class Category(str, Enum):
    """Finding category -- what dimension of honesty is affected.

    These map to the entourage's division of labor:
        structural   -> furqan-lint (D24, D11, R3, return_none_mismatch)
        semantic     -> FATIMA semantic engine (v6.0, 7 levels)
        temporal     -> FATIMA temporal engine (v7.0)
        seal         -> FATIMA seal/audit engine (154-layer)
        adversarial  -> Bayyinah adversarial pattern analysis
        mode_collapse -> Bayyinah mode-collapse detection
        binding      -> HABL itself (cross-tool correlation findings)
    """

    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    TEMPORAL = "temporal"
    SEAL = "seal"
    ADVERSARIAL = "adversarial"
    MODE_COLLAPSE = "mode_collapse"
    BINDING = "binding"


# ---------------------------------------------------------------------------
# Integrity errors -- typed, so callers never have to parse messages
# ---------------------------------------------------------------------------

class LedgerIntegrityError(ValueError):
    """The ledger cannot answer a question without silently choosing.

    Subclasses ValueError so existing `except ValueError` handlers keep
    working.
    """


class ProvenanceCycleError(LedgerIntegrityError):
    """A parent_id chain revisits a finding it has already passed."""

    def __init__(self, cycle: list[str]) -> None:
        self.cycle = cycle
        super().__init__("provenance cycle: " + " -> ".join(cycle))


class DuplicateFindingIdError(LedgerIntegrityError):
    """A finding_id needed for an answer appears on more than one line."""

    def __init__(self, finding_id: str, count: int) -> None:
        self.finding_id = finding_id
        self.count = count
        super().__init__(
            f"finding_id {finding_id!r} appears {count} times in the ledger; "
            "provenance through it is ambiguous"
        )


class LedgerParseError(LedgerIntegrityError):
    """A ledger line could not be read as a Finding."""

    def __init__(self, path: Path, line_no: int, reason: str) -> None:
        self.path = path
        self.line_no = line_no
        self.reason = reason
        super().__init__(f"{path}:{line_no}: {reason}")


class SchemaVersionError(ValueError):
    """A finding declares a schema_version this reader does not support."""


# ---------------------------------------------------------------------------
# Strict JSON -- what one tool writes, any standard parser reads the same
# ---------------------------------------------------------------------------

def _check_json_value(value: Any, where: str) -> None:
    """Require a strict-JSON value: str keys, finite numbers, list not tuple.

    Anything that json.dumps would silently convert (int keys, tuples)
    or emit as non-standard JSON (NaN, Infinity) is rejected, so a
    finding reads back equal to what was written, in any language.
    """
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            msg = f"{where}: non-finite number {value!r} is not valid JSON"
            raise ValueError(msg)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_json_value(item, f"{where}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                msg = f"{where}: key {key!r} must be str, got {type(key).__name__}"
                raise TypeError(msg)
            _check_json_value(item, f"{where}.{key}")
        return
    msg = f"{where}: {type(value).__name__} is not a JSON type"
    raise TypeError(msg)


class StrictJSONError(ValueError):
    """A line is syntactically JSON but not strict JSON (NaN/Infinity
    constant, or the same key twice in one object)."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            msg = f"duplicate key {key!r}"
            raise StrictJSONError(msg)
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    msg = f"non-standard constant {name}"
    raise StrictJSONError(msg)


def strict_loads(line: str) -> Any:
    """json.loads that rejects NaN/Infinity and duplicate object keys."""
    return json.loads(
        line,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )


# ---------------------------------------------------------------------------
# Location -- where in the artifact the finding lives
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Location:
    """A finding's position in the artifact under examination.

    Not every field applies to every tool -- furqan-lint uses file/line/
    function, FATIMA uses file/seal_layer/domain, Bayyinah uses file/
    section. Each tool fills what it has; consumers read what they need.
    """

    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    function: str | None = None
    ast_node: str | None = None
    seal_layer: int | None = None
    domain: int | None = None       # 1-22 in FATIMA's architecture
    section: str | None = None      # for document-level findings

    def __post_init__(self) -> None:
        for name in ("line", "end_line", "seal_layer", "domain"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                msg = f"Location.{name} must be int or None, got {type(value).__name__}"
                raise TypeError(msg)
        for name in ("file", "function", "ast_node", "section"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                msg = f"Location.{name} must be str or None, got {type(value).__name__}"
                raise TypeError(msg)


# ---------------------------------------------------------------------------
# The Finding Envelope -- the spore
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Finding:
    """A single finding from any tool in the entourage.

    This is the unit of exchange in the mycorrhizal network. Every tool
    emits these; every tool can consume these. The provenance chain is
    built through parent_id and correlation_id:

        parent_id      -- the finding that *caused* this one to be
                          emitted (retrograde signal)
        correlation_id -- groups related findings across tools that
                          pertain to the same underlying issue
                          (lateral signal)

    The payload carries tool-specific detail that the envelope schema
    does not constrain. A furqan-lint Marad, a Bayyinah MC-score
    breakdown, a FATIMA seal hash -- each goes in payload as the tool
    sees fit. The envelope is the common shape; the payload is the
    tool's own voice.
    """

    # --- Required fields ---
    source_tool: str                # one of VALID_SOURCES
    severity: Severity
    category: Category
    summary: str                    # one-line human description
    location: Location

    # --- Identity ---
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    schema_version: str = field(default=HABL_SCHEMA_VERSION)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # --- Provenance chain (the retrograde / lateral signals) ---
    parent_id: str | None = None        # finding that triggered this one
    correlation_id: str | None = None   # shared across related findings

    # --- Tool-specific payload ---
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source_tool not in VALID_SOURCES:
            msg = (
                f"source_tool {self.source_tool!r} not in "
                f"VALID_SOURCES: {sorted(VALID_SOURCES)}"
            )
            raise ValueError(msg)
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.category, str):
            self.category = Category(self.category)
        self.validate()

    def validate(self) -> None:
        """Check every field. Called at construction and again at append,
        because Finding is mutable and a field may change in between."""
        if self.source_tool not in VALID_SOURCES:
            msg = f"source_tool {self.source_tool!r} not in VALID_SOURCES"
            raise ValueError(msg)
        if not isinstance(self.severity, Severity):
            msg = f"severity must be a Severity, got {self.severity!r}"
            raise TypeError(msg)
        if not isinstance(self.category, Category):
            msg = f"category must be a Category, got {self.category!r}"
            raise TypeError(msg)
        if not isinstance(self.location, Location):
            msg = f"location must be a Location, got {type(self.location).__name__}"
            raise TypeError(msg)
        for name in ("summary", "finding_id", "schema_version", "timestamp"):
            if not isinstance(getattr(self, name), str):
                msg = f"{name} must be str, got {type(getattr(self, name)).__name__}"
                raise TypeError(msg)
        for name in ("parent_id", "correlation_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                msg = f"{name} must be str or None, got {type(value).__name__}"
                raise TypeError(msg)
        if not isinstance(self.payload, dict):
            msg = f"payload must be a dict, got {type(self.payload).__name__}"
            raise TypeError(msg)
        _check_json_value(self.payload, "payload")
        if self.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            msg = (
                f"schema_version {self.schema_version!r} not supported by this "
                f"reader (supports {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
            )
            raise SchemaVersionError(msg)
        try:
            ts = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError:
            msg = f"timestamp {self.timestamp!r} is not ISO-8601"
            raise ValueError(msg) from None
        if ts.tzinfo is None:
            msg = f"timestamp {self.timestamp!r} has no timezone offset"
            raise ValueError(msg)

    # --- Serialization ---

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d

    def to_json(self) -> str:
        """Serialize to a single JSON line (for the ledger).

        Keys are sorted at every level and output is ASCII, so equal
        findings give equal bytes regardless of dict insertion order.
        Non-finite numbers are refused (allow_nan=False). This is stable
        serialization, not a full canonical form: number formatting and
        Unicode normalization rules for the v0.2 hash chain are still to
        be specified.
        """
        return json.dumps(
            self.to_dict(), separators=(",", ":"), sort_keys=True, allow_nan=False
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        """Deserialize from a plain dict. The input dict is not modified."""
        if not isinstance(d, dict):
            msg = f"finding must be a JSON object, got {type(d).__name__}"
            raise TypeError(msg)
        fields_ = dict(d)  # never mutate the caller's dict
        loc_data = fields_.pop("location", None)
        if loc_data is None:
            location = Location()
        elif isinstance(loc_data, dict):
            location = Location(**loc_data)
        else:
            msg = f"location must be a JSON object, got {type(loc_data).__name__}"
            raise TypeError(msg)
        return cls(location=location, **fields_)

    @classmethod
    def from_json(cls, line: str) -> Finding:
        """Deserialize from a single JSON line.

        Strict: NaN/Infinity constants and duplicate object keys are
        rejected rather than read as whichever value came last.
        """
        return cls.from_dict(strict_loads(line))


# ---------------------------------------------------------------------------
# Correlation -- linking findings across tools
# ---------------------------------------------------------------------------

def new_correlation_id() -> str:
    """Generate a new correlation ID for grouping related findings.

    Use this when a tool detects something that it expects other tools
    to have related findings for. Attach the same correlation_id to
    all of them. The mycorrhizal network is built from these links.
    """
    return f"habl-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# The Ledger -- append-only, in the soil
# ---------------------------------------------------------------------------

HABL_DIR = ".habl"
LEDGER_FILENAME = "findings.jsonl"


def ledger_path(project_root: str | Path) -> Path:
    """Return the path to the HABL ledger for a project."""
    return Path(project_root) / HABL_DIR / LEDGER_FILENAME


@contextmanager
def _locked(handle: IO[Any], exclusive: bool) -> Iterator[None]:
    """Hold a POSIX advisory lock on an open ledger file.

    Writers take LOCK_EX, readers LOCK_SH, so a reader never observes
    half of a batch and two writers never interleave. Advisory only:
    a process writing the file without this module is not coordinated.
    On platforms without fcntl (Windows) this is a no-op, and
    concurrent appends there are not coordinated.
    """
    if _fcntl is None:
        yield
        return
    _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX if exclusive else _fcntl.LOCK_SH)
    try:
        yield
    finally:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)


def _append_records(findings: list[Finding], project_root: str | Path) -> Path:
    """Serialize first, then write all records in one locked append.

    Validation and serialization happen before the file is touched, so
    a finding that fails either leaves the ledger unchanged.
    """
    path = ledger_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    for f in findings:
        f.validate()
    data = "".join(f.to_json() + "\n" for f in findings).encode("utf-8")
    if not data:
        return path
    with open(path, "ab", buffering=0) as handle, _locked(handle, exclusive=True):
        view = memoryview(data)
        while view:
            written = handle.write(view)
            view = view[written:]
    return path


def append_finding(finding: Finding, project_root: str | Path) -> Path:
    """Append a single finding to the project's HABL ledger.

    Creates the .habl/ directory and ledger file if they don't exist.
    Append-only -- the ledger is never rewritten, only extended.
    This is the structural honesty property of the connective tissue
    itself: the rope does not fray.

    Returns the path to the ledger file.
    """
    return _append_records([finding], project_root)


def append_findings(
    findings: list[Finding],
    project_root: str | Path,
) -> Path:
    """Append multiple findings to the ledger in one locked write.

    Concurrent callers using this module do not interleave records
    (POSIX). A crash mid-write can still leave a truncated final line;
    readers report it with its line number.
    """
    return _append_records(list(findings), project_root)


def read_ledger(project_root: str | Path) -> list[Finding]:
    """Read all findings from the project's HABL ledger.

    Returns an empty list if the ledger doesn't exist yet.
    The soil may be empty before the first seed germinates.

    Fail-stop: the first unreadable line raises LedgerParseError naming
    the file and line number. For a read that reports every bad line and
    continues, use habl.query.load_ledger.
    """
    path = ledger_path(project_root)
    if not path.exists():
        return []
    findings = []
    with open(path, encoding="utf-8") as f, _locked(f, exclusive=False):
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                findings.append(Finding.from_json(line))
            except json.JSONDecodeError as exc:
                raise LedgerParseError(path, line_no, f"invalid JSON: {exc.msg}") from exc
            except StrictJSONError as exc:
                raise LedgerParseError(path, line_no, f"invalid JSON: {exc}") from exc
            except (TypeError, ValueError) as exc:
                raise LedgerParseError(path, line_no, f"invalid finding: {exc}") from exc
    return findings


def read_by_correlation(
    correlation_id: str,
    project_root: str | Path,
) -> list[Finding]:
    """Read all findings sharing a correlation ID.

    This is how a tool follows the mycorrhizal network: given one
    finding's correlation_id, retrieve every related finding from
    every tool. The retrograde signal made visible.
    """
    return [
        f for f in read_ledger(project_root)
        if f.correlation_id == correlation_id
    ]


def read_by_source(
    source_tool: str,
    project_root: str | Path,
) -> list[Finding]:
    """Read all findings from a specific tool."""
    return [
        f for f in read_ledger(project_root)
        if f.source_tool == source_tool
    ]


def read_provenance_chain(
    finding_id: str,
    project_root: str | Path,
) -> list[Finding]:
    """Walk the provenance chain backwards from a finding.

    Given a finding, return the chain of parent findings that
    caused it -- the retrograde signal path from postsynaptic
    back to presynaptic. Returns oldest-first (root cause first).

    Returns [] if finding_id is not in the ledger. If the oldest
    finding reached names a parent_id that is not in this ledger,
    the chain stops there; habl stats reports such dangling parents.

    Raises:
        DuplicateFindingIdError -- an id on the walk appears on more
            than one ledger line, so which parent is meant is ambiguous.
        ProvenanceCycleError -- the walk revisits an id (self-parent or
            longer loop). The walk is bounded by the ledger size either
            way; it never loops indefinitely.
    """
    by_id: dict[str, list[Finding]] = {}
    for f in read_ledger(project_root):
        by_id.setdefault(f.finding_id, []).append(f)

    chain: list[Finding] = []
    seen: list[str] = []
    current_id: str | None = finding_id

    while current_id and current_id in by_id:
        if current_id in seen:
            raise ProvenanceCycleError([*seen[seen.index(current_id):], current_id])
        matches = by_id[current_id]
        if len(matches) > 1:
            raise DuplicateFindingIdError(current_id, len(matches))
        seen.append(current_id)
        chain.append(matches[0])
        current_id = matches[0].parent_id

    chain.reverse()  # root cause first
    return chain


# Bismillah ir-Rahman ir-Rahim
