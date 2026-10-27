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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants -- the seven values from the du'as
# ---------------------------------------------------------------------------

__version__ = "0.1.0"

HABL_SCHEMA_VERSION = "0.1.0"

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

    # --- Serialization ---

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d

    def to_json(self) -> str:
        """Serialize to a single JSON line (for the ledger)."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        """Deserialize from a plain dict."""
        loc_data = d.pop("location", {})
        location = Location(**loc_data) if loc_data else Location()
        return cls(location=location, **d)

    @classmethod
    def from_json(cls, line: str) -> Finding:
        """Deserialize from a single JSON line."""
        return cls.from_dict(json.loads(line))


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


def append_finding(finding: Finding, project_root: str | Path) -> Path:
    """Append a single finding to the project's HABL ledger.

    Creates the .habl/ directory and ledger file if they don't exist.
    Append-only -- the ledger is never rewritten, only extended.
    This is the structural honesty property of the connective tissue
    itself: the rope does not fray.

    Returns the path to the ledger file.
    """
    path = ledger_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(finding.to_json())
        f.write("\n")
    return path


def append_findings(
    findings: list[Finding],
    project_root: str | Path,
) -> Path:
    """Append multiple findings to the ledger in one write."""
    path = ledger_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for finding in findings:
            f.write(finding.to_json())
            f.write("\n")
    return path


def read_ledger(project_root: str | Path) -> list[Finding]:
    """Read all findings from the project's HABL ledger.

    Returns an empty list if the ledger doesn't exist yet.
    The soil may be empty before the first seed germinates.
    """
    path = ledger_path(project_root)
    if not path.exists():
        return []
    findings = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                findings.append(Finding.from_json(line))
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
    """
    all_findings = {f.finding_id: f for f in read_ledger(project_root)}
    chain: list[Finding] = []
    current_id: str | None = finding_id

    while current_id and current_id in all_findings:
        finding = all_findings[current_id]
        chain.append(finding)
        current_id = finding.parent_id

    chain.reverse()  # root cause first
    return chain


# Bismillah ir-Rahman ir-Rahim
