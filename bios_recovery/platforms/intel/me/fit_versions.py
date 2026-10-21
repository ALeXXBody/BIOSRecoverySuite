"""Which Intel CSME System Tools release matches a given ME firmware version.

Intel ships the Flash Image Tool (FIT, called FITC in older packages) and its
successors (MFIT for CSME 16) inside a "CSME System Tools" release, one per ME
family. A tool must match the firmware family; a mismatch fails the build.

Rules come from public listings and forum reports (see SOURCES). Each rule
records how it was established: "listed" when a source names the exact pairing,
"inferred" when only the family boundary is known. Ambiguous ranges say so.

This module only maps versions. It never downloads or runs a tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

SOURCES = (
    "indiafix.in FIT/CSME tool list (per-release CSME version text)",
    "community.intel.com 'Flash Image Tool' thread (CSME 12 and 16 pairings)",
    "github.com/CE1CECL/IntelCSTools (release names only)",
    "winraid.level1techs.com CSME 16+ thread (MFIT and LINUX64 builds)",
)


@dataclass(frozen=True)
class ToolRule:
    low: tuple          # inclusive lower bound of the ME version
    high: tuple         # exclusive upper bound
    release: str       # CSME System Tools release that carries the tool
    confidence: str    # "listed" | "inferred" | "ambiguous"
    note: str = ""


# Ordered by version. Bounds are compared as integer tuples.
RULES: tuple = (
    ToolRule((6,), (7,), "v6 IBX r2 / v6 CCK r1", "inferred", "two platform variants"),
    ToolRule((7,), (8,), "v7 r2", "inferred"),
    ToolRule((8,), (9,), "v8 r3", "inferred"),
    ToolRule((9,), (9, 5), "v9.1 r7", "inferred"),
    ToolRule((9, 5), (10,), "v9.5 r6", "inferred", "8-series"),
    ToolRule((10,), (11,), "v10.0 r8", "inferred", "Broadwell mobile"),
    ToolRule((11,), (12,), "v11 r46", "listed", "100/200, Z370, X299, C620 platforms"),
    ToolRule((12,), (13,), "v12 r38", "listed", "300 and C240 platforms"),
    ToolRule((13,), (13, 30), "v13.0 r7", "listed", "FIT 13.0.37.1556 comes from this release"),
    ToolRule((13, 30), (13, 50), "v13.30 r3", "listed"),
    ToolRule((13, 50), (14, 0, 12), "v13.50 r3 or v14.0.11 r1", "ambiguous",
             "one listing puts 13.50 r3 at CSME 14.0.11 and older; another lists v14.0.11 r1"),
    ToolRule((14, 0, 12), (14, 0, 20), "v14.0.11 r1", "inferred"),
    ToolRule((14, 0, 20), (14, 5), "v14.0.20 r20", "listed", "CSME 14.0.20 and newer"),
    ToolRule((14, 5), (15,), "v14.5 r7", "listed"),
    ToolRule((15,), (15, 40), "v15.0 r15", "listed"),
    ToolRule((15, 40), (16,), "v15.40 r3", "listed"),
    ToolRule((16,), (16, 1), "v16.0 r8", "listed", "v16.0 r2 also exists"),
    ToolRule((16, 1), (17,), "v16.1 r0", "inferred", "MFIT 16.1 Linux64 build reported"),
)


@dataclass(frozen=True)
class ToolMatch:
    me_version: str
    release: Optional[str]
    confidence: str
    note: str


def _parse(version: str) -> tuple:
    parts = []
    for piece in (version or "").strip().split("."):
        if not piece.isdigit():
            break
        parts.append(int(piece))
    return tuple(parts)


def tool_for_me_version(me_version: str) -> ToolMatch:
    """Map an ME firmware version (e.g. '15.0.3.1402') to its System Tools release."""
    v = _parse(me_version)
    if not v:
        return ToolMatch(me_version, None, "unknown", "no ME version to match")
    for rule in RULES:
        if rule.low <= v < rule.high:
            return ToolMatch(me_version, rule.release, rule.confidence, rule.note)
    return ToolMatch(me_version, None, "unknown", "no rule covers this version")
