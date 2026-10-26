"""Intel engine details, read with the bundled ME Analyzer.

The analyzer decodes the engine manifest, the manifest extensions, the MFS
state, the FIT version and its own firmware database. This module turns its
JSON report into one labelled line per field, so the page shows the same detail
as a full analyzer report without the ASCII tables.

ME Analyzer is BSD-2-Clause-Patent (https://github.com/platomav/MEAnalyzer).
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

# Field label shown to the user -> key in ME Analyzer's JSON report.
ENGINE_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("Family", "Family"),
    ("Version", "Version"),
    ("Release", "Release"),
    ("Type", "Type"),
    ("SKU", "SKU"),
    ("Chipset", "Chipset"),
    ("TCB SVN", "TCB Security Version Number"),
    ("ARB SVN", "ARB Security Version Number"),
    ("VCN", "Version Control Number"),
    ("Production Ready", "Production Ready"),
    ("OEM Configuration", "OEM Configuration"),
    ("FWUpdate Support", "FWUpdate Support"),
    ("Date", "Date"),
    ("File System State", "File System State"),
    ("Size", "Size"),
    ("Flash Image Tool", "Flash Image Tool"),
    ("MEA Database Name", "MEA Database Name"),
)

# Fields only an engine entry carries: independent firmware has its own section.
_ENGINE_ONLY = ("File System State", "Flash Image Tool", "OEM Configuration")

_UNREADABLE = "This image has no engine data ME Analyzer could read."


def engine_entries(report: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """Engine entries of a report, in report order, each with its section name.

    Independent firmware (PMC, PCHC, PHY, OROM) is reported in its own section
    and is not the engine, so only entries carrying engine-only fields are kept.
    """
    entries: List[Tuple[str, Dict[str, Any]]] = []
    if not isinstance(report, dict):
        return entries
    for sections in report.values():
        if not isinstance(sections, dict):
            continue
        for name, section in sections.items():
            if name == "Messages" or not isinstance(section, list):
                continue
            for entry in section:
                if isinstance(entry, dict) and any(key in entry for key in _ENGINE_ONLY):
                    entries.append((name, entry))
    return entries


def engine_fields(entry: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Known fields of one engine entry, in report order, as (label, text)."""
    lines: List[Tuple[str, str]] = []
    for label, key in ENGINE_FIELDS:
        value = entry.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if not text or text == "NaN":
            continue
        lines.append((label, text))
    return lines


def format_engines(entries: Sequence[Tuple[str, Dict[str, Any]]]) -> List[str]:
    """Detail lines for one or more engines; several engines get a heading each."""
    lines: List[str] = []
    many = len(entries) > 1
    for index, (name, entry) in enumerate(entries, 1):
        prefix = ""
        if many:
            lines.append(f"Engine {index} ({name}):")
            prefix = "  "
        lines.extend(f"{prefix}{label}: {value}" for label, value in engine_fields(entry))
        if many:
            lines.append("")
    if many:
        lines.pop()
    return lines


def failure_reason(result) -> str:
    """One short sentence for why the analyzer produced no detail."""
    output = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}"
    error = getattr(result, "error", "") or ""
    if "timed out" in error.lower():
        return "ME Analyzer timed out on this image."
    if 'is missing!' in output:
        # A packaging problem, not a problem with the image: say which one it is.
        return "The bundled ME Analyzer is incomplete; reinstall the suite."
    return _UNREADABLE


def engine_details(path: str) -> Dict[str, Any]:
    """Detail for one image.

    Returns {"found": True, "engines": entries, "lines": [...]} or
    {"found": False, "reason": <one sentence>}.
    """
    from bios_recovery.platforms.intel.me import mea_bridge

    try:
        result = mea_bridge.run_mea_analyzer(path)
    except Exception as exc:  # a broken analyzer must not break the page
        return {"found": False, "reason": f"ME Analyzer could not run: {exc}"}
    if not result.success:
        return {"found": False, "reason": failure_reason(result)}
    entries = engine_entries(result.json_data)
    if not entries:
        return {"found": False, "reason": _UNREADABLE}
    return {"found": True, "engines": entries, "lines": format_engines(entries)}
