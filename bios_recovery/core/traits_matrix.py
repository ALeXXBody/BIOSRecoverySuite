"""The tool-availability matrix: which tools apply on which platform/vendor.

Shared by the GUI (tab gating) and the CLI (command gating) so both present
the same answer for the same image.
"""

from __future__ import annotations

from dataclasses import dataclass

from bios_recovery.core.traits import ARCH_AMD, ARCH_APPLE_INTEL, ARCH_INTEL


@dataclass
class ToolRow:
    applies: bool
    reason: str = ""


_INTEL_ARCHS = (ARCH_INTEL, ARCH_APPLE_INTEL)


def tool_matrix(traits) -> dict[str, ToolRow]:
    """Decide, per tool name, whether it applies to the classified image."""
    intel_tool = (
        ToolRow(True)
        if traits.architecture in _INTEL_ARCHS
        else ToolRow(
            False,
            "Not applicable: AMD platform (no Intel ME)"
            if traits.architecture == ARCH_AMD
            else "Not applicable on this platform type",
        )
    )
    return {
        # Intel-bound tools
        "ME Cleaner": intel_tool,
        "ME Injector": intel_tool,
        # vendor-bound tools
        "Lenovo Unlock": ToolRow(True)
        if traits.vendor == "lenovo"
        else ToolRow(False, "Not applicable: manufacturer-specific tool (Lenovo)"),
        "Dell DVAR Recovery": ToolRow(True)
        if traits.vendor == "dell"
        else ToolRow(False, "Not applicable: Dell-specific password store"),
        "Apple Fsys Tools": ToolRow(True)
        if traits.vendor == "apple"
        else ToolRow(False, "Not applicable: Apple-specific NVRAM store"),
        # common tools
        "Overview": ToolRow(True),
        "Repair": ToolRow(True),
        "DMI": ToolRow(True),
        "Security": ToolRow(True),
        "Extract": ToolRow(True),
        "Hex Viewer": ToolRow(True),
        "Passwords": ToolRow(True),
        "SPI Flasher": ToolRow(True),
        "EC Patching": ToolRow(True),
    }
