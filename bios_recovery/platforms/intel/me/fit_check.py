"""Which library tools fit an image's ME firmware (shared by the GUI and CLI)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from bios_recovery.core import user_library as lib
from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.platforms.intel.me.fit_bridge import ToolProbe, compatible_with_me, probe_tool
from bios_recovery.platforms.intel.me.fit_versions import tool_for_me_version

CHECK_PROBE_TIMEOUT = 10


@dataclass
class ToolRow:
    family: str
    version: str
    platform: str
    release: str
    path: str
    compatible: bool
    reason: str

    def label(self) -> str:
        """Short one-line name: 'MFIT 16.1.25.2053 (Windows)'."""
        platform = f" ({self.platform})" if self.platform not in ("", "unknown") else ""
        if not self.version:
            return f"{self.family or 'FIT'} (not identified){platform}"
        return f"{self.family} {self.version}{platform}"


@dataclass
class FitCheck:
    image: str
    me_version: str
    release: str
    confidence: str
    note: str
    tools: list = field(default_factory=list)

    @property
    def needed_version(self) -> str:
        """The release number this image needs, e.g. '16.1' ('' when unknown)."""
        found = re.search(r"v(\d+(?:\.\d+)?)", self.release or "")
        return found.group(1) if found else ""

    @property
    def needed_tool(self) -> str:
        """The tool family this image needs, e.g. 'MFIT 16.1' ('' when unknown)."""
        if not self.release:
            return ""
        family = "MFIT" if self.release.startswith("v16") else "FIT"
        return f"{family} {self.needed_version}".strip()

    def lines(self) -> list[str]:
        """Short, plain result: what this image needs and what is in the library."""
        name = os.path.basename(self.image) or self.image
        head = f"ME:    {self.me_version or 'not found'}"
        if self.needed_tool:
            head += f" - needs {self.needed_tool}"
        matching = [t for t in self.tools if t.compatible]
        others = [t for t in self.tools if not t.compatible]
        out = [f"Image: {name}", head, ""]
        out.append(
            "Matching tool: " + ", ".join(t.label() for t in matching)
            if matching
            else "Matching tool: none"
        )
        if others:
            out.append("Other tools:   " + ", ".join(t.label() for t in others))
        if not matching:
            out.append("")
            where = f"the CSME {self.needed_version} System Tools" if self.needed_version else (
                "the matching Intel System Tools"
            )
            if not self.tools:
                out.append(f"No Intel tools found. Add {where} folder in Settings.")
            else:
                out.append(f"Add {where} folder in Settings.")
        return out


def check_image(image_path: str) -> FitCheck:
    me = BiosAnalyzer().analyze(image_path).me_version
    match = tool_for_me_version(me)
    report = FitCheck(
        image=image_path,
        me_version=me,
        release=match.release or "",
        confidence=match.confidence,
        note=match.note,
    )
    for entry in lib.scan().tools:
        probe = ToolProbe(
            path=entry.path,
            identified=entry.identified,
            family=entry.family,
            version=entry.version,
            platform=entry.platform,
        )
        if not probe.version:
            # The user asked to check tools, so look inside the file; it is only run
            # if its bytes do not state a version. A failure is listed, never hidden.
            fresh = probe_tool(entry.path, timeout=CHECK_PROBE_TIMEOUT)
            if fresh.identified:
                probe = fresh
                if fresh.version:
                    try:
                        lib.remember_identity(entry.path, fresh.family, fresh.version)
                    except OSError:
                        pass
        if not probe.platform or probe.platform == "unknown":
            probe.platform = entry.platform
        ok, why = compatible_with_me(probe, me)
        report.tools.append(
            ToolRow(
                family=probe.family or "FIT",
                version=probe.version,
                platform=probe.platform,
                release=lib.release_line(probe.version) if probe.version else entry.release,
                path=entry.path,
                compatible=ok,
                reason=why,
            )
        )
    return report
