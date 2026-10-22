"""Which library tools fit an image's ME firmware (shared by the GUI and CLI)."""

from __future__ import annotations

from dataclasses import dataclass, field

from bios_recovery.core import user_library as lib
from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.platforms.intel.me.fit_bridge import ToolProbe, compatible_with_me
from bios_recovery.platforms.intel.me.fit_versions import tool_for_me_version


@dataclass
class ToolRow:
    family: str
    version: str
    platform: str
    release: str
    path: str
    compatible: bool
    reason: str


@dataclass
class FitCheck:
    image: str
    me_version: str
    release: str
    confidence: str
    note: str
    tools: list = field(default_factory=list)

    def lines(self) -> list[str]:
        out = [
            f"Image:        {self.image}",
            f"ME version:   {self.me_version or 'not found'}",
            f"Tool release: {self.release or 'none'} [{self.confidence}]"
            + (f" - {self.note}" if self.note else ""),
        ]
        if not self.tools:
            out.append(
                "Library:      no Intel tools in your library match (add folders in Settings)"
            )
        for t in self.tools:
            verdict = "compatible" if t.compatible else "not compatible"
            out.append(
                f"  {t.family} {t.version} {t.platform} ({t.release}): {verdict} - {t.reason}"
            )
            out.append(f"      {t.path}")
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
        if not entry.identified:
            continue  # listed but never run: its version is unknown, so it cannot be matched
        probe = ToolProbe(
            path=entry.path, identified=True, family=entry.family, version=entry.version
        )
        ok, why = compatible_with_me(probe, me)
        report.tools.append(
            ToolRow(entry.family, entry.version, entry.platform, entry.release, entry.path, ok, why)
        )
    return report
