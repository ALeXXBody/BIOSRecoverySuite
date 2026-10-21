"""Identify a user-supplied Intel Flash Image Tool (FIT / MFIT) binary.

The app never ships or downloads Intel's tools (Intel distributes them under a
licence). A user points the app at a binary they obtained themselves. This
module:
  * refuses anything that is not an existing executable file;
  * runs it with no shell, in an empty temporary directory, with a timeout;
  * identifies it from its own banner text and version string;
  * checks that its major version matches the ME firmware it would be used on.

It does not build, sign, or flash anything. Build actions are added only after
the real command-line options of a tool have been read from its own help output.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional

PROBE_TIMEOUT = 20
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)")


@dataclass
class ToolProbe:
    path: str
    identified: bool = False
    family: str = ""             # "MFIT" (CSME 16 Modular Flash Image Tool) | "FIT"
    version: str = ""            # e.g. "16.1.25.2053"
    platform: str = ""           # e.g. "LINUX64" when the banner names one
    error: str = ""
    banner: str = ""
    warnings: list = field(default_factory=list)


def probe_tool(path: str, timeout: int = PROBE_TIMEOUT) -> ToolProbe:
    probe = ToolProbe(path=path)
    if not os.path.isfile(path):
        probe.error = "not a file"
        return probe
    if os.name != "nt" and not os.access(path, os.X_OK):
        probe.error = "not executable"
        return probe

    with tempfile.TemporaryDirectory(prefix="fitprobe_") as work:
        try:
            done = subprocess.run(
                [os.path.abspath(path)], cwd=work, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, errors="replace", timeout=timeout,
            )
            output = (done.stdout or "") + (done.stderr or "")
        except subprocess.TimeoutExpired:
            probe.error = f"no output within {timeout} s"
            return probe
        except OSError as exc:
            probe.error = f"could not start: {exc}"
            return probe

    probe.banner = output[:2000]
    lowered = output.lower()
    if "flash image tool" not in lowered:
        probe.error = "not a Flash Image Tool (no 'Flash Image Tool' banner)"
        return probe

    probe.identified = True
    probe.family = "MFIT" if "modular flash image tool" in lowered else "FIT"
    m = _VERSION_RE.search(output)
    if m:
        probe.version = ".".join(m.groups())
    else:
        probe.warnings.append("banner does not state a version")
    p = re.search(r"\((LINUX64|WIN32|WIN64|EFI64)\)", output)
    if p:
        probe.platform = p.group(1)
    return probe


def compatible_with_me(probe: ToolProbe, me_version: str) -> tuple[bool, str]:
    """A tool must share the ME major version; a minor difference is a warning only."""
    if not probe.identified or not probe.version:
        return False, "tool is not identified"
    if not me_version:
        return False, "image has no ME version to check against"
    tool_parts = [int(x) for x in probe.version.split(".")]
    me_parts = [int(x) for x in re.findall(r"\d+", me_version)[:4]]
    if not me_parts:
        return False, "unreadable ME version"
    if tool_parts[0] != me_parts[0]:
        return False, (f"tool major {tool_parts[0]} does not match ME major {me_parts[0]}; "
                       "a mismatched FIT fails the build")
    if tool_parts[:2] != me_parts[:2]:
        return True, f"same major version; tool {probe.version} vs ME {me_version} differ in minor version"
    return True, "tool and ME versions match"
