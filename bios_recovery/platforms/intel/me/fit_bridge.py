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

from bios_recovery.platforms.intel.me.fit_versions import rule_for_version

PROBE_TIMEOUT = 30
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)")


@dataclass
class ToolProbe:
    path: str
    identified: bool = False
    family: str = ""  # "MFIT" (CSME 16 Modular Flash Image Tool) | "FIT"
    version: str = ""  # e.g. "16.1.25.2053"
    platform: str = ""  # e.g. "LINUX64" when the banner names one
    error: str = ""
    banner: str = ""
    warnings: list = field(default_factory=list)


def _banner_version(output: str) -> str:
    """Version from the line that names the tool, else from a 'version' line.

    The first four-part number in the whole output is not necessarily the tool version.
    """
    lines = output.splitlines()
    named = [ln for ln in lines if "flash image tool" in ln.lower()]
    versioned = [ln for ln in lines if "version" in ln.lower()]
    for line in named + versioned:
        m = _VERSION_RE.search(line)
        if m:
            return ".".join(m.groups())
    return ""


def probe_tool(path: str, timeout: int = PROBE_TIMEOUT) -> ToolProbe:
    probe = ToolProbe(path=path)
    if not os.path.isfile(path):
        probe.error = "not a file"
        return probe
    if os.name != "nt" and not os.access(path, os.X_OK):
        probe.error = "not executable"
        return probe

    with tempfile.TemporaryDirectory(prefix="fitprobe_") as work:
        # "-h" prints the banner and exits. With no arguments the Linux build opens a
        # Qt window and waits, so it must not be run bare. The Qt variables keep it
        # headless and out of the user's runtime directory.
        # Minimal environment: only what the loader needs, and every writable location
        # points at the probe's private folder, not the user's profile.
        tool_dir = os.path.dirname(os.path.abspath(path))
        base_path = os.environ.get("PATH", "")
        if tool_dir not in base_path.split(os.pathsep):
            base_path = tool_dir + os.pathsep + base_path
        keys = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC")
        env = {k: os.environ[k] for k in keys if k in os.environ}
        env["PATH"] = base_path
        env.update(
            QT_QPA_PLATFORM="offscreen",
            XDG_RUNTIME_DIR=work,
            HOME=work,
            TMPDIR=work,
            TEMP=work,
            TMP=work,
        )
        for flag in ("-h", "--help", "-?"):
            try:
                done = subprocess.run(
                    [os.path.abspath(path), flag],
                    cwd=tool_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=timeout,
                    input="\n",
                )
                output = (done.stdout or "") + (done.stderr or "")
                if "flash image tool" in output.lower():
                    break
            except subprocess.TimeoutExpired as exc:
                output = (exc.stdout or "") + (exc.stderr or "")
                if "flash image tool" in output.lower():
                    # Tool printed its banner but waited for a keypress; we have
                    # enough to identify it.
                    probe.banner = output[:2000]
                    lowered = output.lower()
                    probe.identified = True
                    probe.family = "MFIT" if "modular flash image tool" in lowered else "FIT"
                    version = _banner_version(output)
                    if version:
                        probe.version = version
                    else:
                        probe.warnings.append("banner does not state a version")
                    p = re.search(r"\((LINUX64|WIN32|WIN64|EFI64)\)", output)
                    if p:
                        probe.platform = p.group(1)
                    return probe
                probe.error = f"no output within {timeout} s"
                return probe
            except OSError as exc:
                probe.error = f"could not start: {exc}"
                return probe
        else:
            # Neither flag produced a banner. Some FIT builds print the banner only
            # when invoked with no arguments and then wait for input; try once with
            # a very short timeout and kill it if it hangs.
            try:
                done = subprocess.run(
                    [os.path.abspath(path)],
                    cwd=tool_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=5,
                    input="\n",
                )
                output = (done.stdout or "") + (done.stderr or "")
            except subprocess.TimeoutExpired as exc:
                partial = (exc.stdout or "") + (exc.stderr or "")
                if partial:
                    output = partial
            except OSError as exc:
                probe.error = f"could not start: {exc}"
                return probe

    probe.banner = output[:2000]
    lowered = output.lower()
    if "flash image tool" not in lowered:
        snippet = output.strip()[:500]
        probe.error = (
            "not a Flash Image Tool (no 'Flash Image Tool' banner in output)"
            + (f": {snippet}" if snippet else "")
        )
        return probe

    probe.identified = True
    probe.family = "MFIT" if "modular flash image tool" in lowered else "FIT"
    version = _banner_version(output)
    if version:
        probe.version = version
    else:
        probe.warnings.append("banner does not state a version")
    p = re.search(r"\((LINUX64|WIN32|WIN64|EFI64)\)", output)
    if p:
        probe.platform = p.group(1)
    return probe

    probe.identified = True
    probe.family = "MFIT" if "modular flash image tool" in lowered else "FIT"
    version = _banner_version(output)
    if version:
        probe.version = version
    else:
        probe.warnings.append("banner does not state a version")
    p = re.search(r"\((LINUX64|WIN32|WIN64|EFI64)\)", output)
    if p:
        probe.platform = p.group(1)
    return probe


def compatible_with_me(probe: ToolProbe, me_version: str) -> tuple[bool, str]:
    """A tool must belong to the same System Tools release line as the ME version.

    The tool's own version is mapped through the same rule table as the ME version.
    Different release lines are refused. A range the table marks ambiguous is refused
    too: the table cannot decide which release the image was built with, and a wrong
    tool produces a build that fails, so nothing is guessed.
    """
    if not probe.identified or not probe.version:
        return False, "tool is not identified"
    if not me_version:
        return False, "image has no ME version to check against"
    tool_rule = rule_for_version(probe.version)
    me_rule = rule_for_version(me_version)
    if tool_rule is None or me_rule is None:
        return False, "no release line covers this tool or ME version"
    if tool_rule is not me_rule:
        return False, (
            f"tool {probe.version} belongs to {tool_rule.release}, ME {me_version} "
            f"needs {me_rule.release}; a mismatched FIT fails the build"
        )
    if me_rule.confidence == "ambiguous" or tool_rule.confidence == "ambiguous":
        return False, (
            f"{me_rule.release} is ambiguous in the release table; "
            "the tool cannot be confirmed for this ME version"
        )
    return True, (
        f"tool {probe.version} and ME {me_version} are both {me_rule.release} "
        f"(release table confidence: {me_rule.confidence})"
    )
