"""Identify a user-supplied Intel Flash Image Tool (FIT / MFIT) binary.

The app never ships or downloads Intel's tools (Intel distributes them under a
licence). A user points the app at a binary they obtained themselves. This
module:
  * refuses anything that is not an existing executable file;
  * reads the tool's own banner and version from its bytes first, which runs
    nothing, so a GUI build (MFIT) cannot hang the check;
  * falls back to running it with -h, in an empty temporary directory, with a
    timeout, only when the bytes do not state a version;
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
MAX_STATIC_BYTES = 64 * 1024 * 1024
_VERSION_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,6})(?![\d.])")
_BANNER = "flash image tool"
_MFIT_BANNER = "modular flash image tool"
_VERSION_KEYS = ("fileversion", "productversion")


@dataclass
class ToolProbe:
    path: str
    identified: bool = False
    family: str = ""  # "MFIT" (CSME 16 Modular Flash Image Tool) | "FIT"
    version: str = ""  # e.g. "16.1.25.2053"
    platform: str = ""  # e.g. "WIN64" when the tool names one
    error: str = ""
    banner: str = ""
    source: str = ""  # "file" when read from the bytes, "help output" when run
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


def _platform_from_magic(path: str) -> str:
    """Platform from the executable format itself, not from the file name."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return ""
    if head[:4] == b"\x7fELF":
        return "Linux"
    if head[:2] == b"MZ":
        return "Windows"
    return ""


def _version_in_blob(flat: str) -> str:
    """The tool's version as stored in the file: FileVersion first, then the banner."""
    for key in _VERSION_KEYS:
        for m in re.finditer(key, flat):
            found = _VERSION_RE.search(flat[m.end() : m.end() + 160])
            if found:
                return ".".join(found.groups())
    for m in re.finditer(_BANNER, flat):
        window = flat[max(0, m.start() - 80) : m.end() + 200]
        found = _VERSION_RE.search(window)
        if found:
            return ".".join(found.groups())
    return ""


def identify_static(path: str) -> ToolProbe:
    """Read the tool's identity out of its own bytes. Nothing is executed.

    Windows stores the banner and the version as UTF-16, so NUL bytes are dropped
    first: that turns a wide string into the same text as the plain one. A file is
    accepted only when it actually carries the Flash Image Tool banner.
    """
    probe = ToolProbe(path=path)
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_STATIC_BYTES)
    except OSError as exc:
        probe.error = f"could not read: {exc.strerror or exc}"
        return probe
    flat = data.replace(b"\x00", b"").decode("latin-1").lower()
    if _BANNER not in flat:
        probe.error = "no 'Flash Image Tool' banner in the file"
        return probe
    probe.identified = True
    probe.source = "file"
    probe.family = "MFIT" if _MFIT_BANNER in flat else "FIT"
    probe.version = _version_in_blob(flat)
    if not probe.version:
        probe.warnings.append("the file does not state a version")
    found = re.search(r"\((linux64|win32|win64|efi64)\)", flat)
    probe.platform = found.group(1).upper() if found else ""
    return probe


def _probe_by_running(path: str, timeout: int) -> ToolProbe:
    """Run the tool with -h in a private folder and read the banner it prints."""
    probe = ToolProbe(path=path)
    with tempfile.TemporaryDirectory(prefix="fitprobe_") as work:
        # "-h" prints the banner and exits. With no arguments the Linux build opens a
        # Qt window and waits, so it must not be run bare. The Qt variables keep it
        # headless and out of the user's runtime directory.
        # The tool's own folder goes on PATH so it finds the libraries beside it.
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
        output = ""
        for flag in ("-h", "--help", "-?"):
            try:
                # A newline dismisses the "Press any key to continue" prompt that
                # some builds print before exiting.
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
                if _BANNER in output.lower():
                    break
            except subprocess.TimeoutExpired as exc:
                # A GUI build prints nothing and waits. Keep any output it did emit.
                output = _text(exc.stdout) + _text(exc.stderr)
                if _BANNER in output.lower():
                    break
                probe.error = f"no answer within {timeout} s"
                return probe
            except OSError as exc:
                probe.error = f"could not start: {exc}"
                return probe
        else:
            # No flag produced a banner. Some builds print it only when run with no
            # arguments and then wait for input; try once, briefly, and kill it.
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
                output = _text(exc.stdout) + _text(exc.stderr)
            except OSError as exc:
                probe.error = f"could not start: {exc}"
                return probe

    lowered = output.lower()
    if _BANNER not in lowered:
        probe.error = "not a Flash Image Tool (its help output does not say so)"
        return probe
    probe.identified = True
    probe.source = "help output"
    probe.family = "MFIT" if _MFIT_BANNER in lowered else "FIT"
    probe.banner = output[:2000]
    probe.version = _banner_version(output)
    if not probe.version:
        probe.warnings.append("its help output does not state a version")
    found = re.search(r"\((LINUX64|WIN32|WIN64|EFI64)\)", output)
    probe.platform = found.group(1) if found else ""
    return probe


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def probe_tool(path: str, timeout: int = PROBE_TIMEOUT) -> ToolProbe:
    """Identify a FIT/MFIT binary: from its bytes first, by running it only if needed."""
    static = identify_static(path)
    if not static.identified:
        if not os.path.isfile(path):
            static.error = "not a file"
            return static
        if os.name != "nt" and not os.access(path, os.X_OK):
            static.error = "not executable"
            return static
    if static.identified and static.version:
        static.platform = static.platform or _platform_from_magic(path)
        return static

    if not os.path.isfile(path):
        static.error = "not a file"
        return static
    if os.name != "nt" and not os.access(path, os.X_OK):
        static.error = "not executable"
        return static
    ran = _probe_by_running(path, timeout)
    if ran.identified:
        ran.version = ran.version or static.version
        ran.warnings.extend(static.warnings if not static.version else [])
        ran.platform = ran.platform or _platform_from_magic(path)
        return ran
    if static.identified:
        # The bytes say it is a Flash Image Tool even though running it said nothing.
        static.platform = static.platform or _platform_from_magic(path)
        return static
    return ran


def compatible_with_me(probe: ToolProbe, me_version: str) -> tuple[bool, str]:
    """A tool must belong to the same System Tools release line as the ME version.

    The tool's own version is mapped through the same rule table as the ME version.
    Different release lines are refused. A range the table marks ambiguous is refused
    too: the table cannot decide which release the image was built with, and a wrong
    tool produces a build that fails, so nothing is guessed.
    """
    if not probe.identified or not probe.version:
        return False, "not identified"
    if not me_version:
        return False, "image has no ME version to check against"
    tool_rule = rule_for_version(probe.version)
    me_rule = rule_for_version(me_version)
    if tool_rule is None or me_rule is None:
        return False, "no release line covers this tool or ME version"
    if tool_rule is not me_rule:
        return False, f"it is for {tool_rule.release}, this image needs {me_rule.release}"
    if me_rule.confidence == "ambiguous" or tool_rule.confidence == "ambiguous":
        return False, f"{me_rule.release} is ambiguous in the release table"
    return True, f"matches this image ({me_rule.release})"
