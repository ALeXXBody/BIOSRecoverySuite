"""User-chosen folders for Intel tools and ME firmware.

The app ships no Intel tools and no ME firmware, and it never downloads them.
The user adds the folders where they keep their own copies; this module stores
those folders in a per-user config file and scans them on request.

Config location:
  Windows:  %APPDATA%\\BIOSRecoverySuite\\library.json
  Linux:    ~/.config/bios-recovery/library.json
  override: BIOS_RECOVERY_CONFIG_DIR
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import asdict, dataclass, field
from typing import Optional

MAX_DEPTH = 6
MAX_FIRMWARE_BYTES = 64 * 1024 * 1024
TOOL_NAMES = ("fit", "fit.exe", "fitc.exe", "mfit", "mfit.exe")


def config_dir() -> str:
    override = os.environ.get("BIOS_RECOVERY_CONFIG_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "BIOSRecoverySuite")
    return os.path.join(os.path.expanduser("~"), ".config", "bios-recovery")


def config_path() -> str:
    return os.path.join(config_dir(), "library.json")


KINDS = ("tools", "firmware")


def app_library_dir() -> str:
    """Folder the app owns for imported copies (scanned automatically)."""
    if os.environ.get("BIOS_RECOVERY_DATA_DIR"):
        return os.environ["BIOS_RECOVERY_DATA_DIR"]
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "BIOSRecoverySuite", "library")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "bios-recovery", "library")


@dataclass
class Library:
    tools_folders: list = field(default_factory=list)
    firmware_folders: list = field(default_factory=list)

    def folders(self, kind: str) -> list:
        return self.tools_folders if kind == "tools" else self.firmware_folders


def load_library() -> Library:
    try:
        with open(config_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return Library()
    lib = Library(
        tools_folders=[p for p in data.get("tools_folders", []) if isinstance(p, str)],
        firmware_folders=[p for p in data.get("firmware_folders", []) if isinstance(p, str)],
    )
    # Version 1 stored one flat list; it applies to both kinds.
    for p in data.get("folders", []) if isinstance(data.get("folders"), list) else []:
        if isinstance(p, str):
            if p not in lib.tools_folders:
                lib.tools_folders.append(p)
            if p not in lib.firmware_folders:
                lib.firmware_folders.append(p)
    return lib


def save_library(lib: Library) -> None:
    os.makedirs(config_dir(), exist_ok=True)
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump({"tools_folders": lib.tools_folders,
                   "firmware_folders": lib.firmware_folders}, f, indent=2)


def _kinds(kind: str) -> tuple:
    if kind == "both":
        return KINDS
    if kind not in KINDS:
        raise ValueError(f"unknown kind: {kind}")
    return (kind,)


def add_folder(path: str, kind: str = "both") -> Library:
    absolute = os.path.abspath(path)
    if not os.path.isdir(absolute):
        raise ValueError(f"not a folder: {path}")
    lib = load_library()
    for k in _kinds(kind):
        if absolute not in lib.folders(k):
            lib.folders(k).append(absolute)
    save_library(lib)
    return lib


def remove_folder(path: str, kind: str = "both") -> Library:
    absolute = os.path.abspath(path)
    lib = load_library()
    for k in _kinds(kind):
        remaining = [p for p in lib.folders(k) if p != absolute]
        lib.folders(k)[:] = remaining
    save_library(lib)
    return lib


@dataclass
class ImportResult:
    source: str
    kind: str
    copied_to: str = ""
    refused: str = ""


def _probe_import(path: str):
    """Probe a temporary executable copy, so the original is never changed."""
    import tempfile
    from bios_recovery.platforms.intel.me.fit_bridge import probe_tool
    with tempfile.TemporaryDirectory(prefix="fitimport_") as work:
        probe_copy = os.path.join(work, os.path.basename(path))
        shutil.copyfile(path, probe_copy)
        if os.name != "nt":
            os.chmod(probe_copy, os.stat(probe_copy).st_mode | stat.S_IXUSR)
        return probe_tool(probe_copy)


def _looks_like_me_image(path: str) -> bool:
    from bios_recovery.core.bios_analyzer import BiosAnalyzer
    with open(path, "rb") as f:
        return bool(BiosAnalyzer()._fpt_positions(f.read()))


def import_files(paths: list, kind: str) -> list:
    """Copy user-chosen files into the app's own library folder.

    A tool is copied only if it identifies as a Flash Image Tool; firmware only if it
    has a full ME partition table. Originals are never moved or changed.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown kind: {kind}")
    target_dir = os.path.join(app_library_dir(), kind)
    os.makedirs(target_dir, exist_ok=True)
    results = []
    for src in paths:
        result = ImportResult(source=src, kind=kind)
        if not os.path.isfile(src):
            result.refused = "not a file"
            results.append(result)
            continue
        probe = _probe_import(src) if kind == "tools" else None
        ok = probe.identified if probe is not None else _looks_like_me_image(src)
        if not ok:
            result.refused = ("not a Flash Image Tool banner" if kind == "tools"
                              else "no full ME partition table")
            results.append(result)
            continue
        if kind == "tools":
            name = tool_file_name(probe.family, probe.version, file_platform(src),
                                  os.path.splitext(src)[1] if os.name == "nt" else "")
        else:
            from bios_recovery.core.me_manifest import iter_manifest_versions
            with open(src, "rb") as f:
                versions = iter_manifest_versions(f.read())
            me = max(set(v for v, _ in versions), key=[v for v, _ in versions].count) if versions else "unknown"
            name = f"ME_{me}_{os.path.basename(src)}"
        dest = os.path.join(target_dir, name)
        base, ext = os.path.splitext(dest)
        n = 1
        while os.path.exists(dest):
            dest = f"{base}_{n}{ext}"
            n += 1
        shutil.copy2(src, dest)
        if kind == "tools" and os.name != "nt":
            os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR)
        result.copied_to = dest
        results.append(result)
    return results


def file_platform(path: str) -> str:
    """Platform from the executable format itself, not from the file name."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:4] == b"\x7fELF":
        return "Linux"
    if head[:2] == b"MZ":
        return "Windows"
    return "unknown"


def release_line(version: str) -> str:
    from bios_recovery.platforms.intel.me.fit_versions import rule_for_version
    rule = rule_for_version(version)
    return rule.release if rule else "unknown"


def tool_file_name(family: str, version: str, platform: str, ext: str = "") -> str:
    """Identity-bearing name for an imported tool: FIT_15.0.35.1951_Linux."""
    return f"{family}_{version}_{platform}{ext}"


@dataclass
class ToolEntry:
    path: str
    family: str
    version: str
    platform: str = "unknown"
    release: str = "unknown"


@dataclass
class FirmwareEntry:
    path: str
    me_version: str
    size: int


@dataclass
class ScanResult:
    folders: list
    tools: list = field(default_factory=list)
    firmware: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


def _walk(folder: str):
    base_depth = folder.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(folder):
        if dirpath.count(os.sep) - base_depth >= MAX_DEPTH:
            dirnames[:] = []
        for name in filenames:
            yield os.path.join(dirpath, name)


def scan(folders: Optional[list] = None) -> ScanResult:
    """Identify Intel tools and ME firmware in the user's folders.

    Tools are identified by running them with -h (see fit_bridge.probe_tool).
    Firmware is identified by its ME/CSME manifest version. Nothing is written.
    """
    from bios_recovery.core.bios_analyzer import BiosAnalyzer
    from bios_recovery.core.me_manifest import iter_manifest_versions
    from bios_recovery.platforms.intel.me.fit_bridge import probe_tool

    if folders is None:
        lib = load_library()
        folders = list(dict.fromkeys(lib.tools_folders + lib.firmware_folders))
        app_dir = app_library_dir()
        if os.path.isdir(app_dir):
            folders.append(app_dir)
    result = ScanResult(folders=list(folders))
    seen = set()
    seen_content: set = set()
    for folder in folders:
        if not os.path.isdir(folder):
            result.skipped.append(f"missing folder: {folder}")
            continue
        for path in _walk(folder):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            name = os.path.basename(path).lower()
            if name in TOOL_NAMES or name.startswith(("fit", "mfit")):
                probe = probe_tool(path)
                if probe.identified:
                    result.tools.append(ToolEntry(
                        path, probe.family, probe.version,
                        platform=file_platform(path),
                        release=release_line(probe.version)))
                continue
            size = os.path.getsize(path)
            if 0 < size <= MAX_FIRMWARE_BYTES and name.endswith((".bin", ".rom", ".fd", ".cap")):
                with open(path, "rb") as f:
                    data = f.read()
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen_content:
                    continue
                seen_content.add(digest)
                # A full ME image carries its partition table. Sub-partitions (OEMP, IOMP,
                # PCH configuration...) carry manifest tags too but no partition table.
                if not BiosAnalyzer()._fpt_positions(data):
                    continue
                versions = iter_manifest_versions(data)
                if versions:
                    counts: dict = {}
                    for v, _base in versions:
                        counts[v] = counts.get(v, 0) + 1
                    best = max(counts, key=counts.get)
                    result.firmware.append(FirmwareEntry(path, best, size))
    return result
