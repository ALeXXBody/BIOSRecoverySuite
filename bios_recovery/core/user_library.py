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


@dataclass
class Library:
    folders: list = field(default_factory=list)


def load_library() -> Library:
    try:
        with open(config_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return Library()
    folders = [p for p in data.get("folders", []) if isinstance(p, str)]
    return Library(folders=folders)


def save_library(lib: Library) -> None:
    os.makedirs(config_dir(), exist_ok=True)
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(asdict(lib), f, indent=2)


def add_folder(path: str) -> Library:
    absolute = os.path.abspath(path)
    if not os.path.isdir(absolute):
        raise ValueError(f"not a folder: {path}")
    lib = load_library()
    if absolute not in lib.folders:
        lib.folders.append(absolute)
        save_library(lib)
    return lib


def remove_folder(path: str) -> Library:
    absolute = os.path.abspath(path)
    lib = load_library()
    lib.folders = [p for p in lib.folders if p != absolute]
    save_library(lib)
    return lib


@dataclass
class ToolEntry:
    path: str
    family: str
    version: str


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
        folders = load_library().folders
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
            if name in TOOL_NAMES or name.startswith("mfit"):
                probe = probe_tool(path)
                if probe.identified:
                    result.tools.append(ToolEntry(path, probe.family, probe.version))
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
