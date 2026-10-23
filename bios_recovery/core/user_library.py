"""User-chosen folders for Intel tools and ME firmware.

The app ships no Intel tools and no ME firmware, and it never downloads them.
The user adds the folders where they keep their own copies.

Scanning never runs anything. A tool's identity (family and version) is only
known by running it with -h, so that happens only when the user asks to identify
a specific file. The result is cached by the file's SHA-256, so a later scan does
not run the file again unless its contents change.

Identifying a tool, or importing one, runs that file once with -h as the current
user. The child gets a scrubbed environment and a temporary working folder, but
no sandbox: in a root session it runs as root. Identify and import only files you
trust.

Config location:
  Windows:  %APPDATA%\\BIOSRecoverySuite\\library.json
  Linux:    ~/.config/bios-recovery/library.json
  override: BIOS_RECOVERY_CONFIG_DIR
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from typing import Optional

from bios_recovery.core.safety import write_file_atomic

MAX_DEPTH = 6
MAX_FIRMWARE_BYTES = 64 * 1024 * 1024
MAX_TOOL_BYTES = 256 * 1024 * 1024
KINDS = ("tools", "firmware")
_FIRMWARE_SUFFIXES = (".bin", ".rom", ".fd", ".cap")
_SAFE_NAME_PART = re.compile(r"[A-Za-z0-9._-]+")


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


def app_library_dir() -> str:
    """Folder the app owns for imported copies (scanned automatically)."""
    if os.environ.get("BIOS_RECOVERY_DATA_DIR"):
        return os.environ["BIOS_RECOVERY_DATA_DIR"]
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "BIOSRecoverySuite", "library")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "bios-recovery", "library")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class Library:
    tools_folders: list = field(default_factory=list)
    firmware_folders: list = field(default_factory=list)
    identified: dict = field(default_factory=dict)  # sha256 -> {"family", "version"}

    def folders(self, kind: str) -> list:
        return self.tools_folders if kind == "tools" else self.firmware_folders


def _strings(values) -> list:
    return [v for v in values if isinstance(v, str) and v]


def _keep_damaged_copy(path: str) -> None:
    """Copy a damaged config to <path>.damaged, or <path>.damaged.N if that is taken."""
    target, n = path + ".damaged", 1
    while os.path.exists(target):
        target = f"{path}.damaged.{n}"
        n += 1
    try:
        shutil.copyfile(path, target)
    except OSError:
        pass


def load_library() -> Library:
    """Read the config. A missing file is an empty library; a damaged file is kept aside."""
    path = config_path()
    if not os.path.exists(path):
        return Library()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("config is not an object")
    except (OSError, ValueError):
        _keep_damaged_copy(path)
        return Library()
    lib = Library(
        tools_folders=_strings(data.get("tools_folders", []))
        if isinstance(data.get("tools_folders"), list)
        else [],
        firmware_folders=_strings(data.get("firmware_folders", []))
        if isinstance(data.get("firmware_folders"), list)
        else [],
    )
    # Version 1 stored one flat list; it applies to both kinds.
    if isinstance(data.get("folders"), list):
        for p in _strings(data["folders"]):
            if p not in lib.tools_folders:
                lib.tools_folders.append(p)
            if p not in lib.firmware_folders:
                lib.firmware_folders.append(p)
    ident = data.get("identified")
    if isinstance(ident, dict):
        for digest, value in ident.items():
            if (
                isinstance(value, dict)
                and isinstance(value.get("family"), str)
                and isinstance(value.get("version"), str)
            ):
                lib.identified[str(digest)] = {
                    "family": value["family"],
                    "version": value["version"],
                }
    return lib


def save_library(lib: Library) -> None:
    """Write atomically: a temporary file in the same folder, then replace."""
    os.makedirs(config_dir(), exist_ok=True)
    payload = {
        "tools_folders": lib.tools_folders,
        "firmware_folders": lib.firmware_folders,
        "identified": lib.identified,
    }
    fd, tmp = tempfile.mkstemp(prefix="library_", suffix=".json", dir=config_dir())
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, config_path())
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


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
    if os.path.ismount(absolute) or absolute in ("/", "\\"):
        raise ValueError(
            "refusing to scan a filesystem root; add a specific folder instead"
        )
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
        lib.folders(k)[:] = [p for p in lib.folders(k) if p != absolute]
    save_library(lib)
    return lib


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
    for part in (family, version, platform):
        if not _SAFE_NAME_PART.fullmatch(part):
            raise ValueError(f"not usable in a file name: {part!r}")
    return f"{family}_{version}_{platform}{ext}"


@dataclass
class ToolEntry:
    path: str
    family: str  # "unidentified" until the user identifies the file
    version: str
    platform: str = "unknown"
    release: str = "unknown"
    sha256: str = ""
    identified: bool = False


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


_NON_TOOL_SUFFIXES = (
    ".log",
    ".txt",
    ".md",
    ".ini",
    ".json",
    ".xml",
    ".html",
    ".cfg",
    ".zip",
    ".7z",
    ".tar",
    ".gz",
    ".pdf",
    ".bin",
    ".rom",
)


def _looks_like_tool_name(name: str) -> bool:
    """fit / mfit by name, excluding logs, notes and archives.

    Identity is still checked by running the tool with -h.
    """
    lower = name.lower()
    return lower.startswith(("fit", "mfit")) and not lower.endswith(_NON_TOOL_SUFFIXES)


def identify_tool(path: str, timeout: int = 20):
    """Run a user-chosen tool once with -h and cache its identity by SHA-256.

    Runs a private copy made from the same bytes that were hashed, so the cache
    key always matches the code that ran. The file in the library is never changed.
    """
    from bios_recovery.platforms.intel.me.fit_bridge import probe_tool

    if not os.path.isfile(path):
        raise ValueError(f"not a file: {path}")
    with open(path, "rb") as f:
        blob = f.read(MAX_TOOL_BYTES + 1)
    if len(blob) > MAX_TOOL_BYTES:
        raise ValueError("file is too large to be a flash image tool")
    digest = hashlib.sha256(blob).hexdigest()
    lib = load_library()
    with tempfile.TemporaryDirectory(prefix="fitid_") as work:
        copy = os.path.join(work, os.path.basename(path))
        with open(copy, "wb") as f:
            f.write(blob)
        if os.name != "nt":
            os.chmod(copy, os.stat(copy).st_mode | stat.S_IXUSR)
        probe = probe_tool(copy, timeout=timeout)
    if probe.identified:
        lib.identified[digest] = {"family": probe.family, "version": probe.version}
        save_library(lib)
    return probe


def dominant_me_version(data: bytes) -> str:
    """The ME version an image carries: its most common manifest version, '' if none."""
    from bios_recovery.core.me_manifest import iter_manifest_versions

    versions = [v for v, _base in iter_manifest_versions(data)]
    return max(set(versions), key=versions.count) if versions else ""


def firmware_for_version(version: str) -> list:
    """Library ME images (paths) whose version is exactly `version`. Nothing is run."""
    if not version:
        return []
    return [e.path for e in scan().firmware if e.me_version == version]


def scan(folders: Optional[list] = None) -> ScanResult:
    """List Intel tools and ME firmware in the user's folders. Nothing is executed."""
    from bios_recovery.core.me_manifest import iter_manifest_versions

    lib = load_library()
    if folders is None:
        folders = list(dict.fromkeys(lib.tools_folders + lib.firmware_folders))
        app_dir = app_library_dir()
        if os.path.isdir(app_dir):
            folders.append(app_dir)
    result = ScanResult(folders=list(folders))
    seen_paths: set = set()
    seen_content: set = set()
    for folder in folders:
        if not os.path.isdir(folder):
            result.skipped.append(f"missing folder: {folder}")
            continue
        for path in _walk(folder):
            real = os.path.realpath(path)
            if real in seen_paths:
                continue
            seen_paths.add(real)
            name = os.path.basename(path).lower()
            wanted = _looks_like_tool_name(name) or name.endswith(_FIRMWARE_SUFFIXES)
            try:
                if not os.path.isfile(path):
                    if wanted:
                        result.skipped.append(f"not a regular file: {path}")
                    continue
                size = os.path.getsize(path)
                if _looks_like_tool_name(name):
                    if size > MAX_TOOL_BYTES:
                        continue
                    digest = _sha256_file(path)
                    known = lib.identified.get(digest)
                    result.tools.append(
                        ToolEntry(
                            path=path,
                            family=known["family"] if known else "unidentified",
                            version=known["version"] if known else "",
                            platform=file_platform(path),
                            release=release_line(known["version"]) if known else "unknown",
                            sha256=digest,
                            identified=bool(known),
                        )
                    )
                    continue
                if 0 < size <= MAX_FIRMWARE_BYTES and name.endswith(_FIRMWARE_SUFFIXES):
                    with open(path, "rb") as f:
                        data = f.read()
                    digest = hashlib.sha256(data).hexdigest()
                    if digest in seen_content:
                        continue
                    seen_content.add(digest)
                    # A full ME image carries its partition table. Sub-partitions (OEMP, IOMP,
                    # PCH configuration...) carry manifest tags too but no partition table.
                    if not _looks_like_me_image(data):
                        continue
                    versions = iter_manifest_versions(data)
                    if versions:
                        counts: dict = {}
                        for v, _base in versions:
                            counts[v] = counts.get(v, 0) + 1
                        best = max(counts, key=counts.get)
                        result.firmware.append(FirmwareEntry(path, best, size))
            except OSError as exc:
                result.skipped.append(f"could not read {path}: {exc.strerror or exc}")
    return result


@dataclass
class ImportResult:
    source: str
    kind: str
    copied_to: str = ""
    refused: str = ""


def _has_flash_descriptor(data: bytes) -> bool:
    """True for a full SPI image. A standalone ME file does not carry this signature.

    The descriptor signature sits at 0x10 in a standard image and at 0 in images
    whose leading 16 bytes were not captured.
    """
    signature = 0x0FF0A55A
    for offset in (0x10, 0):
        end = offset + 4
        if end <= len(data) and int.from_bytes(data[offset:end], "little") == signature:
            return True
    return False


def _looks_like_me_image(data: bytes) -> bool:
    from bios_recovery.core.bios_analyzer import BiosAnalyzer

    if _has_flash_descriptor(data):
        return False
    return bool(BiosAnalyzer()._fpt_positions(data))


def _reserve_name(folder: str, name: str) -> str:
    """Create an empty file for ``name`` in ``folder``, numbered _1, _2... if taken."""
    base, ext = os.path.splitext(name)
    n = 0
    while True:
        candidate = os.path.join(folder, name if n == 0 else f"{base}_{n}{ext}")
        try:
            os.close(os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644))
            return candidate
        except FileExistsError:
            n += 1


def _remove_reserved(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def import_files(paths: list, kind: str) -> list:
    """Copy user-chosen files into the app's own library folder.

    Each file is read once. For a tool, that same copy is identified and then saved,
    so the file that was identified is the file that is kept. A firmware image is
    accepted only with a full ME partition table. Originals are never changed.
    """
    from bios_recovery.platforms.intel.me.fit_bridge import probe_tool

    if kind not in KINDS:
        raise ValueError(f"unknown kind: {kind}")
    target_dir = os.path.join(app_library_dir(), kind)
    os.makedirs(target_dir, exist_ok=True)
    results = []
    for src in paths:
        result = ImportResult(source=src, kind=kind)
        results.append(result)
        if not os.path.isfile(src):
            result.refused = "not a file"
            continue
        if os.path.getsize(src) > (MAX_TOOL_BYTES if kind == "tools" else MAX_FIRMWARE_BYTES):
            result.refused = "file is too large"
            continue
        with open(src, "rb") as f:
            blob = f.read()
        digest = hashlib.sha256(blob).hexdigest()
        ext = os.path.splitext(src)[1] if os.name == "nt" else ""
        if kind == "tools":
            with tempfile.TemporaryDirectory(prefix="fitimport_") as work:
                staged = os.path.join(work, os.path.basename(src))
                with open(staged, "wb") as f:
                    f.write(blob)
                if os.name != "nt":
                    os.chmod(staged, os.stat(staged).st_mode | stat.S_IXUSR)
                probe = probe_tool(staged)
            if not probe.identified:
                result.refused = "not a Flash Image Tool banner"
                continue
            name = tool_file_name(probe.family, probe.version, file_platform(src), ext)
            lib = load_library()
            lib.identified[digest] = {"family": probe.family, "version": probe.version}
            save_library(lib)
        else:
            if not _looks_like_me_image(blob):
                result.refused = "no full ME partition table"
                continue
            from bios_recovery.core.me_manifest import iter_manifest_versions

            versions = [v for v, _ in iter_manifest_versions(blob)]
            me = max(set(versions), key=versions.count) if versions else "unknown"
            name = f"ME_{me}_{os.path.basename(src)}"
        dest = _reserve_name(target_dir, name)
        try:
            write_file_atomic(dest, blob)
        except OSError as exc:
            _remove_reserved(dest)
            result.refused = f"could not save the copy: {exc.strerror or exc}"
            continue
        if kind == "tools" and os.name != "nt":
            os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR)
        result.copied_to = dest
    return results
