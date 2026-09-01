"""Self-update mechanism for BIOS Recovery Suite.

Queries the GitHub releases API for the latest release and, when a newer
version is found, downloads the Windows installer produced by CI and runs it
silently. Falls back to opening the releases page in a browser when the API
is unreachable (e.g. private repository without a token).

Stdlib only: urllib + json. No third-party dependencies.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

REPO = "ALeXXBody/BIOSRecoverySuite"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"
USER_AGENT = "BIOSRecoverySuite-Updater"
REQUEST_TIMEOUT = 20


def _parse_tag(tag: str) -> tuple:
    """'v1.2.3' -> (1, 2, 3); non-numeric parts are ignored."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", (tag or "").strip())
    if not m:
        return ()
    return tuple(int(p) for p in m.groups())


def is_newer(remote_tag: str, current_version: str) -> bool:
    remote = _parse_tag(remote_tag)
    current = _parse_tag(current_version)
    if not remote:
        return False
    if not current:
        return True
    return remote > current


def _pick_assets(assets: list) -> dict:
    """Select installer/portable download URLs from a release assets list."""
    installer = None
    portable = None
    for a in assets:
        name = (a.get("name") or "").lower()
        url = a.get("browser_download_url")
        if not url:
            continue
        if installer is None and name.startswith("biosrecoverysuite-setup-") and name.endswith(".exe"):
            installer = url
        if portable is None and "portable" in name and name.endswith(".zip"):
            portable = url
    return {"installer": installer, "portable": portable}


@dataclass
class ReleaseInfo:
    version: str
    notes: str
    html_url: str
    installer_url: Optional[str] = None
    portable_url: Optional[str] = None


def fetch_latest_release() -> ReleaseInfo:
    """Fetch the latest published release. Raises urllib.error on failure."""
    req = urllib.request.Request(LATEST_URL, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        data = json.load(resp)

    urls = _pick_assets(data.get("assets", []))
    return ReleaseInfo(
        version=(data.get("tag_name") or "").lstrip("v"),
        notes=data.get("body") or "",
        html_url=data.get("html_url") or RELEASES_PAGE,
        installer_url=urls["installer"],
        portable_url=urls["portable"],
    )


def download(url: str, dest_path: str, progress_cb: Optional[Callable[[int], None]] = None,
             chunk_size: int = 256 * 1024) -> str:
    """Stream a file to dest_path, reporting 0-100 progress via progress_cb."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, "wb") as out:
        total = resp.getheader("Content-Length")
        total = int(total) if total else None
        done = 0
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
            if progress_cb and total:
                progress_cb(min(100, int(done * 100 / total)))
    if progress_cb:
        progress_cb(100)
    return dest_path


def default_installer_destination(version: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"BIOSRecoverySuite-Setup-{version}.exe")


def apply_installer_update(installer_path: str) -> None:
    """Launch the downloaded Inno Setup installer silently.

    The caller should exit the application right afterwards. On systems where
    the app is installed in Program Files, Windows will show the UAC prompt.
    """
    if sys.platform != "win32":
        raise OSError("Silent self-update is only supported on Windows")
    subprocess.Popen(
        [installer_path, "/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"],
        close_fds=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
