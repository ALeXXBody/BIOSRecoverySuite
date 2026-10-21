"""ME Analyzer update check and verified staging (platomav/MEAnalyzer).

The check compares the bundled MEA.py version with the latest GitHub release.
A release is staged only when:
  * GitHub publishes a SHA-256 digest for the zip asset and the download matches it;
  * only .py and .dat members are extracted, each written by base name only.
Nothing is loaded or executed from the staging folder by this module.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Optional

MEA_REPO = "platomav/MEAnalyzer"
LATEST_URL = f"https://api.github.com/repos/{MEA_REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{MEA_REPO}/releases"
USER_AGENT = "BIOSRecoverySuite-MEA-Updater"
REQUEST_TIMEOUT = 20
ALLOWED_SUFFIXES = (".py", ".dat")
MAX_ZIP_BYTES = 64 * 1024 * 1024


@dataclass
class MEAReleaseInfo:
    tag: str
    name: str
    html_url: str
    zip_url: Optional[str] = None
    zip_sha256: Optional[str] = None
    published_at: str = ""


def parse_mea_version(tag: str) -> tuple:
    """'v1.312.0-r378' -> (1, 312, 0, 378); 'r376' -> (0, 0, 0, 376)."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)-r(\d+)", tag)
    if m:
        return tuple(int(x) for x in m.groups())
    m = re.search(r"r(\d+)", tag)
    if m:
        return (0, 0, 0, int(m.group(1)))
    return ()


def _base_version(text: str) -> tuple:
    """'v1.312.0-r378' or '1.312.0' -> (1, 312, 0); anything else -> ()."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else ()


def is_mea_newer(remote_tag: str, local_tag: str) -> bool:
    remote = parse_mea_version(remote_tag)
    local = parse_mea_version(local_tag)
    if not remote:
        return False
    if not local:
        return True
    return remote > local


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.load(resp)


def fetch_latest_mea_release() -> MEAReleaseInfo:
    data = _get_json(LATEST_URL)
    zip_url = None
    zip_sha = None
    for asset in data.get("assets", []):
        if (asset.get("name") or "").lower().endswith(".zip"):
            zip_url = asset.get("browser_download_url")
            digest = asset.get("digest") or ""
            if digest.startswith("sha256:"):
                zip_sha = digest.split(":", 1)[1]
            break
    return MEAReleaseInfo(
        tag=data.get("tag_name") or "",
        name=data.get("name") or "",
        html_url=data.get("html_url") or RELEASES_PAGE,
        zip_url=zip_url,
        zip_sha256=zip_sha,
        published_at=data.get("published_at") or "",
    )


def extract_version_from_mea_py(mea_py_path: str) -> str:
    """Version from the `title = 'ME Analyzer vX.Y.Z'` line of MEA.py."""
    try:
        with open(mea_py_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("title ="):
                    m = re.search(r"v(\d+\.\d+\.\d+)", line)
                    return m.group(1) if m else ""
    except OSError:
        pass
    return ""


def check_mea_update(local_mea_py: str) -> dict:
    """Compare the bundled MEA.py with the latest release. Makes one API request."""
    local = extract_version_from_mea_py(local_mea_py)
    remote = fetch_latest_mea_release()
    remote_base = _base_version(remote.tag)
    local_base = _base_version(local)
    if local_base and remote_base == local_base:
        # Same release line; MEA.py does not record its revision, so the revision
        # suffix cannot be compared and the build is reported as unknown.
        status = "same version (revision unknown)"
        newer = False
    else:
        status = "newer release available" if is_mea_newer(remote.tag, f"v{local}" if local else "") else "up to date"
        newer = status == "newer release available"
    return {
        "local_version": local,
        "remote_tag": remote.tag,
        "status": status,
        "newer": newer,
        "html_url": remote.html_url,
        "has_verified_asset": bool(remote.zip_url and remote.zip_sha256),
        "_release": remote,
    }


def stage_mea_update(release: MEAReleaseInfo, staging_dir: str) -> list[str]:
    """Download the release zip, verify its digest, and stage .py/.dat files.

    Raises ValueError (and writes nothing) if the digest is missing or wrong.
    """
    if not release.zip_url or not release.zip_sha256:
        raise ValueError("release has no published SHA-256 digest for its zip; refusing to stage")
    req = urllib.request.Request(release.zip_url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        blob = resp.read(MAX_ZIP_BYTES + 1)
    if len(blob) > MAX_ZIP_BYTES:
        raise ValueError("zip is larger than the allowed size; refusing to stage")
    if hashlib.sha256(blob).hexdigest() != release.zip_sha256:
        raise ValueError("SHA-256 mismatch on the downloaded zip; refusing to stage")

    staged = []
    os.makedirs(staging_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            base = os.path.basename(info.filename)
            if not base.lower().endswith(ALLOWED_SUFFIXES):
                continue
            dest = os.path.join(staging_dir, base)
            with zf.open(info) as src, open(dest, "wb") as out:
                out.write(src.read())
            staged.append(base)
    if "MEA.py" not in staged:
        raise ValueError("zip does not contain MEA.py; nothing staged")
    return staged
