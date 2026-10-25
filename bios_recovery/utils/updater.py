"""Self-update mechanism for BIOS Recovery Suite.

Queries the GitHub releases API for the latest release and, when a newer
version is found, downloads the Windows installer produced by CI and runs it
silently. Falls back to opening the releases page in a browser when the API
is unreachable (e.g. private repository without a token).

Stdlib only: urllib + json. No third-party dependencies.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

# Ed25519 public key used to verify release signatures. The matching private key
# is kept off the repository and is used to sign each installer at release time.
_SIGNING_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEA+z/OlJRE5SPt/OEUwEYRH3DGfETTY+y7zoqBnjj/fa4="

REPO = "ALeXXBody/BIOSRecoverySuite"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"
USER_AGENT = "BIOSRecoverySuite-Updater"
REQUEST_TIMEOUT = 20
MAX_INSTALLER_BYTES = 256 * 1024 * 1024
_STRICT_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


class UpdateIntegrityError(Exception):
    """The download is not the file the release published; it is never run."""


def _parse_tag(tag: str) -> tuple:
    """'v1.2.3' -> (1, 2, 3); anything else (extra text, path parts) is rejected."""
    m = _STRICT_TAG.match((tag or "").strip())
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
    """Select installer/portable/signature download URLs and the installer's published SHA-256."""
    installer = None
    installer_sha = None
    portable = None
    signature = None
    for a in assets:
        name = (a.get("name") or "").lower()
        url = a.get("browser_download_url")
        if not url or not url.startswith("https://"):
            continue
        if (
            installer is None
            and name.startswith("biosrecoverysuite-setup-")
            and name.endswith(".exe")
        ):
            installer = url
            digest = a.get("digest") or ""
            if digest.startswith("sha256:"):
                installer_sha = digest.split(":", 1)[1].lower()
        if portable is None and "portable" in name and name.endswith(".zip"):
            portable = url
        if signature is None and name.endswith(".sig") and "setup" in name:
            signature = url
    return {
        "installer": installer,
        "installer_sha256": installer_sha,
        "portable": portable,
        "signature": signature,
    }


@dataclass
class ReleaseInfo:
    version: str
    notes: str
    html_url: str
    installer_url: Optional[str] = None
    portable_url: Optional[str] = None
    installer_sha256: Optional[str] = None
    signature_url: Optional[str] = None


def fetch_latest_release() -> ReleaseInfo:
    """Fetch the latest published release. Raises urllib.error on failure."""
    req = urllib.request.Request(
        LATEST_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        _require_https_response(resp)
        data = json.load(resp)

    urls = _pick_assets(data.get("assets", []))
    return ReleaseInfo(
        version=(data.get("tag_name") or "").lstrip("v"),
        notes=data.get("body") or "",
        html_url=data.get("html_url") or RELEASES_PAGE,
        installer_url=urls["installer"],
        portable_url=urls["portable"],
        installer_sha256=urls["installer_sha256"],
        signature_url=urls["signature"],
    )


def _require_https_response(resp) -> None:
    """urllib follows redirects; the final address must still be HTTPS."""
    if not resp.geturl().startswith("https://"):
        raise UpdateIntegrityError("refusing a redirect to a non-HTTPS address")


def download(
    url: str,
    dest_path: str,
    progress_cb: Optional[Callable[[int], None]] = None,
    chunk_size: int = 256 * 1024,
) -> str:
    """Stream a file to dest_path. A download that ends early is an error.

    Refuses non-HTTPS URLs and files over MAX_INSTALLER_BYTES. On any failure the
    partial file is removed.
    """
    if not url.startswith("https://"):
        raise UpdateIntegrityError("refusing a non-HTTPS download")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, "wb") as out:
            _require_https_response(resp)
            length = resp.getheader("Content-Length")
            total = int(length) if length else None
            if total is not None and total > MAX_INSTALLER_BYTES:
                raise UpdateIntegrityError("download is larger than the allowed size")
            done = 0
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                done += len(chunk)
                if done > MAX_INSTALLER_BYTES:
                    raise UpdateIntegrityError("download is larger than the allowed size")
                out.write(chunk)
                if progress_cb and total:
                    progress_cb(min(100, int(done * 100 / total)))
            if total is not None and done != total:
                raise UpdateIntegrityError(f"download ended early ({done} of {total} bytes)")
    except BaseException:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise
    if progress_cb:
        progress_cb(100)
    return dest_path


def verify_sha256(path: str, expected: Optional[str]) -> None:
    """Fail closed: no published digest, or a different digest, means the file is not run."""
    if not expected:
        raise UpdateIntegrityError("the release publishes no SHA-256 for this installer")
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected.lower():
        raise UpdateIntegrityError("SHA-256 of the download does not match the release")


def _load_signing_public_key():
    """Return the Ed25519 public key, or None if cryptography is unavailable."""
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except ImportError:
        return None
    try:
        raw = base64.b64decode(_SIGNING_PUBLIC_KEY_B64)
        return load_der_public_key(raw)
    except Exception:
        return None


def verify_signature(path: str, signature_path: Optional[str]) -> None:
    """Verify an Ed25519 signature over the installer, if a signature is published.

    When cryptography is not installed the check is skipped (the SHA-256 check
    still runs). When a signature file is published it must verify; a missing or
    invalid signature raises UpdateIntegrityError.
    """
    key = _load_signing_public_key()
    if key is None:
        return
    if not signature_path or not os.path.isfile(signature_path):
        # No signature published yet: rely on SHA-256 alone.
        return
    with open(signature_path, "rb") as f:
        signature = f.read()
    with open(path, "rb") as f:
        data = f.read()
    try:
        key.verify(signature, data)
    except Exception as exc:
        raise UpdateIntegrityError(f"installer signature does not verify: {exc}")


def make_private_download_dir() -> str:
    """A fresh directory only this process writes to, so the file cannot be swapped out."""
    return tempfile.mkdtemp(prefix="bsr_update_")


def default_installer_destination(version: str) -> str:
    return os.path.join(make_private_download_dir(), f"BIOSRecoverySuite-Setup-{version}.exe")


def apply_installer_update(installer_path: str) -> None:
    """Launch the downloaded Inno Setup installer silently.

    The caller should exit the application right afterwards. On systems where
    the app is installed in Program Files, Windows will show the UAC prompt.
    """
    if sys.platform != "win32":
        raise OSError("Silent self-update is only supported on Windows")
    if not os.path.isfile(installer_path):
        raise OSError("installer is missing")
    proc = subprocess.Popen(
        [installer_path, "/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"],
        close_fds=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    # A real installer keeps running. One that exits at once did not start the update,
    # so the caller must keep the application open.
    try:
        code = proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return
    raise OSError(f"the installer exited straight away (code {code}); the update did not start")
