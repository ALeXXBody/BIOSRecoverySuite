"""ME Analyzer updater - checks platomav/MEAnalyzer releases and updates bundled MEA files."""

import json
import os
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Optional, Callable

MEA_REPO = "platomav/MEAnalyzer"
LATEST_URL = f"https://api.github.com/repos/{MEA_REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{MEA_REPO}/releases"
USER_AGENT = "BIOSRecoverySuite-MEA-Updater"
REQUEST_TIMEOUT = 20


@dataclass
class MEAReleaseInfo:
    tag: str
    name: str
    html_url: str
    zip_url: Optional[str] = None
    published_at: str = ""


def parse_mea_version(tag: str) -> tuple:
    # tags like v1.312.0-r378 or r376
    import re
    m = re.search(r'(\d+)\.(\d+)\.(\d+)-r(\d+)', tag)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
    m = re.search(r'r(\d+)', tag)
    if m:
        return (0, 0, 0, int(m.group(1)))
    return ()


def fetch_latest_mea_release() -> MEAReleaseInfo:
    req = urllib.request.Request(LATEST_URL, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.load(resp)
    except Exception:
        raise

    zip_url = None
    for a in data.get("assets", []):
        name = (a.get("name") or "").lower()
        if name.endswith(".zip"):
            zip_url = a.get("browser_download_url")
            break
    if not zip_url:
        zip_url = data.get("zipball_url")

    return MEAReleaseInfo(
        tag=data.get("tag_name") or "",
        name=data.get("name") or "",
        html_url=data.get("html_url") or RELEASES_PAGE,
        zip_url=zip_url,
        published_at=data.get("published_at") or "",
    )


def is_mea_newer(remote_tag: str, local_tag: str) -> bool:
    r = parse_mea_version(remote_tag)
    l = parse_mea_version(local_tag)
    if not r: return False
    if not l: return True
    return r > l


def extract_version_from_mea_py(mea_py_path: str) -> str:
    try:
        with open(mea_py_path, encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('title ='):
                    # e.g. title = 'ME Analyzer v1.312.0'
                    import re
                    m = re.search(r'v(\d+\.\d+\.\d+)', line)
                    if m: return m.group(1)
                    break
    except Exception:
        pass
    return ""


def extract_db_rev_from_dat(mea_dat_path: str) -> int:
    try:
        with open(mea_dat_path, encoding='utf-8', errors='replace') as f:
            for line in f:
                if 'Revision' in line:
                    import re
                    m = re.search(r'Revision\s+(\d+)', line)
                    if m: return int(m.group(1))
                    break
    except Exception:
        pass
    return 0


def download_mea_zip(url: str, dest_path: str,
                     progress_cb: Optional[Callable[[int], None]] = None,
                     chunk_size: int = 256*1024) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, 'wb') as out:
        total = resp.getheader("Content-Length")
        total = int(total) if total else None
        done = 0
        while True:
            chunk = resp.read(chunk_size)
            if not chunk: break
            out.write(chunk)
            done += len(chunk)
            if progress_cb and total:
                progress_cb(min(100, int(done*100/total)))
    if progress_cb: progress_cb(100)
    return dest_path


def apply_mea_update(zip_path: str, target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as z:
        for name in z.namelist():
            # extract only root-level files or files in root dir of zip
            parts = name.split('/')
            if len(parts) == 0: continue
            # zipball from GitHub may have prefix repo-commit/
            rel = '/'.join(parts[1:]) if len(parts) > 1 and parts[0].endswith('MEAnalyzer') or len(parts)>1 else name
            if rel in ('', '__MACOSX'): continue
            if rel.endswith('/') or rel.startswith('.git'): continue
            # only MEA files
            if not (rel.endswith('.py') or rel.endswith('.dat')):
                # allow other data files? MEA has .dat only
                pass
            dest_name = rel if '/' not in rel else os.path.basename(rel)
            dest = os.path.join(target_dir, dest_name)
            # extract member
            data = z.read(name)
            with open(dest, 'wb') as f:
                f.write(data)
