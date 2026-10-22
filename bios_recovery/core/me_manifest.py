"""Shared Intel ME manifest version parsing.

Layout (generations 1-3): a partition manifest starts at `base`; its tag
(`$MN2` gen2/gen3, `$MAN` gen1) is stored at base+0x1C, and the firmware
version fields (u16 major, minor, hotfix, build) live at base+0x24 — i.e.
tag_offset + 0x08. This is valid for ME 2.x through CSME 14+ (verified
against MEAnalyzer and me_cleaner on real dumps).
"""

from __future__ import annotations

import hashlib
import struct
from collections import Counter

MANIFEST_TAGS = (b"$MN2", b"$MAN")
_TAG_OFFSET = 0x1C
_VERSION_OFFSET = 0x24
_PUBKEY_OFFSET = 0x80
_PUBKEY_SIZE = 0x104
_MAX_MANIFEST_MATCHES = 2000

# MD5 of the 0x104-byte RSA public key in the manifest (corna/me_cleaner pubkeys_md5, TXE entries).
TXE_PUBKEY_MD5 = frozenset(
    {
        "bda0b6bb8ca0bf0cac55ac4c4d55e0f2",
        "b726a2ab9cd59d4e62fe2bead7cf6997",
        "0633d7f951a3e7968ae7460861be9cfb",
        "1d0a36e9f5881540d8e4b382c6612ed8",
    }
)


def iter_manifest_versions(blob: bytes) -> list[tuple[str, int]]:
    """Return [(version_str, manifest_base_off), ...] for every sane manifest.

    Manifests with a zero major version (uninitialized module copies) are skipped.
    Each tag has its own match cap.
    """
    out: list[tuple[str, int]] = []
    n = len(blob)
    for tag in MANIFEST_TAGS:
        pos = 0
        seen = 0
        while True:
            idx = blob.find(tag, pos)
            if idx < 0 or seen > _MAX_MANIFEST_MATCHES:
                break
            seen += 1
            base = idx - _TAG_OFFSET
            if base >= 0 and base + _VERSION_OFFSET + 8 <= n:
                major, minor, hotfix, build = struct.unpack_from(
                    "<HHHH", blob, base + _VERSION_OFFSET
                )
                if 0 < major < 100 and minor < 200 and build < 0x20000:
                    out.append((f"{major}.{minor}.{hotfix}.{build}", base))
            pos = idx + 1
    return out


def engine_version(blob: bytes) -> str:
    """The engine version: the most common manifest version in the blob ('' if none)."""
    counts = Counter(v for v, _base in iter_manifest_versions(blob))
    return counts.most_common(1)[0][0] if counts else ""


def engine_is_txe(blob: bytes) -> bool:
    """True when a manifest of the engine version carries a TXE public key."""
    versions = iter_manifest_versions(blob)
    if not versions:
        return False
    engine = Counter(v for v, _base in versions).most_common(1)[0][0]
    for version, base in versions:
        if version != engine:
            continue
        key = blob[base + _PUBKEY_OFFSET : base + _PUBKEY_OFFSET + _PUBKEY_SIZE]
        if len(key) == _PUBKEY_SIZE and hashlib.md5(key).hexdigest() in TXE_PUBKEY_MD5:
            return True
    return False


def detect_me_version_in_blob(blob: bytes) -> str:
    """Best-effort full version string (maj.min.hot.bld) inside a blob/region."""
    versions = iter_manifest_versions(blob)
    if not versions:
        return ""
    return versions[0][0]


def detect_me_version_best(blob: bytes) -> str:
    """Highest version found (used to pick the main engine manifest)."""
    versions = iter_manifest_versions(blob)
    if not versions:
        return ""

    def key(v: str) -> tuple[float, ...]:
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (0.0,)

    return max(versions, key=lambda t: key(t[0]))[0]
