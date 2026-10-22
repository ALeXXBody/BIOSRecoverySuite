# Backward-compat shim — real implementation lives in bios_recovery.core.
from bios_recovery.core.me_manifest import (
    MANIFEST_TAGS,
    annotations,
    detect_me_version_best,
    detect_me_version_in_blob,
    iter_manifest_versions,
    struct,
)

__all__ = [
    "MANIFEST_TAGS",
    "annotations",
    "detect_me_version_best",
    "detect_me_version_in_blob",
    "iter_manifest_versions",
    "struct",
]
