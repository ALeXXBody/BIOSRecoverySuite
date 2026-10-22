# Backward-compat shim — real implementation lives in bios_recovery.core.
from bios_recovery.core.bios_analyzer import (
    BiosAnalysisResult,
    BiosAnalyzer,
    BiosType,
    Enum,
    RegionInfo,
    RegionType,
    auto,
    dataclass,
    field,
    hashlib,
    os,
    struct,
)

__all__ = [
    "BiosAnalysisResult",
    "BiosAnalyzer",
    "BiosType",
    "Enum",
    "RegionInfo",
    "RegionType",
    "auto",
    "dataclass",
    "field",
    "hashlib",
    "os",
    "struct",
]
