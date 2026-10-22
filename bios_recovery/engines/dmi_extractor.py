# Backward-compat shim — real implementation lives in bios_recovery.core.
from bios_recovery.core.dmi_extractor import (
    DMIExtractor,
    DMIField,
    DMIInfo,
    DMIStructure,
    Optional,
    dataclass,
    field,
    struct,
)

__all__ = [
    "DMIExtractor",
    "DMIField",
    "DMIInfo",
    "DMIStructure",
    "Optional",
    "dataclass",
    "field",
    "struct",
]
