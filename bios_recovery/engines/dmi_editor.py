# Backward-compat shim — real implementation lives in bios_recovery.core.
from bios_recovery.core.dmi_editor import (
    DMIEditor,
    DMIEditReport,
    Optional,
    annotations,
    dataclass,
    field,
    struct,
)

__all__ = [
    "DMIEditReport",
    "DMIEditor",
    "Optional",
    "annotations",
    "dataclass",
    "field",
    "struct",
]
