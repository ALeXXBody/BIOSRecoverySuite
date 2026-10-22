# Backward-compat shim — real implementation lives in bios_recovery.core.
from bios_recovery.core.dmi_clone import (
    DMIClone,
    struct,
)

__all__ = [
    "DMIClone",
    "struct",
]
