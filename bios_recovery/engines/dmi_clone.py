# Backward-compat shim — real implementation lives in bios_recovery.core.
import struct

from bios_recovery.core.dmi_clone import (
    DMIClone,
)

__all__ = [
    "DMIClone",
    "struct",
]
