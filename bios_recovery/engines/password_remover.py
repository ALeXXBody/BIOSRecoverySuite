# Backward-compat shim — real implementation lives in bios_recovery.core.
from bios_recovery.core.password_remover import (
    Enum,
    Optional,
    PasswordRemovalReport,
    PasswordRemovalResult,
    PasswordRemover,
    PasswordType,
    auto,
    dataclass,
    field,
    os,
    struct,
)

__all__ = [
    "Enum",
    "Optional",
    "PasswordRemovalReport",
    "PasswordRemovalResult",
    "PasswordRemover",
    "PasswordType",
    "auto",
    "dataclass",
    "field",
    "os",
    "struct",
]
