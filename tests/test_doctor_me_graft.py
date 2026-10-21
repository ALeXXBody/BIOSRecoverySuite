"""Tests for the integrity doctor and ME-coverage graft guards."""

import struct

from bios_recovery.engines.bios_repair import BiosRepairEngine
from bios_recovery.engines.me_injector import _inject_from_dump  # not used; remove
