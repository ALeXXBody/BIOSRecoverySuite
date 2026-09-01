"""EC (Embedded Controller) firmware analysis and patching engine.

The EC is a dedicated microcontroller on the motherboard that manages power,
keyboard, fan control, and (on many modern laptops) performs the BIOS-setup
password verification. On 2-chip designs the EC firmware lives in a separate
flash chip (often 256KB or 512KB) that is imaged in the top of a full SPI dump.

This engine:
  1. Locates EC firmware inside a BIOS/spi dump,
  2. Identifies the EC controller vendor (ITE / Nuvoton / Microchip MEC / ENE),
  3. Scans for password/security markers,
  4. Provides a data-driven patch framework with a verifiable signature/patch
     registry (patterns are loaded from `patches/ec_patches.json` so users can
     contribute verified patterns without touching code).
"""

import json
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class ECController(Enum):
    UNKNOWN = auto()
    ITE = auto()
    NUVOTON = auto()
    MEC = auto()
    ENE = auto()


class ECStatus(Enum):
    ECOK = auto()
    NOT_FOUND = auto()
    PATTERN_MISSING = auto()
    VERIFIED = auto()
    UNVERIFIED = auto()
    SUCCESS = auto()
    ERROR = auto()


@dataclass
class ECPatch:
    key: str
    vendor: str
    generation: str
    controller: str
    description: str
    signature_hex: str
    patch_hex: str
    offset_hint: str = ""
    verified: bool = False
    source: str = ""


@dataclass
class ECAnalysis:
    found: bool = False
    offset: int = 0
    size: int = 0
    controller: ECController = ECController.UNKNOWN
    controller_name: str = ""
    magic: str = ""
    password_flags: list[dict] = field(default_factory=list)
    has_kbc_config: bool = False
    checksum_valid: Optional[bool] = None
    raw: bytes = b""


@dataclass
class ECPatchResult:
    status: ECStatus
    patch: Optional[ECPatch] = None
    message: str = ""
    offset: int = -1
    output_path: str = ""


class ECPatcher:
    """Analyzes and patches EC firmware regions."""

    CONTROLLER_SIGNATURES = {
        ECController.ITE: [
            b"ITE",
            b"IT85",
            b"IT87",
            b"IT89",
            b"8528",
            b"8587",
            b"8528E",
            b"8518",
            b"\x80\x04",   # ITE reporter ID used in many EC images
        ],
        ECController.NUVOTON: [
            b"NPCE",
            b"Nuvoton",
            b"NUVOTON",
            b"NPCX",
            b"NPCY",
        ],
        ECController.MEC: [
            b"MEC1",
            b"MEC14",
            b"MICROCHIP",
            b"MEC15",
            b"MEC16",
            b"MEC17",
        ],
        ECController.ENE: [
            b"ENE",
            b"KB9012",
            b"KB9022",
            b"2533",
            b"2543",
        ],
    }

    SECURITY_MARKERS = {
        "PasswordStatus": b"PasswordStatus",
        "UnLock": b"UnLock",
        "UNLock": b"UNLock",
        "Pass": b"\x50\x00\x61\x00\x73\x00\x73",
        "SecurityFeatures": b"SecurityFeatures",
        "secFPass": b"secFPass",
        "PayloadLock": b"PayloadLock",
        "HashPass": b"HashPass",
        "PassHash": b"PassHash",
        "KBC_PW": b"KBC_PW",
    }

    KBC_MARKERS = [b"KBC_CONFIG", b"KBCDebug", b"KBCSecurity"]

    def __init__(self, patches_path: Optional[str] = None):
        self.patches_path = patches_path or self._default_patches_path()
        self._patches: list[ECPatch] = []
        self._load_patches()

    def _default_patches_path(self) -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(os.path.dirname(here), "patches", "ec_patches.json")

    def find_ec_region(self, data: bytes) -> tuple[int, int]:
        """Return (offset, size) of the EC firmware within a full dump."""
        candidates = []

        for sig_group in self.CONTROLLER_SIGNATURES.values():
            for sig in sig_group:
                idx = data.find(sig)
                if idx >= 0:
                    candidates.append(idx)

        if not candidates:
            return -1, -1

        earliest = min(candidates)

        start = earliest & ~0xFFF
        if start < 0:
            start = 0

        remaining = len(data) - start
        if remaining <= 0x10000:
            return start, remaining

        ff_tail = 0
        tail_start = max(len(data) - 0x40000, start)
        if tail_start > start + 0x10:
            for i in range(len(data) - 1, tail_start - 1, -1):
                if data[i] == 0xFF:
                    ff_tail += 1
                else:
                    break
        else:
            ff_tail = 0

        if ff_tail > 0 and len(data) - ff_tail >= start:
            end = len(data) - ff_tail
        else:
            end = len(data)
            while end - start > 0x80000:
                end = min(len(data), start + 0x80000)

        return start, end - start

    def analyze_ec(self, data: bytes) -> ECAnalysis:
        offset, size = self.find_ec_region(data)
        if offset < 0:
            return ECAnalysis(found=False)

        ec_data = data[offset:offset + size]
        analysis = ECAnalysis(found=True, offset=offset, size=size, raw=ec_data)

        analysis.controller = self._detect_controller(ec_data)
        analysis.controller_name = analysis.controller.name
        analysis.magic = ec_data[:8].hex()

        analysis.has_kbc_config = any(m in ec_data for m in self.KBC_MARKERS)

        for name, pattern in self.SECURITY_MARKERS.items():
            search = 0
            while True:
                idx = ec_data.find(pattern, search)
                if idx < 0:
                    break
                blob = ec_data[max(0, idx - 8):idx + 16]
                analysis.password_flags.append({
                    "name": name,
                    "offset_in_ec": idx,
                    "offset_in_image": offset + idx,
                    "context": blob.hex(),
                })
                search = idx + 1

        analysis.checksum_valid = self._check_xor_checksum(ec_data)
        return analysis

    def _detect_controller(self, ec_data: bytes) -> ECController:
        best = ECController.UNKNOWN
        best_score = 0
        for controller, sigs in self.CONTROLLER_SIGNATURES.items():
            score = sum(1 for s in sigs if s in ec_data)
            if score > best_score:
                best_score = score
                best = controller
        return best if best_score else ECController.UNKNOWN

    def _check_xor_checksum(self, ec_data: bytes) -> Optional[bool]:
        """Many older ITE/Nuvoton EC images store an XOR checksum in the last byte."""
        if len(ec_data) < 2:
            return None
        xor = 0
        for b in ec_data[:-1]:
            xor ^= b
        return xor == ec_data[-1]

    def list_patches(self, vendor: Optional[str] = None, controller: Optional[ECController] = None) -> list[ECPatch]:
        result = []
        for p in self._patches:
            if vendor and p.vendor.lower() != vendor.lower():
                continue
            if controller and p.controller and controller.name.lower() != p.controller.lower():
                continue
            result.append(p)
        return result

    def get_patch(self, key: str) -> Optional[ECPatch]:
        for p in self._patches:
            if p.key == key:
                return p
        return None

    def apply_patch(
        self,
        input_path: str,
        patch_key: str,
        output_path: Optional[str] = None,
        require_verified: bool = True,
    ) -> ECPatchResult:
        patch = self.get_patch(patch_key)
        if patch is None:
            return ECPatchResult(status=ECStatus.ERROR, message=f"Unknown patch key: {patch_key}")

        if require_verified and not patch.verified:
            return ECPatchResult(
                status=ECStatus.UNVERIFIED,
                patch=patch,
                message="This patch is not reviewed/verified and is applied at your own risk.",
            )

        try:
            signature = bytes.fromhex(patch.signature_hex)
            replacement = bytes.fromhex(patch.patch_hex)
        except ValueError as e:
            return ECPatchResult(status=ECStatus.ERROR, patch=patch, message=f"Invalid hex: {e}")

        if len(signature) != len(replacement):
            return ECPatchResult(
                status=ECStatus.ERROR,
                patch=patch,
                message=f"Signature ({len(signature)}) and patch ({len(replacement)}) sizes differ",
            )

        with open(input_path, "rb") as f:
            data = bytearray(f.read())

        offset = self._find_offset_for_patch(data, patch)
        if offset < 0:
            return ECPatchResult(
                status=ECStatus.PATTERN_MISSING,
                patch=patch,
                message="Signature not found in image",
            )

        data[offset:offset + len(replacement)] = replacement

        if output_path is None:
            output_path = input_path.rsplit(".", 1)[0] + "_ecpatched.bin"

        with open(output_path, "wb") as f:
            f.write(data)

        return ECPatchResult(
            status=ECStatus.SUCCESS,
            patch=patch,
            offset=offset,
            output_path=output_path,
            message=f"Patch '{patch.key}' applied at 0x{offset:X}",
        )

    def _find_offset_for_patch(self, data: bytes, patch: ECPatch) -> int:
        try:
            signature = bytes.fromhex(patch.signature_hex)
        except ValueError:
            return -1
        return data.find(signature)

    def extract_ec(self, input_path: str, output_path: str) -> ECPatchResult:
        with open(input_path, "rb") as f:
            data = f.read()
        offset, size = self.find_ec_region(data)
        if offset < 0:
            return ECPatchResult(status=ECStatus.NOT_FOUND, message="No EC firmware found")
        with open(output_path, "wb") as f:
            f.write(data[offset:offset + size])
        return ECPatchResult(
            status=ECStatus.SUCCESS,
            offset=offset,
            output_path=output_path,
            message=f"EC firmware extracted: offset 0x{offset:X}, {size} bytes",
        )

    def _load_patches(self) -> None:
        if not os.path.exists(self.patches_path):
            return
        try:
            with open(self.patches_path, "r") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for item in raw if isinstance(raw, list) else raw.get("patches", []):
            self._patches.append(ECPatch(
                key=item.get("key", ""),
                vendor=item.get("vendor", ""),
                generation=item.get("generation", ""),
                controller=item.get("controller", ""),
                description=item.get("description", ""),
                signature_hex=item.get("signature_hex", ""),
                patch_hex=item.get("patch_hex", ""),
                offset_hint=item.get("offset_hint", ""),
                verified=item.get("verified", False),
                source=item.get("source", ""),
            ))

    def install_patch(self, patch: ECPatch) -> None:
        self._patches.append(patch)
        os.makedirs(os.path.dirname(self.patches_path), exist_ok=True)
        entries = [
            {
                "key": p.key,
                "vendor": p.vendor,
                "generation": p.generation,
                "controller": p.controller,
                "description": p.description,
                "signature_hex": p.signature_hex,
                "patch_hex": p.patch_hex,
                "offset_hint": p.offset_hint,
                "verified": p.verified,
                "source": p.source,
            }
            for p in self._patches
        ]
        with open(self.patches_path, "w") as f:
            json.dump({"patches": entries}, f, indent=2)
