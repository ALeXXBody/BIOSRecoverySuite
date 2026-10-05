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
    message: str = ""


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
            b"IT8218",
            b"8218",
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
        """Return (offset, size) of the EC firmware within a dump.

        Handles both layouts:
          * standalone EC chip dump  ->  offset 0, whole file (it *is* the EC)
          * full SPI image (2-chip Lenovo designs) -> EC image in the TOP of
            the dump; signature hits found deep inside the BIOS area are
            noise and are rejected.

        Strategy: score candidate offsets by how many controller-family AND
        behavioral markers cluster around them; prefer the highest-offset
        cluster; size is derived from content (EOF / FF runs) with a hard
        512KB cap - EC images never exceed that.
        """
        if not data:
            return -1, -1

        families = list(self.CONTROLLER_SIGNATURES.values())
        all_markers = [s for fam in families for s in fam] + self.KBC_MARKERS

        # ---- standalone read (whole file looks like EC firmware) ---------
        window = min(len(data), 0x20000)
        head = data[:window]
        head_hits = sum(1 for s in all_markers if s in head)
        # a genuine EC image carries several markers; a BIOS head almost
        # never accumulates that many inside its first 128KB
        if head_hits >= 3:
            return 0, len(data)

        # ---- find candidate signature offsets ----------------------------
        candidates = []
        for sig_group in self.CONTROLLER_SIGNATURES.values():
            for sig in sig_group:
                idx = 0
                while True:
                    idx = data.find(sig, idx)
                    if idx < 0:
                        break
                    candidates.append((idx, sig_group))
                    idx += 1
        if not candidates:
            return -1, -1

        # ---- score each candidate by marker density in its neighbourhood --
        # a real EC image shows multiple distinct family/behavioral markers
        # within a 128KB window; noise shows one lonely short hit
        SCORE_RADIUS = 0x20000
        scored = []
        for off, _fam in candidates:
            lo, hi = max(0, off - SCORE_RADIUS), min(len(data), off + SCORE_RADIUS)
            distinct = sum(1 for m in all_markers if m in data[lo:hi])
            # density first; on a tie prefer the HIGHEST offset because 2-chip
            # designs put the EC in the top of the dump.
            scored.append((distinct, off))
        scored.sort(reverse=True)

        MAX_EC = 0x80000   # 512KB covers every known EC image
        # Real EC chips are 128/256/512KB, and a manufacturer embeds the EC
        # firmware as exactly one chip-sized block. Snapping to those sizes is
        # far more reliable than guessing where the image begins: the marker
        # hit can be anywhere INSIDE the image, but the region's END is
        # unambiguous (end-of-dump, or the padding that follows it).
        STD_EC_SIZES = (0x20000, 0x40000, 0x80000)

        start, size = -1, -1
        for distinct, anchor in scored[:32]:
            _blob_start, blob_end = self._blob_bounds(data, anchor, MAX_EC)
            # the region must end after the marker cluster
            if blob_end <= anchor:
                blob_end = anchor + 1
            # smallest standard chip size that still contains the cluster
            span = next((p for p in STD_EC_SIZES if blob_end - p <= anchor), None)
            if span is not None and blob_end - span >= 0:
                start, size = blob_end - span, span
                break

        if start < 0:
            # Nothing produced a chip-sized region: report not-found rather than
            # guessing, so the user can fall back to the manual override.
            return -1, -1

        # lonely short-string hit inside the BIOS area with no marker company:
        # reject rather than mislabel a huge region as "EC"
        short_noise = {b"\x80\x04", b"ITE", b"ENE", b"8218"}
        if distinct < 2:
            hit_sig = next(
                (s for s in all_markers if data.find(s, max(0, anchor - 8)) == anchor),
                None,
            )
            if start < len(data) - MAX_EC or (hit_sig in short_noise):
                return -1, -1

        return start, size

    @staticmethod
    def _is_pad_block(block: bytes) -> bool:
        """True when a block is entirely 0xFF.

        0xFF is *erased* flash, so it always terminates programmed content.
        All-zero blocks are deliberately NOT treated as padding: firmware is
        routinely zero-padded out to the full chip capacity, and cutting the
        region at the first zero run would truncate the image the user needs to
        flash. Zeros therefore stay inside the region.
        """
        if not block:
            return True
        return block.count(0xFF) == len(block)

    @classmethod
    def _blob_bounds(cls, data: bytes, anchor: int, max_span: int) -> tuple[int, int]:
        """Walk out from a marker hit to the enclosing firmware blob.

        Scans in 4KB blocks in both directions and stops at the first block
        that is pure 0xFF padding, or at the end of the file. Scanning
        per-block (rather than per-byte) means small 0xFF runs *inside* the
        firmware do not truncate the region.
        """
        BLOCK = 0x1000
        total = len(data)
        pos = (anchor // BLOCK) * BLOCK

        start = pos
        floor = max(0, pos - max_span)
        while start > floor:
            prev = start - BLOCK
            if prev < 0:
                break
            if cls._is_pad_block(data[prev:prev + BLOCK]):
                break
            start = prev

        end = min(total, pos + BLOCK)
        ceiling = min(total, pos + max_span)
        while end < ceiling:
            if cls._is_pad_block(data[end:end + BLOCK]):
                break
            end = min(total, end + BLOCK)

        return start, min(end, total)

    @staticmethod
    def _strip_ff_tail(data: bytes, start: int, end: int) -> int:
        """Trim trailing 0xFF padding down to the last non-FF byte."""
        while end > start + 0x100 and data[end - 1] == 0xFF:
            end -= 1
        return end

    def _strip_ff_run(self, data, start, end):
        # placeholder kept for API compatibility
        return self._strip_ff_tail(data, start, end)

    def analyze_ec(
        self,
        data: bytes,
        offset: Optional[int] = None,
        size: Optional[int] = None,
    ) -> ECAnalysis:
        """Analyse the EC firmware inside ``data``.

        ``offset``/``size`` override auto-detection. This matters because the
        EC region cannot always be found automatically, and a wrong guess means
        flashing the wrong bytes to the chip -- so the user must be able to pin
        the region themselves.
        """
        if offset is not None and offset >= 0 and size:
            offset = int(offset)
            size = int(size)
            if offset + size > len(data):
                return ECAnalysis(
                    found=False,
                    message=(
                        f"Region 0x{offset:X}+0x{size:X} runs past the end of the "
                        f"file (0x{len(data):X} bytes)."
                    ),
                )
        else:
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

    def extract_ec(
        self,
        input_path: str,
        output_path: str,
        offset: Optional[int] = None,
        size: Optional[int] = None,
    ) -> ECPatchResult:
        """Extract the EC region to ``output_path``.

        Pass ``offset``/``size`` to override auto-detection. The written file is
        ALWAYS exactly ``size`` bytes, so it can be flashed straight onto a chip
        of that capacity.
        """
        with open(input_path, "rb") as f:
            data = f.read()

        if offset is not None and offset >= 0 and size:
            offset = int(offset)
            size = int(size)
            if offset + size > len(data):
                return ECPatchResult(
                    status=ECStatus.ERROR,
                    message=(
                        f"Region 0x{offset:X}+0x{size:X} runs past the end of the "
                        f"file (0x{len(data):X} bytes)."
                    ),
                )
        else:
            offset, size = self.find_ec_region(data)
            if offset < 0:
                return ECPatchResult(
                    status=ECStatus.NOT_FOUND,
                    message=(
                        "No EC firmware found automatically. Set the offset and "
                        "size manually (e.g. size 0x40000 for a 256KB IT8218)."
                    ),
                )

        with open(output_path, "wb") as f:
            f.write(data[offset:offset + size])
        return ECPatchResult(
            status=ECStatus.SUCCESS,
            offset=offset,
            output_path=output_path,
            message=f"EC firmware extracted: offset 0x{offset:X}, {size} bytes ({size // 1024} KB)",
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
