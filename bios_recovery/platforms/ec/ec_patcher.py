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

from bios_recovery.core.safety import SameFileError, ensure_distinct


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
            # New-generation ITE ECs (IT5xxx family: IT5571E, IT5731E,
            # IT51363E/IT51368E/IT51378E variants) — same RISC-V lineage.
            b"IT55",
            b"IT51",
            b"IT57",
            b"\x80\x04",  # ITE reporter ID used in many EC images
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
        self.load_error: Optional[str] = None
        self._load_patches()

    def _default_patches_path(self) -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(os.path.dirname(os.path.dirname(here)), "patches", "ec_patches.json")

    def _scored_anchors(self, data: bytes) -> list[tuple[int, int]]:
        """Score every controller/KBC signature hit by marker density nearby.

        Returns (distinct_markers, offset) pairs, densest first; on a tie the
        HIGHEST offset wins because 2-chip designs put the EC in the top of
        the dump. A real EC image shows several distinct family/behavioral
        markers inside a 128KB window; noise shows one lonely short hit.
        """
        candidates = []
        for sig_group in self.CONTROLLER_SIGNATURES.values():
            for sig in sig_group:
                idx = 0
                while True:
                    idx = data.find(sig, idx)
                    if idx < 0:
                        break
                    candidates.append(idx)
                    idx += 1
        if not candidates:
            return []

        families = list(self.CONTROLLER_SIGNATURES.values())
        all_markers = [s for fam in families for s in fam] + self.KBC_MARKERS
        radius = 0x20000
        scored = []
        for off in candidates:
            lo, hi = max(0, off - radius), min(len(data), off + radius)
            distinct = sum(1 for m in all_markers if m in data[lo:hi])
            scored.append((distinct, off))
        scored.sort(reverse=True)
        return scored

    def find_ec_region(self, data: bytes) -> tuple[int, int]:
        """Return (offset, size) of the EC firmware within a dump.

        Handles both layouts:
          * standalone EC chip dump  ->  offset 0, whole file (it *is* the EC)
          * full SPI image (2-chip Lenovo designs) -> EC image in the TOP of
            the dump; signature hits found deep inside the BIOS area are
            noise and are rejected.

        Strategy: score candidate offsets by how many controller-family AND
        behavioral markers cluster around them; then require the region to be
        bounded by observed content facts (0xFF padding / EOF) at a real chip
        capacity, with every check derived from structure alone. A boundary
        that is computed rather than observed is a guess, and a guessed EC
        region must never be flashed.
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
        scored = self._scored_anchors(data)
        if not scored:
            return -1, -1

        MAX_EC = 0x80000  # 512KB covers every known EC image
        # Real EC chips are 128/256/512KB, and a manufacturer embeds the EC
        # firmware as exactly one chip-sized block delimited by erased flash.
        STD_EC_SIZES = (0x20000, 0x40000, 0x80000)

        # Search a little beyond MAX_EC so a genuine 512KB blob is
        # distinguishable from one where the walk simply hit the search limit.
        SEARCH = MAX_EC + 0x10000

        # Probe every strong cluster and accept a region only when the
        # content facts single out exactly ONE (start, size) pair:
        #   (W) the backward walk measured a real boundary below the cluster
        #       (two full 0xFF blocks -- the cluster sits on padding) and the
        #       forward walk observed the end (padding or EOF, not the
        #       search ceiling);
        #   (E) the end is one of the region's real ends: the last
        #       programmed byte, the block-aligned padding boundary, or the
        #       end of that padding -- an image 0xFF-padded out to its chip
        #       capacity ends where the next region's content resumes;
        #   (I) start = end - capacity never falls below the measured start,
        #       so the answer can never stretch across padding the backward
        #       walk already proved is outside the region;
        #   (B) the marker cluster sits inside [start, end);
        #   (C) a real 0xFF run terminates within the same flash block below
        #       start, so the computed start lands on an observed boundary
        #       (a few programmed bytes may sit between padding and the
        #       region -- flash layouts are not always block-aligned).
        # Capacity arithmetic alone is never a justification: if the facts
        # do not single out one pair, refuse rather than guess.
        for _distinct, anchor in scored[:32]:
            blob_start, blob_end = self._blob_bounds(data, anchor, SEARCH)
            if blob_end <= anchor:
                blob_end = anchor + 1
            ends = self._observed_ends(data, blob_end)
            if not ends:
                continue  # walk hit the search ceiling: end not observable
            if not (blob_start > 0 and self._bounded_below(data, blob_start)):
                continue  # cluster not bounded below by observed padding
            hits = set()
            for end in ends:
                for p in STD_EC_SIZES:
                    start = end - p
                    if start < 0 or start < blob_start:
                        continue  # would cross the measured boundary
                    if not (start <= anchor < end):
                        continue  # marker cluster must sit inside the region
                    if not self._sits_on_padding(data, start):
                        continue  # computed start with no boundary under it
                    hits.add((start, p))
            if len(hits) == 1:
                return next(iter(hits))
            # 0 hits: this cluster justifies nothing; >1: the content does
            # not decide between them. Both move on to the next cluster and
            # never pick a favourite.

        # No candidate cluster produced a unique pair of observed
        # boundaries, so the region cannot be delimited from content alone.
        # Marker positions are useless for the size (they report a 256KB
        # chip as 128KB whenever the markers land in the second half), and
        # a wrong region flashed to the EC bricks the machine. Refuse and
        # let the user state the region explicitly.
        return -1, -1

    def find_ec_region_end(self, data: bytes) -> int:
        """Return the block-observed end of the EC blob, or -1 if unknown.

        The end is the most reliable fact available: it is either the end of
        the dump or the erased (0xFF) flash that follows the region. An end
        that merely coincides with the walk's search ceiling is not derivable
        from content and reports -1. (End-anchored resolution uses
        ``_end_anchored_start``, which considers every real end of the
        region, including where an internal FF tail runs out.)
        """
        if not data:
            return -1

        scored = self._scored_anchors(data)
        if not scored:
            return -1

        # Try the strongest clusters first and accept the first end that is an
        # OBSERVED boundary (padding or EOF). An end that merely coincides with
        # the search ceiling is not derivable from content, and end-anchored
        # extraction would slice the wrong bytes from a known-wrong position.
        for _distinct, anchor in scored[:32]:
            # Headroom beyond MAX_EC: a genuine 512KB region whose anchor sits
            # near its start must not look like "the search limit was reached".
            _blob_start, blob_end = self._blob_bounds(data, anchor, 0x90000)
            if blob_end <= anchor:
                blob_end = anchor + 1
            if self._bounded_above(data, blob_end):
                return blob_end
        return -1

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
    def _bounded_below(cls, data: bytes, off: int) -> bool:
        """True when ``off`` sits directly on observed padding (or file start).

        Two full 4KB 0xFF blocks must lie immediately below ``off`` -- the same
        PAD_RUN rule the blob walk uses -- so a lone interior FF run cannot be
        mistaken for a region boundary.
        """
        if off == 0:
            return True  # the start of the file bounds the region itself
        if off < 0x2000:
            return False  # cannot observe the required 8KB of padding
        return cls._is_pad_block(data[off - 0x2000 : off - 0x1000]) and cls._is_pad_block(
            data[off - 0x1000 : off]
        )

    @classmethod
    def _bounded_above(cls, data: bytes, off: int) -> bool:
        """True when ``off`` is EOF or is followed by real padding (PAD_RUN).

        This is what makes a candidate chip capacity *justified*: the region's
        proposed end must be an observed boundary, never a computed one.
        """
        total = len(data)
        if off >= total:
            return off == total  # only exact EOF counts; past EOF is nonsense
        if off < 0:
            return False
        run, p = 0, off
        while run < 2 and p < total:
            if not cls._is_pad_block(data[p : p + 0x1000]):
                return False
            run += 1
            p += 0x1000
        # padding may run out at EOF: one block then end-of-file still delimits
        return run >= 2 or p >= total

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
        # A lone 4KB run of 0xFF occurs inside ordinary firmware, so a single
        # padding block must NOT be treated as a region boundary. Require
        # consecutive padding blocks: real inter-region gaps are far larger
        # than that, so this tolerates stray FF inside the image without
        # walking straight through a genuine boundary.
        PAD_RUN = 2

        # Walk outwards in both directions until PAD_RUN consecutive padding
        # blocks are seen, then report the boundary position -- the offset
        # where padding BEGAN, not where the walk gave up. The padding run
        # itself is not part of the region.
        start = pos
        floor = max(0, pos - max_span)
        run = 0
        boundary = None
        while start > floor:
            prev = start - BLOCK
            if prev < 0:
                break
            if cls._is_pad_block(data[prev : prev + BLOCK]):
                if boundary is None:
                    boundary = start  # last real-content block
                run += 1
                if run >= PAD_RUN:
                    start = boundary
                    break
            else:
                run = 0
                boundary = None
            start = prev

        end = min(total, pos + BLOCK)
        ceiling = min(total, pos + max_span)
        run = 0
        boundary = None
        while end < ceiling:
            if cls._is_pad_block(data[end : end + BLOCK]):
                if boundary is None:
                    boundary = end  # padding starts here
                run += 1
                if run >= PAD_RUN:
                    end = boundary
                    break
            else:
                run = 0
                boundary = None
            end = min(total, end + BLOCK)

        return start, min(end, total)

    @classmethod
    def _observed_ends(cls, data: bytes, blob_end: int) -> tuple[int, ...]:
        """The real end candidates for a blob whose forward walk stopped at ``blob_end``.

        A region ends at its last programmed byte, or at the block-aligned
        padding boundary the walk measured -- and when the image carries an
        internal 0xFF tail padded out to its chip capacity, at the point
        where the NEXT region's content resumes after that tail. A
        ``blob_end`` that is merely the search ceiling is not derivable from
        content and yields no candidates at all.
        """
        total = len(data)
        if blob_end < 0 or blob_end > total:
            return ()
        if blob_end < total and not cls._is_pad_block(data[blob_end : blob_end + 0x1000]):
            return ()  # search ceiling, not a boundary content shows
        content_end = cls._content_end_before(data, blob_end)
        ends = [blob_end, content_end, cls._pad_end_after(data, content_end)]
        # Block-level resume point: where the run of all-FF 4KB blocks stops.
        # Byte-level resume drifts past a region that BEGINS with 0xFF bytes,
        # but a tail padded out to capacity always ends on a block boundary,
        # so this candidate recovers the exact capacity end in that case.
        # (If both survive every check the content did not decide between
        # them, so the caller refuses instead of picking one.)
        BLOCK = 0x1000
        b = (min(content_end, total) + BLOCK - 1) // BLOCK * BLOCK
        if b < total and cls._is_pad_block(data[b : b + BLOCK]):
            while b < total and cls._is_pad_block(data[b : b + BLOCK]):
                b += BLOCK
            ends.append(b)
        return tuple(dict.fromkeys(ends))

    @classmethod
    def _content_end_before(cls, data: bytes, pos: int) -> int:
        """One past the last programmed byte below ``pos`` (0 if all padding)."""
        total = len(data)
        pos = min(pos, total)
        BLOCK = 0x1000
        i = pos
        while i > 0:
            lo = max(0, i - BLOCK)
            chunk = data[lo:i]
            if not cls._is_pad_block(chunk):
                for j in range(len(chunk) - 1, -1, -1):
                    if chunk[j] != 0xFF:
                        return lo + j + 1
            i = lo
        return 0

    @classmethod
    def _pad_end_after(cls, data: bytes, pos: int) -> int:
        """First programmed byte at or after ``pos``, or EOF when padding runs out."""
        total = len(data)
        BLOCK = 0x1000
        i = max(0, min(pos, total))
        while i < total:
            chunk = data[i : i + BLOCK]
            if cls._is_pad_block(chunk):
                i += len(chunk)
                continue
            for j in range(len(chunk)):
                if chunk[j] != 0xFF:
                    return i + j
            i += len(chunk)
        return total

    @classmethod
    def _sits_on_padding(cls, data: bytes, start: int) -> bool:
        """True when a real 0xFF run ENDS within the same flash block below ``start``.

        Capacity-derived starts (``end - size``) are arithmetic; this is the
        content fact that makes one trustworthy. Padding must terminate no
        further than one 4KB block above the proposed start: that tolerates a
        few programmed bytes sitting between the padding and the region (real
        flash layouts are not always block-aligned), but nothing more. A run
        that ends further below means ``start`` lies inside content, not on a
        boundary. The run itself must be at least PAD_RUN (2 blocks) of 0xFF
        so a lone interior FF fragment cannot qualify.
        """
        if start <= 0 or start > len(data):
            return False
        lo = max(1, start - 0x1000)
        window = data[lo : start + 1]
        for i in range(1, len(window)):
            if window[i - 1] == 0xFF and window[i] != 0xFF:
                e = lo + i  # first non-FF byte after the run ends
                if e >= 0x2000 and data[e - 0x2000 : e].count(0xFF) == 0x2000:
                    return True
        return False

    @staticmethod
    def _strip_ff_tail(data: bytes, start: int, end: int) -> int:
        """Trim trailing 0xFF padding down to the last non-FF byte."""
        while end > start + 0x100 and data[end - 1] == 0xFF:
            end -= 1
        return end

    def _strip_ff_run(self, data, start, end):
        # placeholder kept for API compatibility
        return self._strip_ff_tail(data, start, end)

    def _end_anchored_start(self, data: bytes, size: int) -> int:
        """Locate the start of a ``size``-byte region via its observed end(s).

        The chip capacity is hardware truth the user supplies; everything
        else must still come from content: an observed end (padding or EOF),
        a start at ``end - size`` that never falls below the start the
        backward walk measured, and the marker cluster inside the region.
        When the content facts single out exactly one start it is returned;
        otherwise -1 -- a computed start content does not corroborate must
        refuse, not approximate.
        """
        if not data or size <= 0:
            return -1
        scored = self._scored_anchors(data)
        if not scored:
            return -1
        # Headroom beyond MAX_EC: a genuine 512KB region whose anchor sits
        # near its start must not look like "the search limit was reached".
        SEARCH = 0x90000
        for _distinct, anchor in scored[:32]:
            blob_start, blob_end = self._blob_bounds(data, anchor, SEARCH)
            if blob_end <= anchor:
                blob_end = anchor + 1
            ends = self._observed_ends(data, blob_end)
            if not ends:
                continue  # walk hit the search ceiling: end not observable
            hits = set()
            for end in ends:
                start = end - size
                if start < 0 or start < blob_start:
                    continue  # would cross the measured boundary
                if not (start <= anchor < end):
                    continue  # marker cluster must sit inside the region
                hits.add(start)
            if len(hits) == 1:
                return next(iter(hits))
        return -1

    def resolve_region(
        self,
        data: bytes,
        offset: Optional[int] = None,
        size: Optional[int] = None,
    ) -> tuple[int, int, str]:
        """Resolve the EC region to (offset, size, error).

        Three modes:
          * offset AND size given  -> used verbatim.
          * size only              -> END-ANCHORED. The chip capacity is known
            hardware truth; the region is placed where an observed end (the
            last programmed byte, the padding boundary, or the end of an FF
            tail padded to capacity) minus that capacity lands on content
            that corroborates it (measured start, contained marker cluster).
          * neither                 -> auto-detection.
        """
        size = int(size) if size else None
        if offset is not None and offset < 0:
            return -1, -1, "The manual offset must be zero or more."
        if offset is not None and not size:
            return -1, -1, "A manual offset needs a region size as well."

        if offset is not None and offset >= 0 and size:
            offset = int(offset)
            if offset + size > len(data):
                return (
                    -1,
                    -1,
                    (
                        f"Region 0x{offset:X}+0x{size:X} runs past the end of the "
                        f"file (0x{len(data):X} bytes)."
                    ),
                )
            return offset, size, ""

        if size:
            offset = self._end_anchored_start(data, size)
            if offset < 0:
                return (
                    -1,
                    -1,
                    (
                        "Could not locate the end of the EC region. Enter an offset "
                        "manually, or check that this file is a full SPI dump."
                    ),
                )
            return offset, size, ""

        offset, size = self.find_ec_region(data)
        if offset < 0:
            return -1, -1, ""
        return offset, size, ""

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
        offset, size, error = self.resolve_region(data, offset, size)
        if error or offset < 0:
            return ECAnalysis(found=False, message=error)

        ec_data = data[offset : offset + size]
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
                blob = ec_data[max(0, idx - 8) : idx + 16]
                analysis.password_flags.append(
                    {
                        "name": name,
                        "offset_in_ec": idx,
                        "offset_in_image": offset + idx,
                        "context": blob.hex(),
                    }
                )
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

    def list_patches(
        self, vendor: Optional[str] = None, controller: Optional[ECController] = None
    ) -> list[ECPatch]:
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

    def scan_patch_sites(self, input_path: str) -> list[dict]:
        """Advisory scan: which EC patches' signatures are present and where.

        Performs NO writes and produces no output file — the safety pass that
        also shows which patches are verified versus advisory-only before
        anyone considers applying them.
        """
        with open(input_path, "rb") as f:
            data = f.read()
        out = []
        for patch in self._patches:
            try:
                signature = bytes.fromhex(patch.signature_hex)
            except ValueError:
                out.append(
                    {
                        "key": patch.key,
                        "vendor": patch.vendor,
                        "found": False,
                        "note": "invalid hex in pattern",
                        "verified": patch.verified,
                    }
                )
                continue
            offsets = []
            pos = 0
            while True:
                i = data.find(signature, pos)
                if i < 0:
                    break
                offsets.append(i)
                pos = i + 1
            out.append(
                {
                    "key": patch.key,
                    "vendor": patch.vendor,
                    "controller": patch.controller,
                    "generation": patch.generation,
                    "found": bool(offsets),
                    "offsets": [hex(x) for x in offsets],
                    "verified": patch.verified,
                }
            )
        return out

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

        data[offset : offset + len(replacement)] = replacement

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
        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            return ECPatchResult(status=ECStatus.ERROR, message=str(exc))
        with open(input_path, "rb") as f:
            data = f.read()

        offset, size, error = self.resolve_region(data, offset, size)
        if error:
            return ECPatchResult(status=ECStatus.ERROR, message=error)
        if offset < 0:
            return ECPatchResult(
                status=ECStatus.NOT_FOUND,
                message=(
                    "Could not delimit the EC region from the dump alone. Tick "
                    "'Manual region override' and select your chip size (e.g. "
                    "0x40000 for a 256KB IT8218VG) -- leave the offset blank to "
                    "anchor the region at its detected end. No bytes were "
                    "extracted."
                ),
            )

        with open(output_path, "wb") as f:
            f.write(data[offset : offset + size])
        return ECPatchResult(
            status=ECStatus.SUCCESS,
            offset=offset,
            output_path=output_path,
            message=f"EC firmware extracted: offset 0x{offset:X}, {size} bytes ({size // 1024} KB)",
        )

    def _load_patches(self) -> None:
        if not os.path.exists(self.patches_path):
            self.load_error = f"EC patch registry not found: {self.patches_path}"
            return
        try:
            with open(self.patches_path, "r") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for item in raw if isinstance(raw, list) else raw.get("patches", []):
            self._patches.append(
                ECPatch(
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
                )
            )

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
