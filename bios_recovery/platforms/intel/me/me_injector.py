"""Intel ME/TXE region injector - repairs corrupted ME regions.

The IndiaFix "ME/TXE Injector" workflow: when a dump's ME region is corrupt
(fan spin, no display, boot loops, missing CSME), you overwrite the region
with a CLEAN ME firmware image of the same version instead of just disabling.

This engine:
  * locates the ME region in the target image (flash descriptor FLREG bounds,
    falling back to $FPT-based detection),
  * verifies the clean image contains ME firmware (FPT/FTPR markers),
  * checks sizes (clean image may be smaller - remainder is padded with 0xFF),
  * rewrites the region in place, leaving the descriptor untouched.
"""

import os
import struct
import tempfile
from typing import Optional

from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.core.me_manifest import engine_version as detect_me_version_in_blob
from bios_recovery.core.rebuild_verify import verify_rebuild
from bios_recovery.core.safety import SameFileError, ensure_distinct
from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner


class MEInjector:
    """Replaces the ME region of a BIOS image with a clean firmware image."""

    def analyze(self, image_path: str) -> dict:
        if not os.path.isfile(image_path):
            return {"found": False, "offset": None, "size": 0, "version": "", "error": "not a file"}
        with open(image_path, "rb") as f:
            data = f.read()
        result = BiosAnalyzer().analyze(image_path)
        me = next((r for r in result.regions if r.region_type.name == "INTEL_ME"), None)
        blob_version = detect_me_version_in_blob(data)
        return {
            "found": me is not None,
            "offset": me.offset if me else None,
            "size": me.size if me else 0,
            "version": result.me_version or blob_version,
        }

    @staticmethod
    def _fpt_layout(region: bytes) -> Optional[list[tuple[bytes, int, int]]]:
        """The FPT partition rows of an ME region image, or None when absent.

        Rows are (name, offset, size); entries with no data (zero offsets/sizes)
        are skipped. Two regions with the same engine layout produce the exact
        same list — the precondition used before replacing a target's ME.
        """
        n = 0
        pos = region.find(b"$FPT")
        if pos < 0:
            return None
        n = int.from_bytes(region[pos + 4 : pos + 8], "little")
        if not 1 <= n <= 64 or pos + 0x20 + n * 0x20 > len(region):
            return None
        out = []
        for i in range(n):
            e = region[pos + 0x20 + i * 0x20 : pos + 0x20 + (i + 1) * 0x20]
            base, size = struct.unpack_from("<II", e, 8)
            if base in (0, 0xFFFFFFFF) or size in (0, 0xFFFFFFFF):
                continue
            out.append((e[:4], base, size))
        return out

    @staticmethod
    def _layout_diff_names(
        target: list[tuple[bytes, int, int]], clean: list[tuple[bytes, int, int]]
    ) -> str:
        """Short, human reasons for why two FPT layouts differ (names first)."""
        t_names = [e[0].rstrip(b"\x00").decode("latin-1") or "----" for e in target]
        c_names = [e[0].rstrip(b"\x00").decode("latin-1") or "----" for e in clean]
        if t_names != c_names:
            return (
                f"target partitions {','.join(t_names[:6])} vs clean image "
                f"{','.join(c_names[:6])}"
            )
        for (tn, t_off, t_size), (cn, c_off, c_size) in zip(target, clean):
            if (t_off, t_size) != (c_off, c_size):
                name = tn.rstrip(b"\x00").decode("latin-1") or "----"
                return f"partition {name} offsets/sizes differ"
        return ""

    def inject(self, image_path: str, clean_me_path: str, output_path: str) -> dict:
        try:
            ensure_distinct(image_path, output_path)
        except SameFileError as exc:
            return {"success": False, "message": str(exc)}
        for path in (image_path, clean_me_path):
            if not os.path.isfile(path):
                return {"success": False, "message": f"not a file: {path}"}

        with open(image_path, "rb") as f:
            original = f.read()
        image = bytearray(original)
        with open(clean_me_path, "rb") as f:
            clean = f.read()

        if not clean:
            return {"success": False, "message": "clean ME image is empty; nothing written"}

        result = BiosAnalyzer().analyze(image_path)
        me = next((r for r in result.regions if r.region_type.name == "INTEL_ME"), None)
        if me is None:
            return {
                "success": False,
                "message": "target image has no Intel ME region (no flash descriptor?)",
            }

        # Only a region the flash descriptor declares may be overwritten. A region found by
        # a fallback scan is not a boundary we can prove, so it is refused.
        cleaner = IntelMECleaner()
        fd = cleaner._find_fd_in_data(image)
        declared = cleaner._me_region_from_flreg(image, fd) if fd >= 0 else None
        if declared is None or (declared[0], declared[1]) != (me.offset, me.offset + me.size):
            return {
                "success": False,
                "message": "the ME region is not declared by the flash descriptor; "
                "refusing to overwrite a guessed range",
            }

        clean_version = detect_me_version_in_blob(clean)
        if not clean_version and not detect_me_version_in_blob(clean[:0x1000]):
            # not fatal, but warn loudly - injecting garbage bricks recovery paths
            warn = "clean image does not look like ME firmware (no $MN2 marker)"
        else:
            warn = None

        # Layout precondition: the clean blob must carry the SAME engine partition
        # layout as the target's ME region (identical FPT rows — names, order,
        # offsets, sizes). A blob from a different engine generation (e.g. an CSME
        # 16 LT update image with an FPT that lists FTPR, over a CSME 15 LT target
        # whose FPT does not) produces a dead engine and bricks recovery paths, so
        # it is refused instead of blindly spliced. The supported route for a wrong
        # layout is the Intel Flash Image Tool round-trip (licence-protected: not
        # bundled, the app only says which FIT is needed).
        target_layout = self._fpt_layout(image[me.offset : me.offset + me.size])
        clean_layout = self._fpt_layout(clean)
        if target_layout is not None and clean_layout is not None and target_layout != clean_layout:
            from bios_recovery.platforms.intel.me.fit_check import check_image

            fit_hint = ""
            try:
                fit = check_image(image_path)
                if fit.needed_tool and fit.confidence:
                    fit_hint = (
                        f" The supported route for a wrong layout is the Intel Flash "
                        f"Image Tool round-trip ({fit.needed_tool}); your library's "
                        "matching tool is listed under 'Tools for this image'."
                    )
            except Exception:
                fit_hint = (
                    " The supported route for a wrong layout is the Intel Flash "
                    "Image Tool round-trip."
                )
            diff_names = self._layout_diff_names(target_layout, clean_layout)
            bad_part = diff_names if diff_names else "the partition table rows differ"
            return {
                "success": False,
                "message": f"clean image has a different engine layout ({bad_part}); "
                "nothing written" + fit_hint,
            }

        region = image[me.offset : me.offset + me.size]
        cur_version = result.me_version or detect_me_version_in_blob(region)

        if len(clean) > me.size:
            return {
                "success": False,
                "message": f"clean ME image ({len(clean)} bytes) is larger than the "
                f"ME region ({me.size} bytes) - wrong file or wrong machine",
            }

        new_region = bytearray(b"\xff" * me.size)
        new_region[: len(clean)] = clean
        image[me.offset : me.offset + me.size] = new_region

        if bytes(image) == original:
            return {
                "success": True,
                "message": f"ME region at 0x{me.offset:X} already matches the clean image; "
                "nothing written",
                "output_path": "",
                "old_version": cur_version,
                "new_version": clean_version,
            }

        # Write to a temporary file beside the output, check that only ME bytes changed, and
        # move it into place only if the check accepts it. A failed check leaves no output.
        out_dir = os.path.dirname(os.path.abspath(output_path))
        fd_tmp, tmp_path = tempfile.mkstemp(prefix=".inject_", suffix=".tmp", dir=out_dir)
        try:
            with os.fdopen(fd_tmp, "wb") as f:
                f.write(bytes(image))
            check = verify_rebuild(image_path, tmp_path, allow=("me",))
            if not check.accepted:
                os.remove(tmp_path)
                return {
                    "success": False,
                    "message": "the rebuilt image changed bytes outside the ME region; nothing "
                    "written: " + "; ".join(check.reasons or ["refused by the region check"]),
                }
            os.replace(tmp_path, output_path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        msg = f"ME region at 0x{me.offset:X} ({me.size} bytes) replaced with clean image" + (
            f" (v{clean_version})" if clean_version else ""
        )
        if cur_version and clean_version and cur_version != clean_version:
            msg += f" - NOTE: old dump was v{cur_version}; version differs, verify this is intended"
        if warn:
            msg += f" - WARNING: {warn}"
        return {
            "success": True,
            "message": msg,
            "output_path": output_path,
            "old_version": cur_version,
            "new_version": clean_version,
        }
