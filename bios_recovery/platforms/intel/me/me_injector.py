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


from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.core.me_manifest import detect_me_version_best as detect_me_version_in_blob


class MEInjector:
    """Replaces the ME region of a BIOS image with a clean firmware image."""

    def analyze(self, image_path: str) -> dict:
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

    def inject(self, image_path: str, clean_me_path: str, output_path: str) -> dict:
        with open(image_path, "rb") as f:
            image = bytearray(f.read())
        with open(clean_me_path, "rb") as f:
            clean = f.read()

        result = BiosAnalyzer().analyze(image_path)
        me = next((r for r in result.regions if r.region_type.name == "INTEL_ME"), None)
        if me is None:
            return {"success": False,
                    "message": "target image has no Intel ME region (no flash descriptor?)"}

        clean_version = detect_me_version_in_blob(clean)
        if not clean_version and not detect_me_version_in_blob(clean[:0x1000]):
            # not fatal, but warn loudly - injecting garbage bricks recovery paths
            warn = "clean image does not look like ME firmware (no $MN2 marker)"
        else:
            warn = None

        region = image[me.offset:me.offset + me.size]
        cur_version = result.me_version or detect_me_version_in_blob(region)

        if len(clean) > me.size:
            return {"success": False,
                    "message": f"clean ME image ({len(clean)} bytes) is larger than the "
                               f"ME region ({me.size} bytes) - wrong file or wrong machine"}

        new_region = bytearray(b"\xFF" * me.size)
        new_region[:len(clean)] = clean
        image[me.offset:me.offset + me.size] = new_region

        with open(output_path, "wb") as f:
            f.write(bytes(image))
        msg = (f"ME region at 0x{me.offset:X} ({me.size} bytes) replaced with clean image"
               + (f" (v{clean_version})" if clean_version else ""))
        if cur_version and clean_version and cur_version != clean_version:
            msg += f" - NOTE: old dump was v{cur_version}; version differs, verify this is intended"
        if warn:
            msg += f" - WARNING: {warn}"
        return {"success": True, "message": msg, "output_path": output_path,
                "old_version": cur_version, "new_version": clean_version}
