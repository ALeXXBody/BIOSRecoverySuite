"""Platform/manufacturer classification ("traits") — the app's routing key.

A classification answers three questions about a loaded image:
  * architecture:  intel | amd | apple_intel | apple_t2 | unknown
  * vendor:        asus | dell | apple | hp | lenovo | acer | samsung |
                   toshiba | sony | generic
  * family strings: CSME version / PSP gen / EC controller model / bundle kind

Every tool's applicability is decided from these traits (the UI matrix and the
CLI share the same decision table), so a tool never runs on a platform it does
not belong to.
"""

from __future__ import annotations

from dataclasses import dataclass, field


ARCH_INTEL = "intel"
ARCH_AMD = "amd"
ARCH_APPLE_INTEL = "apple_intel"
ARCH_APPLE_T2 = "apple_t2"
ARCH_UNKNOWN = "unknown"

_INTEL_MARKERS = (
    b"\x5a\xa5\xf0\x0f",          # FLA signature (descriptor mode)
    b"$MN2",                       # CSME manifests
    b"$CPD",                       # CPD structures
    b"$FPT",                       # legacy FPT region
    b"Intel(R) Management Engine",
)
_AMD_MARKERS = (
    b"$PSP",                       # PSP directories
    b"$BHD",                       # bootstrap directory
    b"AGESA",
)
_APPLE_INTEL_MARKERS = (
    b"Fsys\x01",                   # SMC NVRAM Fsys store
    b"BIOS ID: ",                  # AppleRomInformation
    b"Model: MacBook",
)
_APPLE_T2_MARKERS = (
    b"iBoot",                      # T2 SMC ROM boot stage
    b"T2SOC",
)

_VENDOR_MARKERS = {
    "asus": (b"ASUSTeK", b"ASUS Notebook", b"90NB", b"ASUS"),
    "dell": (
        b"Dell Inc.", b"Dell System", b"DELL", b"$UPT", b"$SLA", b"DVAR",
    ),
    "apple": (b"Apple Computer, Inc.", b"Apple Inc.", b"AppleRomInfo",
              b"Fsys\x01"),
    "hp": (b"Hewlett-Packard", b"HPE", b"HP Inc.", b"Insyde", b"H2OFFT"),
    "lenovo": (b"LENOVO", b"Lenovo", b"ThinkPad", b"$MAN$"),
    "acer": (b"Acer Aspire", b"Acer", b"TravMate", b"ZFOREST"),
    "samsung": (b"SAMSUNG", b"Samsung", b"Samsung Electronics"),
    "toshiba": (b"Toshiba", b"TOSHIBA"),
    "sony": (b"Sony", b"SONY", b"VAIO"),
}


@dataclass
class Traits:
    architecture: str = ARCH_UNKNOWN
    vendor: str = "generic"
    evidence: dict = field(default_factory=dict)
    me_family: str = ""      # e.g. "CSME 15", "CSME 16", "Core Ultra"
    me_version: str = ""
    psp_generation: str = ""
    ec_controller: str = ""  # "IT51368 VG (BGA128)" / "NPCE…"
    bundle_kind: str = ""    # "aptio_capsule" / "dell_pfs" / "apple_efirom" / ""


def _hits(data: bytes, markers) -> list[bytes]:
    return [m for m in markers if m in data]


def classify(data: bytes) -> Traits:
    """Classify an image's architecture + vendor by evidenced markers."""
    t = Traits()
    intel_hits = _hits(data, _INTEL_MARKERS)
    amd_hits = _hits(data, _AMD_MARKERS)
    apple_intel = _hits(data, _APPLE_INTEL_MARKERS)
    apple_t2 = _hits(data, _APPLE_T2_MARKERS)

    if apple_t2:
        t.architecture = ARCH_APPLE_T2
        t.vendor = "apple"
        t.bundle_kind = "apple_socrom"
    elif apple_intel or (not intel_hits and any(
            i in (b"Fsys\x01", b"BIOS ID: ", b"Model: MacBook") for i in apple_intel)):
        # Fsys presence decides over a bare-IFD Intel Mac
        t.architecture = ARCH_APPLE_INTEL
        t.vendor = "apple"
        t.bundle_kind = "apple_efirom"
    elif intel_hits:
        t.architecture = ARCH_INTEL
    elif amd_hits:
        t.architecture = ARCH_AMD
    else:
        t.architecture = ARCH_UNKNOWN

    if t.vendor == "generic" or t.vendor == "apple" and apple_t2:
        # vendor detection from brand markers (evidence-based; generic if none) —
        # the whole image is scanned: ASUS/HP-class identity data (MFG0 blocks,
        # "ASUS Notebook" NV strings) lives deep in the NV stores, not at page 0.
        scored = []
        for vendor, marks in _VENDOR_MARKERS.items():
            hits = _hits(data, marks)
            if hits:
                scored.append((len(hits), vendor, hits))
        scored.sort(key=lambda x: -x[0])
        if scored:
            t.vendor = scored[0][1]
            t.evidence = {v: [h.decode('ascii', 'replace') for h in hs[:6]] for ln, v, hs in scored[:3]}
        elif t.architecture == ARCH_APPLE_INTEL:
            t.vendor = "apple"

    # ME family details for Intel
    if t.architecture in (ARCH_INTEL, ARCH_APPLE_INTEL):
        try:
            from bios_recovery.engines.me_cleaner import IntelMECleaner
            info = IntelMECleaner()._get_me_version(data, 0, len(data)) if False else None
        except Exception:
            info = ""
        # light-weight manifest probe (no heavy per-region detection here)
        fam = ""
        try:
            from bios_recovery.utils.me_manifest import iter_manifest_versions
            mvs = iter_manifest_versions(data)
            if mvs:
                maj = mvs[0][0].split(".")[0]
                major = int(maj or 0)
                fam = f"CSME {major}" if major > 11 else ("ME" if major >= 6 else "ME/TXE")
                t.me_version = mvs[0][0]
        except Exception:
            fam = ""
        t.me_family = fam

    return t
