"""EC firmware version detection.

ThinkPad-class EC firmware (and many other OEM ECs) carry a human-readable
version token like ``N2IHT39W`` (T14 Gen 2 Intel) or ``R16ET35W`` (R-branch
builds) hard-coded inside the ROM. Reading that token is what lets a repair
workflow detect an *EC firmware generation mismatch* — exactly the failure
mode where a donor chip pair still doesn't boot until the EC update capsule
re-baselines the EC against the platform.

The detection is deliberately conservative:

* the token is searched inside the located EC region (never the whole SPI
  image), because the same token pattern can appear in unrelated blobs
  elsewhere;
* possible hits are *reported*, never believed uniquely: the chosen offset and
  every other plausible candidate are shown, so the operator can verify
  visually;
* an empty result is stated as "not found", not guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ECFirmwareVersion:
    """Version tokens found inside an EC firmware region."""

    version: str
    offset: int  # offset *inside the EC region*
    candidates: list[tuple[int, str]] = field(default_factory=list)
    note: str = ""


# ThinkPad EC firmware tokens: [A-Z][0-9]{1,2}[A-Z]{1,3}[0-9]{2}[A-Z].
# Real examples: N2IHT39W (branch IHT, rev 39), R16ET35W (R16 + ET + 35),
# N2RET26W, N2IET38W. Lookbehind/lookahead keep a token glued inside a longer
# alphanumeric run from double-hitting.
EC_VERSION_RE = re.compile(
    rb"(?<![A-Z0-9])[A-Z][0-9]{1,2}[A-Z]{1,3}[0-9]{2}[A-Z](?![A-Z0-9])"
)


def scan_ec_firmware_version(ec_data: bytes) -> ECFirmwareVersion:
    """Return the scoring version token inside an EC region (never ``None``).

    Highest scoring = rightmost occurrence wins (EC update capsules append),
    with the whole hit list kept for the operator to inspect. An empty result
    is stated as "not found" with a note — never guessed.
    """
    if len(ec_data) < 8:
        return ECFirmwareVersion(
            version="",
            offset=-1,
            candidates=[],
            note="EC region too small to scan for a version token.",
        )
    candidates: list[tuple[int, str]] = []
    for m in EC_VERSION_RE.finditer(ec_data):
        candidates.append((m.start(), m.group().decode("ascii")))
    if not candidates:
        return ECFirmwareVersion(
            version="",
            offset=-1,
            candidates=[],
            note=(
                "No ThinkPad-EC-style version token (pattern [A-Z][0-9][A-Z]{1,2}"
                "[0-9]{2}[A-Z]) found in the EC region. The dump may be padded, "
                "clipped, or from a non-ThinkPad controller — verify manually "
                "before relying on any version comparison."
            ),
        )
    # Tokens deeper into the image are the freshest writes (updates append):
    offset, version = candidates[-1]
    others = [f"{v} @ 0x{o:X}" for o, v in candidates[:-1]]
    if others:
        note = "Also inside this region: " + "; ".join(others[:6])
        return ECFirmwareVersion(version=version, offset=offset, candidates=candidates, note=note)
    return ECFirmwareVersion(version=version, offset=offset, candidates=candidates)
