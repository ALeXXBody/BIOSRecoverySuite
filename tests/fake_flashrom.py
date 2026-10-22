#!/usr/bin/env python3
"""Test double for flashrom. Emulates a CH341A + a 16MB chip backed by a file.

This is used by the test suite to exercise SPIFlasher deterministically without
real hardware. It is NOT a real flashrom and should never be used for flashing.
"""

import os
import sys

IMAGE_ENV = "FAKE_FLASH_IMAGE"  # path to the "chip" image file
SIZE = 16 * 1024 * 1024


def main(argv):
    image = os.environ.get(IMAGE_ENV)
    if image:
        try:
            with open(image, "rb") as f:
                chip = bytearray(f.read())
            chip += bytearray(SIZE - len(chip))
        except OSError:
            chip = bytearray(0xFF for _ in range(SIZE))
    else:
        chip = bytearray(0xFF for _ in range(SIZE))

    program = argv[1] if len(argv) > 1 else ""
    target = None
    if program == "-p":
        target = argv[2]
        rest = argv[3:]
    else:
        rest = argv[2:]

    def dump(prefix=""):
        print("flashrom v1.4 -- fake test double (do NOT flash with this!)")
        if target:
            print(f"Using clock_getres success result for programmer: {target}")

    all_args = " ".join(argv)

    if "--list-supported" in all_args and "programmer" in all_args:
        print(
            "Programmers:\n  ch341a_spi      ...  \n  ft2232_spi      ...  \n"
            "  linux_spi       ...  \n  buspirate_spi   ..."
        )
        return 0

    if "--flashtest" in rest or "--list-supported" in rest or "--flash-name" in rest:
        if "--list-supported" in rest and "programmer" in rest:
            print(
                "Programmers:\n  ch341a_spi ...  \n  ft2232_spi ...  \n"
                "  linux_spi ...  \n  buspirate_spi ..."
            )
        else:
            dump()
            print(
                "Detected flash chip 'W25Q128JV @ 16 MB capacity: 32768 kB' "
                "+-----------------------------------------------------------------------------+"
            )
            print("Flashing is disabled on this fake binary.\n")
        return 0

    if "-r" in rest:
        idx = rest.index("-r")
        out = rest[idx + 1]
        dump()
        print("Reading flash... done.")
        with open(out, "wb") as f:
            f.write(bytes(chip))
        return 0

    if "-w" in rest:
        idx = rest.index("-w")
        img = rest[idx + 1]
        dump()
        with open(img, "rb") as f:
            data = f.read()
        for i in range(len(data)):
            chip[i] = data[i]
        if image:
            with open(image, "wb") as f:
                f.write(bytes(chip))
        print("Erasing and writing flash chip... done.")
        if "-v" in rest:
            print("Verifying flash... VERIFIED.")
        return 0

    if "-E" in rest:
        for i in range(SIZE):
            chip[i] = 0xFF
        if image:
            with open(image, "wb") as f:
                f.write(bytes(chip))
        print("Erasing flash chip... done.")
        return 0

    dump()
    print("Unknown fake-flashrom invocation: " + " ".join(argv))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
