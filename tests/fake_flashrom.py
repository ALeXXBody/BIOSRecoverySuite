#!/usr/bin/env python3
"""Test double for flashrom. Emulates a CH341A + a 16MB chip backed by a file.

This is used by the test suite to exercise SPIFlasher deterministically without
hardware. It is NOT a real flashrom and should never be used for flashing.

Output strings and option rules follow flashrom's sources (flashrom.c probe line,
cli_classic.c --flash-name, single-operation check and the leftover-parameter check).
"""

import os
import sys

IMAGE_ENV = "FAKE_FLASH_IMAGE"  # path to the "chip" image file
SIZE = 16 * 1024 * 1024
OPERATIONS = ("-r", "-w", "-v", "-E")
PROGRAMMERS = ["ch341a_spi", "ft2232_spi", "linux_spi", "buspirate_spi"]


def main(argv):
    args = argv[1:]
    if args[:1] == ["--list-supported"]:
        if len(args) > 1:
            print("Error: Extra parameter found.", file=sys.stderr)
            return 1
        print("Supported programmers:")
        for name in PROGRAMMERS:
            print(f"\t{name}")
        return 0

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

    target = args[args.index("-p") + 1] if "-p" in args else None

    def probe_line():
        print(
            f'Found Winbond flash chip "W25Q128JV" (16384 kB, SPI) on {target}.',
            file=sys.stderr,
        )

    if "--flash-name" in args:
        probe_line()
        print('vendor="Winbond" name="W25Q128JV"')
        return 0

    ops = [a for a in args if a in OPERATIONS]
    if len(ops) > 1:
        print("More than one operation specified. Aborting.", file=sys.stderr)
        return 1

    if "-r" in args:
        out = args[args.index("-r") + 1]
        probe_line()
        with open(out, "wb") as f:
            f.write(bytes(chip))
        print("Reading flash... done.", file=sys.stderr)
        return 0

    if "-w" in args:
        img = args[args.index("-w") + 1]
        probe_line()
        with open(img, "rb") as f:
            data = f.read()
        for i in range(len(data)):
            chip[i] = data[i]
        if image:
            with open(image, "wb") as f:
                f.write(bytes(chip))
        print("Erasing and writing flash chip... done.", file=sys.stderr)
        if "-n" not in args:
            print("Verifying flash... VERIFIED.", file=sys.stderr)
        return 0

    if "-E" in args:
        probe_line()
        for i in range(SIZE):
            chip[i] = 0xFF
        if image:
            with open(image, "wb") as f:
                f.write(bytes(chip))
        print("Erasing flash chip... done.", file=sys.stderr)
        return 0

    print("Unknown fake-flashrom invocation: " + " ".join(argv), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
