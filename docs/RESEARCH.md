# BIOS Repair Knowledge Base

Research summary for the BIOS Recovery Suite project.

## LBE Analysis

LBE (Laptop Bios Extractor) by EgyFixLab is the inspiration for this tool. Its key features:

- BIOS extraction from EXE, FD, BIN, WPH, ROM formats
- Main BIOS / EC BIOS splitting
- Security clearing from BIOS dumps
- Supervisor password generation
- Auto ME clearing
- Region injection (ME, BIOS)

### LBE Feature Tiers
- **Basic**: Extraction, repair, EC extractor, Dell/HP/Sony/Samsung tools, ME support, password generators
- **Advanced**: Universal extractor, HP security unlock, chipsets
- **Expert**: All + password decryption, NVram cleaner, Chromebook enrollment removal
- **Pro**: All + Lenovo patching, Dell 8FC8 unlock, HP 9th-10th gen removal

## Intel ME Cleaning Research

### me_cleaner (corna/me_cleaner)
- Python tool to deblob Intel ME/TXE firmware
- Removes most code from ME, sets HAP/MeAltDisable bit
- Supports ME versions 1.x - Coffee Lake, TXE on Braswell/Cherry Trail
- Key mechanisms: FPT parsing, partition removal, FTPR module stripping

### HAP Bit Locations (updated for modern platforms)
| ME Version | Platform | Location |
|---|---|---|
| ME 12 LP | 8th/9th gen | PCHSTRP28 `fpsba+0x70` bit 16 |
| ME 12 H | Cannon Lake H | PCHSTRP32 `fpsba+0x80` bit 16 |
| ME 13 | Ice Lake LP | PCHSTRP28 `fpsba+0x70` bit 16 |
| ME 14 | Comet Lake | PCHSTRP28/32 |
| ME 15 | Tiger Lake | PCHSTRP31/37 |
| ME 16 | Alder Lake | PCHSTRP31 (mobile) / PCHSTRP55 (desktop) |
| ME 18 | Meteor Lake | Unknown - no discrete PCH |

## BIOS Password Removal

### Methods by Manufacturer
- **AMI**: Clear `AMITSESetup` NVRAM variable, or set delete bit (0x3F->0x3D)
- **Insyde**: Clear password variables in GUID namespaces
- **Dell**: Master password generation from Service Tag (8FC8, BF97, CF1B, 595B, D35B suffixes)
- **HP**: Master password via code; clear NVRAM variables
- **Lenovo**: Delete `cE!` variable from GUID namespace
- **Toshiba**: EEPROM reset (24C04)
- **Sony**: EEPROM handling

### Master Password Algorithms
- Dell: Service tag encoded + suffix
- HP: Code-based generation
- Insyde: 8 digit code
- Phoenix: 5 digit code
- CmosPwd: Supports AMI, Award, Phoenix, Compaq, IBM, Dell, Fujitsu-Siemens, HP, Insyde H20, Sony, Samsung

## BIOS Structure Research

### Intel Flash Descriptor
- Located at offset 0 (or 0x10 for new format)
- Signature: `0x0FF0A55A` (little-endian: `5A A5 F0 0F`)
- Contains region layout (FLREG), component section, master access (FLMSTR)

### Firmware Volumes / FFS
- Signature: `_FVH`
- Contains firmware files with GUIDs
- UEFITool / UEFIExtract parse these

### DMI / SMBIOS
- `_SM_` entry point (SMBIOS 2.x)
- `_DMI_` table
- SMBIOS 3.0+ uses `_SM3_`
- Structure types: 0 (BIOS), 1 (System), 2 (Baseboard), 3 (Chassis), 4 (Processor), 17 (Memory)

### Vendor Update Formats
- **Dell**: PFS (Packaged Firmware Suite)
- **HP**: HPSF / Insyde iFlash
- **Lenovo**: FL1, EXE updates
- **Toshiba**: Encrypted COM files
- **AMI**: UCP / AFU
- **Phoenix**: TDK Packer

## Open Source Tools

- `me_cleaner` (GPL-3) - Intel ME deblobbing
- `UEFITool` / `UEFIExtract` - UEFI firmware parsing
- `ifdtool` (coreboot) - Intel flash descriptor management
- `BIOSUtilities` - Python collection for vendor format extraction
- `uefi-firmware-parser` - Python UEFI firmware parsing
- `CmosPwd` - Legacy BIOS password decryption
- `pwgen-for-bios` - Master password generators
- `spi_flash_auto_unlocker` - Automated password removal from dumps

## SPI Programmer Integration (flashrom)

- **Programmers**: `ch341a_spi` (low-cost CH341A clip), `ft2232_spi` (FTDI), `linux_spi`
  (SoC SPI), `buspirate_spi`, `dediprog`, `realtek_mst_i2c_spi`.
- flashrom surfaced as a subprocess; the engine auto-discovers the binary on PATH plus
  common Windows/Linux install locations (`C:\Program Files\flashrom\flashrom.exe`,
  `/usr/sbin/flashrom`).
- Invocation contract used by `spi_flasher.py`:
  - List supported programmers: `flashrom --list-supported programmer`
  - Identify chip: `flashrom -p <prog> --flash-name`
  - Read: `flashrom -p <prog> -r <file>`
  - Write: `flashrom -p <prog> -w <file> [-v]`
  - Erase: `flashrom -p <prog> -E`
- Progress is parsed from `==> NN%` markers in flashrom's stderr.
- **Safety model**: writes and erases are gated behind explicit UI consent; a full read
  backup is taken before any write; `verify` after write is on by default.

## EC Firmware Patching (Embedded Controller)

- **Role**: On most laptops the EC owns the KBC and enforces the setup-password state,
  so modern password holds (Lenovo/HP gen 2-3) persist in `EC` flash, not just NVRAM.
- **Common EC silicon**:
  | Vendor | Typical chips | Disambiguation strings |
  |---|---|---|
  | ITE | IT8518, IT8531, IT8528, IT8587 | `ITE`, `IT85`, `IT87`, `8528` |
  | Nuvoton | NPCE793, NPCE795, NPCX  | `NPCE`, `NPCX`, `Nuvoton` |
  | Microchip | MEC1322, MEC1501 | `MEC1`, `MICROCHIP` |
  | ENE | KB9012, KB9022 | `ENE`, `KB90` |
- **Layout**: 2-chip design images the EC ROM in the top of the SPI dump (often the last
  256-512KB); standalone EC flashes are exactly 1 chip. The engine scans from the first
  controller signature and trims trailing `FF` padding.
- **Password markers scanned**: `PasswordStatus`, `UnLock`, `UNLock`,
  UTF-16LE "Pass", `SecurityFeatures`, `secFPass`, `PayloadLock`, `HashPass`,
  `PassHash`, `KBC_PW`.
- **Checksums**: many older ITE/Nuvoton EC images store an 8-bit XOR checksum in the
  final byte; the engine reports validity and can recompute it.
- **Patch policy**: byte patches live in `bios_recovery/patches/ec_patches.json` and are
  loaded at runtime, so community-verified signatures can be contributed without code
  changes. Every entry has a `verified` flag; the engine refuses to apply unverified
  patches unless the operator explicitly confirms. No hardcoded unverified byte patches
  ship in code.

## Lenovo Unlocking (ThinkPad)

### The three generations of methods
1. **cE! runtime backdoor (up to ~2019/2020 BIOSes)** — `H2OFormBrowserDxe` checks for an
   NVRAM variable named `cE!` (GUID `6ACCE65D-DA35-4B39-B64B-5ED927A7DC7E`); if present,
   every setup form is shown. Runtime tool: LenovoH2O-Unlocker. Later BIOSes removed the
   check, so the app only *detects* applicability.
2. **UEFIPatch pattern patches (xx30-xx80 ThinkPads)** — byte patterns inside DXE drivers
   (`LenovoWmaPolicyDxe` for whitelist, `SystemFormBrowserCoreDxe` for the hidden Advanced
   menu). Applied offline to a dump, then flashed back. Sources: digmorepaka/
   thinkpad-firmware-patches, Aldair402/thinkpad-t460s-biosmod. Our engine is
   UEFIPatch-format compatible and handles LZMA-compressed sections natively.
3. **badcaps autopatch (SVP removal, up to 8th gen)** — replaces the password-check DXE
   driver with a patched one and cleans NVRAM state. Booting the patched image turns the
   supervisor password prompt into a one-time bypass (enter any character, confirm
   hardware ID, press space twice), then the original image is flashed back. The driver
   binaries are community-distributed (badcaps thread); our app supports the replacement
   step via `dxe_replacements.json` + auto-derivation by diffing original vs. patched dumps.

### Tamper protection (LNVBBSEC)
xx40+ ThinkPads verify FV signatures; after modifying a signed FV the marker
`4C 4E 56 42 42 53 45 43 FB` (`LNVBBSEC`+FB) must be flipped to `...FF`, else the
machine beeps (e.g. 010225 error codes) on boot. Shipped as the `xx40_plus_tamper_fix` group.

### Signature/csum facts used by the engine
- FFS header checksum: sum of header bytes (IntegrityCheck + State zeroed) ≡ 0 mod 256
- FFS file checksum: only when `FFS_ATTRIB_CHECKSUM` (0x40), else byte = 0xAA
- FFS data alignment: `2^((attrs & 0x38) >> 3)`, minimum 8; pad files (type 0xF0) fill gaps
- LZMA GUID-defined section: GUID `EE4E5898-...`, DataOffset 0x18, payload = LZMA-alone
  (5 props + 8 size) — Python `lzma.FORMAT_ALONE` compatible
- FV header checksum: 16-bit sum over the 0x48-byte header ≡ 0 mod 0x10000
