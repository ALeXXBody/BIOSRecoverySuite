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
3. **badcaps autopatch (SVP removal, up to 8th gen)** — replaces two DXE drivers with
   patched ones (`E0746C42-D3F9-4F8B-B211-1410957B9FF5` "BootOption" and
   `826BCF56-BAC4-43F4-8EA1-8CDF0A121ABD` "LenovoTranslateService") and optionally cleans
   the NVRAM store FV (EFI_SYSTEM_NV_DATA_FV_GUID `FFF12B8D-7696-4C8B-A985-2747075B4F50`,
   replaced in place only when size AND header checksum match). Booting the patched image
   turns the supervisor password prompt into a ONE-TIME BYPASS: enter any character,
   confirm hardware ID, press space twice, power off, then flash the original image back
   and reset settings to factory default.
   **Shipped binaries**: `bios_recovery/patches/dxe/*.ffs` + `NVRAM_EfiSystemNvDataFvGuid.vol`
   from the badcaps autopatcher v0.2 distribution (credits: Knucklegrumble and the
   badcaps thread 65996 contributors; DXE patch by the original thread authors). They are
   community repair artifacts distributed as-is, NOT verified by us — apply at your own
   risk. `dxe_replacements.json` also supports auto-derivation by diffing an original vs
   autopatched dump pair.

### Where the supervisor password actually lives per generation
`diagnose_svp_storage` classifies the target and says which of the methods above
applies instead of silently reporting "nothing found":

- **in_dump_backdoor / in_dump_autopatch**: cE! marker or autopatch target GUIDs
  present -> an in-dump patch can work.
- **ec_eeprom**: on 8th-gen-and-newer ThinkPads (T490/X1 C7+/X13 Gen 4 class) the
  supervisor and power-on password hashes live in the **embedded controller
  EEPROM**, not in the SPI BIOS dump. Verified on a Lenovo X13 Gen 4 64 MB dump:
  every NVRAM store (three EVSA bank copies plus the SecureBoot default store)
  enumerates to ~173 variables (`Setup` 3162 B, `LenovoConfig`, `LBC`,
  `LenovoSecurityConfig`, `PwdUnlockErr`, `UnlockID`/`UnlockIDCopy`, boot keys)
  with no password-hash variable in any record. Proven clearings: an offline EC
  EEPROM edit with offsets documented per EC firmware version (e.g. T490-class
  with firmware N2IHT39W: 0x302/0x303/0x310..0x34F -> FF) or Lenovo's ThinkPad
  Config Information Update Utility ("initialize EEPROM"). Editing `Setup` or
  `LenovoSecurityConfig` variables instead bricks the board (black screen, no
  POST) — documented repeatedly on badcaps; the suite refuses to do it.

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

## IndiaFix / RC-Unlocker style tooling (v1.4.0)

### HP dump unlock (RC Unlocker / HP Unlocker mechanism)
Ported from schorschii's public HPUnlocker.py (same core the indiafix drag-drop
HP unlockers implement):
- **Modern HP UEFI**: UTF-16LE `UserCred` structure -> 100-byte credential block
  zeroed, with flag bytes 10..13 of the block set to 0xFF.
- **Legacy HP BIOS**: every `$VSS` entry keyed `BiosUser` (UTF-16LE) has its
  value region wiped with 0xFF up to the `AA 55` marker.
Limitations: G8+ (32MB, Sure Start protected) dumps may need additional steps;
the engine reports detection rather than blindly patching when nothing matches.

### ME/TXE injection (indiafix ME Injector / LRT workflow)
Instead of disabling a corrupted ME, replace it: locate the ME region via the
flash descriptor, verify the clean image carries CSME firmware ($MN2), reject
oversized images, FF-pad undersized ones, rewrite the region in place.
Clean ME repositories are distributed on indiafix/LRT ecosystems.

### DMI identity clone (All-in-One BIOS Edit 'DMI auto input')
Locate `_SM_` EPS + table in both dumps and copy the identity block old->new at
matched offsets, so a fresh BIOS keeps the machine's serial/UUID/MAC identity.

### Master password algorithms (dogbert, GPL-2+ port)
Phoenix/HP/Compaq/FSI 5-decimal (buggy-CRC16 brute force), FSI 8-hex + 5x4-hex
(CRC16-CCITT table), FSI 6x4-decimal (XOR/nibble-interleave), Insyde H2O 8-decimal
(salted arithmetic), Samsung (rotation-matrix keys, scancode + ASCII + hex),
Sony 4x4 OTP (RSA-64 with public constants), HP Mini (substitution tables),
ASUS system-date. Dell: the real algorithm is a modified-MD5 with suffix tables
(595B/D35B/2A7B/1F66/6FF1) - still a heuristic placeholder in this suite.

## Intel Engine Detail Fields (ME Analyzer)

Source: https://github.com/platomav/MEAnalyzer (BSD-2-Clause-Patent) — trust: high; it is
the de-facto reference for Intel engine dumps and follows the structures published in the
CSME kits. The suite ships the analyzer and reads its JSON report, so the ME Region page
shows the same field set as a full analyzer run:

| Field | Read from |
|---|---|
| Family | engine variant: ME / CSME / TXE / SPS |
| Version | `$MN2` manifest Major.Minor.Hotfix.Build |
| Release | manifest flags: Production / Pre-Production / Debug |
| Type | Stock / Extracted / Update, from the FPT layout and FIT fields |
| SKU | extension 0x0C SKU type plus capability flags (e.g. Consumer H) |
| Chipset | `mphytbl` in the chipset init configuration |
| TCB SVN / ARB SVN | manifest SVN and extension 0x0F ARBSVN |
| VCN | extension 0x0F VCN |
| Production Ready | manifest PV flag |
| OEM Configuration | `fitc.cfg` or a non-placeholder OEM key in FTPR |
| FWUpdate Support | IUP partitions (PMCP / PCHC / PHY) |
| Date | manifest BCD date |
| File System State | MFS / EFS parse state |
| Size | engine end from the FPT / CSE LT layout |
| Flash Image Tool | FIT version fields of the FPT 2.1 header |
| MEA Database Name | database entry for the image's RSA signature hash |

Only fields the analyzer decoded are printed; anything it could not decode stays "Unknown"
instead of a guess.

## CSME 11+ ("CSE LT") — what a proper ME clean actually is

Validation ground truth: U2201, Lenovo P14s Gen 2 (Tiger Lake, CSME 15.0.55.2751),
from the good & booting machine, plus me_cleaner's own source as armature:

- The FPT of this layout does NOT carry an FTPR entry (PSVN, UEP, IVBP, MFS, UTOK,
  HVMP, FLOG, EFS, RSTR, IMDP, FITC only — the $MN2 manifests live in a $CPD
  partition directory instead).
- me_cleaner *refuses* that layout for partition removal outright: its FTPR lookup
  requires a `CODE`/`FTPR` FPT entry and exits with
  "FTPR header not found, this image doesn't seem to be valid".
- me_cleaner's gen3 soft-disable is `PCHSTRP0 |= (1 << 16)` where PCHSTRP0 is the
  flash strap dword at FPSBA ((flmap1 >> 16 & 0xFF) * 0x10 = 0x100 here) — i.e. the
  app's `HAP/AltMeDisable` write is byte-identical in location and effect.
- Therefore the two on-disk facts the user must expect: (a) the "Clean ME" output
  differs from the input in exactly ONE bit, at FPSBA+2 with bit16 of the dword there
  (file byte 0x102 for this dump); (b) "Cleaned Size" stays the region size (no
  truncation exists for this layout).

Nothing more exists that any mainstream tool does on this generation beyond the
HAP-bit soft-disable; bigger "cleanings" are undocumented surgery and not shipped.
