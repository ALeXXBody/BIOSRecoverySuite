# BIOS Recovery Suite

Professional BIOS repair, analysis, ME cleaning, DMI extraction, and password removal tool inspired by LBE.

**⚠️ WARNING: This tool modifies firmware. Improper use can brick your device. Always create backups before flashing.**

## Features

- **BIOS Analysis** - Detect BIOS type, regions, ME version, and identify issues in any firmware image
- **Intel Engine Detail** - Full ME/CSME report for the loaded image: family, release, type, SKU,
  chipset, TCB/ARB SVN, VCN, OEM configuration, FWUpdate support, date, file system state,
  size, Flash Image Tool version and MEA database name
- **Auto Repair** - Fix corrupted flash descriptors, FPT checksums, and normalize image sizes
- **Intel ME Cleaner** - Clear/neuter ME, TXE, and CSME regions with HAP/AltMeDisable support
- **DMI / SMBIOS Extraction** - Extract system, board, and BIOS information from dumps
- **Password Removal** - Remove setup/admin passwords from AMI, Insyde, Phoenix, Dell, HP, Lenovo firmware
- **Master Password Generator** - Real reverse-engineered algorithms (dogbert): Phoenix/HP/Compaq/FSI 5-decimal, FSI 8-hex & 5x4-hex & 6x4-decimal, Insyde H2O, Samsung, Sony 4x4, HP Mini, ASUS system-date
- **BIOS Extraction** - Extract BIOS from vendor EXE, PFS, COM, FL1, and other formats
- **SPI Flasher** - Read/write/erase/verify SPI flash through flashrom (CH341A, FT2232, etc.)
- **EC Patching** - Locate and analyze Embedded Controller firmware, scan for password flags, extract regions, and apply data-driven patches
- **HP Unlock** - Clear HP ProBook/EliteBook/ZBook admin passwords from dumps (UserCred + $VSS/BiosUser wiping)
- **ME/TXE Injector** - Repair corrupted ME regions by injecting a clean firmware image with version verification
- **DMI Clone** - Carry serials/UUID/MAC identity from an old dump into a new BIOS image
- **Lenovo Unlock** - UEFIPatch-compatible pattern patcher for ThinkPads: WLAN/WWAN whitelist removal, hidden Advanced menu unlock, LNVBBSEC tamper-flag fix, and badcaps-style DXE driver replacement for supervisor-password removal
- **Hex Viewer** - Inspect raw bytes of any firmware image

## Supported Manufacturers

Dell, HP, Lenovo, ASUS, Acer, Toshiba, Samsung, Sony/VAIO, MSI, Gigabyte, Apple, Fujitsu, Panasonic, IBM, Packard Bell, Gateway

## Installation

### From Source

```bash
git clone https://github.com/ALeXXBody/BIOSRecoverySuite
cd BIOSRecoverySuite
pip install -r requirements.txt
python -m bios_recovery.main
```

### Platform Support

Windows/Linux/macOS. Windows additionally ships a signed installer with a silent
self-update flow in the app. For Linux and macOS, grab the platform package
from a release: `BIOSRecoverySuite-linux-x64-<v>.tar.gz` (unpack and run
`./BIOSRecoverySuite`) or `BIOSRecoverySuite-macos-arm64-<v>.dmg`. The self-update
button on Linux/macOS points at the releases page instead; PySide6 must be
available through the system Qt libraries there.

### Building the Windows EXE

```bash
pip install pyinstaller
pyinstaller --noconfirm bios_recovery.spec
```

The executable will be in `dist/`.

## Usage Guide

### Overview Tab
Load a BIOS file (from a dump or update package) to analyze it. The tool detects the BIOS type, parses the flash descriptor, finds all regions, and identifies common issues.

### Repair Tab
Run auto-repair to fix common BIOS problems:
- Fix corrupted FPT checksums
- Clean the ME region
- Remove security structures
- Verify size alignment

### ME Cleaner Tab
Clean the Intel Management Engine region:
- Show the loaded engine's full detail: family, version, release, type, SKU, chipset, SVN/VCN,
  OEM configuration, FWUpdate support, file system state, FIT version and database name
- Set HAP/AltMeDisable bit to soft-disable ME
- Remove non-essential ME partitions and modules
- Lock the flash descriptor
- Truncate empty spaces

### DMI Tab
Extract DMI/SMBIOS data including:
- BIOS vendor, version, release date
- System manufacturer, product name, serial number
- Baseboard and chassis info
- Processor, memory details

### Security Tab
Scan for and remove password structures:
- AMI setup password variables (AMITSESetup)
- Lenovo cE! security variables
- Dell password markers (8FC8, BF97)
- EFI/UEFI password variables

### Extract Tab
Extract BIOS components from vendor packages:
- Dell PFS format
- HP/Insyde executables
- Lenovo FL1 and EXE
- Universal firmware volume search

### Hex Viewer
View raw bytes at any offset for advanced manual inspection.

### Passwords Tab
Generate master passwords:
- Dell (all known suffixes: 595B, D35B, 2A7B, A95B, etc.)
- HP
- Insyde (Acer/HP)

### SPI Flasher Tab
Program SPI flash chips with flashrom:
- Auto-detect supported programmers (`ch341a_spi`, `ft2232_spi`, `linux_spi`, ...)
- Identify the installed chip
- **Read** the full chip to a backup file
- **Write** an image (requires an explicit consent check AND an automatic pre-write backup)
- **Erase** the chip (requires an explicit consent check)
- Every destructive action must be consciously confirmed in the UI.

### Lenovo Unlock Tab
Community-proven unlock workflow for Lenovo machines:
- Detects Lenovo firmware, the `cE!` runtime backdoor (LenovoH2O method), and the `LNVBBSEC` tamper flag
- Dry-run scans the built-in UEFIPatch-format registry (xx30 WLAN whitelist, xx60/xx70/xx80 advanced menu + WWAN whitelist, xx40+ tamper fix) — only matching patterns are offered
- Applies pattern patches into raw and LZMA-compressed firmware volumes with full FFS checksum/alignment/pad-file handling
- **DXE driver replacement** for supervisor-password removal: either apply binaries from the registry (`bios_recovery/patches/dxe_replacements.json`) or auto-derive them by diffing an original dump against an autopatched dump
- Pattern sources: digmorepaka/thinkpad-firmware-patches, Aldair402/thinkpad-t460s-biosmod, badcaps autopatch thread

### EC Patching Tab
Analyze the Embedded Controller firmware inside a dump:
- Detect OEM DMI chassis type, model, and version
- Locate the EC region by controller signatures (ITE, Nuvoton, Microchip MEC, ENE)
- Scan for password/security flags (`PasswordStatus`, `UnLock`, `KBC_PW`, ...)
- Extract the EC firmware region to a standalone file
- Apply patches from the **data-driven registry** (`bios_recovery/patches/ec_patches.json`).
  Only `verified` patches apply automatically; unverified patches require typing an
  explicit acceptance phrase. The registry is community-extendable without code changes.

## Testing

The test suite runs against **structurally-valid synthetic fixtures** (no real hardware or real dumps needed):

```bash
pip install pytest
pytest tests/ -v
```

- `tests/fixture_builder.py` - generates realistic dumps: an Intel flash-descriptor +
  ME + GbE + firmware-volume + SMBIOS + NVRAM image, a Dell PFS package, and full-size
  EC dumps with ITE markers and an XOR checksum.
- The SPI flasher tests use a fake `tests/fake_flashrom.py` shim (flashrom itself needs
  real hardware and is never run in CI).
- EC patches are intentionally NOT hardware-verified; the engine refuses unverified patches
  by default.

## Command Line Usage

```bash
# Analyze a BIOS file
python -m bios_recovery.main analysis --file bios.bin

# Clean ME region
python -m bios_recovery.main me-clean --file bios.bin --output cleaned.bin
```

## Dependencies

- Python 3.10+
- PySide6 (GUI)
- PyInstaller (packaging)

## Architecture

```
bios_recovery/
├── engines/
│   ├── bios_analyzer.py      # BIOS type & region detection
│   ├── me_cleaner.py         # Intel ME/TXE/CSME cleaning
│   ├── dmi_extractor.py      # SMBIOS/DMI parsing
│   ├── password_remover.py   # Password removal & generation
│   ├── bios_extractor.py     # Vendor package extraction
│   ├── bios_repair.py        # Auto-repair engine
│   ├── spi_flasher.py        # flashrom-based SPI programmer integration
│   └── ec_patcher.py         # EC firmware analysis + patch registry
├── patches/
│   └── ec_patches.json       # data-driven EC patch registry
├── manufacturers/
│   └── profiles.py           # Manufacturer-specific knowledge
├── gui/
│   ├── main_window.py        # Qt main window
│   ├── spi_tab.py            # SPI flasher tab
│   └── ec_tab.py             # EC patching tab
└── utils/
tests/
├── fixture_builder.py        # synthetic BIOS/EC fixture generators
├── fake_flashrom.py          # deterministic flashrom test double
└── test_*.py                 # regression suites
```

## Disclaimer

This tool is provided for educational and legitimate repair purposes only. Users are responsible for:
- Ensuring they have the right to modify the firmware
- Creating backups before any modification
- Understanding the risks of BIOS modification

The authors are not responsible for any damage caused by misuse of this software.

## License

MIT License - see [LICENSE](LICENSE)
