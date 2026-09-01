# BIOS Recovery Suite

Professional BIOS repair, analysis, ME cleaning, DMI extraction, and password removal tool inspired by LBE.

**⚠️ WARNING: This tool modifies firmware. Improper use can brick your device. Always create backups before flashing.**

## Features

- **BIOS Analysis** - Detect BIOS type, regions, ME version, and identify issues in any firmware image
- **Auto Repair** - Fix corrupted flash descriptors, FPT checksums, and normalize image sizes
- **Intel ME Cleaner** - Clear/neuter ME, TXE, and CSME regions with HAP/AltMeDisable support
- **DMI / SMBIOS Extraction** - Extract system, board, and BIOS information from dumps
- **Password Removal** - Remove setup/admin passwords from AMI, Insyde, Phoenix, Dell, HP, Lenovo firmware
- **Master Password Generator** - Generate master passwords for Dell, HP, and Insyde systems
- **BIOS Extraction** - Extract BIOS from vendor EXE, PFS, COM, FL1, and other formats
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
│   └── bios_repair.py        # Auto-repair engine
├── manufacturers/
│   └── profiles.py           # Manufacturer-specific knowledge
├── gui/
│   ├── main_window.py        # Qt main window
│   └── styles.py             # Theme stylesheets
└── utils/
```

## Disclaimer

This tool is provided for educational and legitimate repair purposes only. Users are responsible for:
- Ensuring they have the right to modify the firmware
- Creating backups before any modification
- Understanding the risks of BIOS modification

The authors are not responsible for any damage caused by misuse of this software.

## License

MIT License - see [LICENSE](LICENSE)
