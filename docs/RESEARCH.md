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
