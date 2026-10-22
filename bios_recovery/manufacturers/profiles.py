"""Manufacturer profiles for BIOS structure, password, and DMI locations."""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class Manufacturer(Enum):
    UNKNOWN = auto()
    DELL = auto()
    HP = auto()
    LENOVO = auto()
    ASUS = auto()
    ACER = auto()
    TOSHIBA = auto()
    SAMSUNG = auto()
    SONY = auto()
    MSI = auto()
    GIGABYTE = auto()
    APPLE = auto()
    FUJITSU = auto()
    PANASONIC = auto()
    IBM = auto()
    PACKARD_BELL = auto()
    GATEWAY = auto()
    MEDION = auto()
    SUPERCORE = auto()


# Password patterns are informational. No writer uses them, and none has been checked
# against vendor firmware; a run of zero bytes matches erased space as well.
@dataclass
class PasswordRegion:
    name: str
    pattern: str
    offset: int = 0
    size: int = 0
    clear_method: str = "zero"
    notes: str = ""


@dataclass
class DMIRegion:
    name: str
    offset: int = 0
    size: int = 0
    search_signature: str = ""
    notes: str = ""


@dataclass
class MERegion:
    name: str = "Intel ME"
    me_version: str = ""
    hap_location: str = ""
    description: str = ""


@dataclass
class ManufacturerProfile:
    manufacturer: Manufacturer
    name: str
    bios_signatures: list[str] = field(default_factory=list)
    password_regions: list[PasswordRegion] = field(default_factory=list)
    dmi_regions: list[DMIRegion] = field(default_factory=list)
    me_regions: list[MERegion] = field(default_factory=list)
    uses_flash_descriptor: bool = True
    common_flash_sizes: list[int] = field(default_factory=list)
    notes: str = ""


class ManufacturerProfiles:
    """Database of manufacturer-specific BIOS profiles."""

    _profiles: dict[Manufacturer, ManufacturerProfile] = {}

    def __init__(self):
        self._build_profiles()

    def _build_profiles(self):
        self._profiles = {
            Manufacturer.DELL: ManufacturerProfile(
                manufacturer=Manufacturer.DELL,
                name="Dell",
                bios_signatures=[b"Dell", b"DELL", b"PFS"],
                password_regions=[
                    PasswordRegion(
                        name="Dell Admin/Setup Password",
                        pattern="8FC8",
                        size=4,
                        clear_method="master_password",
                        notes="Generate master password from service tag with 8FC8 suffix",
                    ),
                    PasswordRegion(
                        name="Dell BF97 Password",
                        pattern="BF97",
                        size=4,
                        clear_method="master_password",
                        notes="Older Dell models use BF97 suffix",
                    ),
                    PasswordRegion(
                        name="Dell Computrace",
                        pattern="\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
                        size=16,
                        clear_method="zero",
                        notes="Remove Computrace from BIOS dump",
                    ),
                ],
                dmi_regions=[
                    DMIRegion(
                        name="System Serial Number",
                        search_signature="System Name",
                        notes="Found in SMBIOS Type 1 table",
                    ),
                    DMIRegion(
                        name="Service Tag",
                        search_signature="Service Tag",
                        notes="Used for master password generation",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x800000, 0x1000000, 0x2000000],
                notes="Dell uses PFS (Packaged Firmware Suite) format for updates. "
                      "BIOS is typically 8-32MB.",
            ),
            Manufacturer.HP: ManufacturerProfile(
                manufacturer=Manufacturer.HP,
                name="HP",
                bios_signatures=[b"HP", b"Hewlett", b"Insyde"],
                password_regions=[
                    PasswordRegion(
                        name="HP Setup Password",
                        pattern="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                        size=10,
                        clear_method="zero",
                        notes="HP stores password in NVRAM, clearing removes it",
                    ),
                    PasswordRegion(
                        name="HP Admin Password",
                        pattern="Admin",
                        size=5,
                        clear_method="master_password",
                        notes="Generate using HP master password algorithm",
                    ),
                ],
                dmi_regions=[
                    DMIRegion(
                        name="HP DMI Data",
                        search_signature="SystemSerialNumber",
                        notes="DMI data stored in specific region",
                    ),
                    DMIRegion(
                        name="Asset Tracking Number",
                        search_signature="Asset",
                        notes="Changeable via HP tools",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x400000, 0x800000, 0x1000000],
                notes="Newer HP models use Insyde firmware with signed EC. "
                      "Password removal may require EC patch.",
            ),
            Manufacturer.LENOVO: ManufacturerProfile(
                manufacturer=Manufacturer.LENOVO,
                name="Lenovo",
                bios_signatures=[b"Lenovo", b"LENOVO", b"IBM"],
                password_regions=[
                    PasswordRegion(
                        name="Lenovo cE! variable",
                        pattern="cE!",
                        size=8,
                        clear_method="delete",
                        notes="Deleting cE! variable resets password protection",
                    ),
                    PasswordRegion(
                        name="Lenovo Supervisor Password",
                        pattern="\x00\x00\x00\x00\x00\x00\x00\x00",
                        size=8,
                        clear_method="zero",
                        notes="Cleared with Lenovo tools",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x400000, 0x800000, 0x1000000, 0x2000000],
                notes="Modern Lenovo (8th gen+) requires EC patch for password removal. "
                      "Uses MEC15XX/MEC17XX chips.",
            ),
            Manufacturer.ASUS: ManufacturerProfile(
                manufacturer=Manufacturer.ASUS,
                name="ASUS",
                bios_signatures=[b"ASUS", b"ASUSTek"],
                password_regions=[
                    PasswordRegion(
                        name="ASUS Setup Password",
                        pattern="AMITSESetup",
                        size=12,
                        clear_method="zero",
                        notes="AMITSESetup variable stores hash",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x800000, 0x1000000],
                notes="ASUS uses AMI Aptio firmware. Passwords stored in NVRAM variables.",
            ),
            Manufacturer.ACER: ManufacturerProfile(
                manufacturer=Manufacturer.ACER,
                name="Acer",
                bios_signatures=[b"Acer", b"ACER"],
                password_regions=[
                    PasswordRegion(
                        name="Acer SVP Password",
                        pattern="SVP",
                        size=8,
                        clear_method="zero",
                        notes="Acer 8-10 digit SVP password",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x800000, 0x1000000],
                notes="Acer uses Insyde firmware. Newer models use 8-10 digit SVP.",
            ),
            Manufacturer.TOSHIBA: ManufacturerProfile(
                manufacturer=Manufacturer.TOSHIBA,
                name="Toshiba",
                bios_signatures=[b"Toshiba", b"TOSHIBA"],
                password_regions=[
                    PasswordRegion(
                        name="Toshiba Password",
                        pattern="\x00\x00\x00\x00",
                        size=4,
                        clear_method="zero",
                        notes="Toshiba stores password in EEPROM",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x400000, 0x800000],
                notes="Toshiba uses encrypted COM files for updates. Some models use 24C04 EEPROM.",
            ),
            Manufacturer.SAMSUNG: ManufacturerProfile(
                manufacturer=Manufacturer.SAMSUNG,
                name="Samsung",
                bios_signatures=[b"Samsung", b"SAMSUNG"],
                password_regions=[
                    PasswordRegion(
                        name="Samsung Password",
                        pattern="\x00\x00\x00\x00\x00\x00",
                        size=12,
                        clear_method="zero",
                        notes="Samsung 12 hex digit password",
                    ),
                ],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x800000, 0x1000000],
            ),
            Manufacturer.SONY: ManufacturerProfile(
                manufacturer=Manufacturer.SONY,
                name="Sony",
                bios_signatures=[b"Sony", b"VAIO"],
                password_regions=[],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x800000, 0x1000000],
                notes="Sony VAIO uses 24C04 EEPROM for password storage.",
            ),
            Manufacturer.APPLE: ManufacturerProfile(
                manufacturer=Manufacturer.APPLE,
                name="Apple",
                bios_signatures=[b"APPLE", b"Apple"],
                password_regions=[
                    PasswordRegion(
                        name="EFI Password",
                        pattern="\x00\x00\x00\x00\x00\x00\x00\x00",
                        size=8,
                        clear_method="zero",
                        notes="Apple EFI password removal",
                    ),
                ],
                uses_flash_descriptor=False,
                common_flash_sizes=[0x400000, 0x800000],
                notes="Apple uses proprietary EFI. "
                      "Password removal requires FSC block CRC calculation.",
            ),
            Manufacturer.FUJITSU: ManufacturerProfile(
                manufacturer=Manufacturer.FUJITSU,
                name="Fujitsu",
                bios_signatures=[b"Fujitsu", b"FUJITSU"],
                password_regions=[],
                uses_flash_descriptor=True,
                common_flash_sizes=[0x800000, 0x1000000],
            ),
        }

    def get(self, manufacturer: Manufacturer) -> Optional[ManufacturerProfile]:
        return self._profiles.get(manufacturer)

    def detect_manufacturer(self, data: bytes) -> Manufacturer:
        text = self._extract_ascii(data[:0x10000])
        for manufacturer, profile in self._profiles.items():
            tokens = [sig.decode("ascii", errors="ignore") for sig in profile.bios_signatures]
            if self._qualifies(text, tokens, ignore_case=False):
                return manufacturer

        for m in Manufacturer:
            if m == Manufacturer.UNKNOWN:
                continue
            if self._qualifies(text, [m.name.replace("_", " ")], ignore_case=True):
                return m

        return Manufacturer.UNKNOWN

    @staticmethod
    def _qualifies(text: str, tokens: list[str], ignore_case: bool) -> bool:
        """True when whole-word tokens match the vendor text.

        Short tokens such as "HP" or "IBM" occur in arbitrary data, so one of them
        is not enough: a manufacturer needs two distinct tokens or one of four
        characters or more.
        """
        flags = re.IGNORECASE if ignore_case else 0
        hits = {
            t.lower()
            for t in tokens
            if t
            and re.search(rf"(?<![A-Za-z0-9]){re.escape(t)}(?![A-Za-z0-9])", text, flags)
        }
        return len(hits) >= 2 or any(len(t) >= 4 for t in hits)

    def _extract_ascii(self, data: bytes) -> str:
        result = bytearray()
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                result.append(byte)
            else:
                result.append(0x20)
        return result.decode("ascii", errors="ignore")

    def list_profiles(self) -> list[ManufacturerProfile]:
        return list(self._profiles.values())
