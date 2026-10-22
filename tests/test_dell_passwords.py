"""Dell passwords must match the vectors published by pwgen-for-bios."""

import pytest

from bios_recovery.core.password_remover import PasswordRemover
from bios_recovery.utils.dell_passwords import dell_from_code, dell_password
from bios_recovery.utils.master_passwords import generate

# (serial, suffix, hdd, expected). Expected values are from that project's dell.spec.ts.
_CASES = [
    ("1234567", "595B", False, ["46rg65ky"]),
    ("1234567", "D35B", False, ["5tc8q9re"]),
    ("1234567", "2A7B", False, ["J1KuwWpSUgnDarfi"]),
    ("1234567", "A95B", False, ["46rg65ky"]),
    ("1234567", "1D3B", False, ["Sn4fkF8bS57NymZl"]),
    ("OPENSRC", "1D3B", False, ["S3yJ91q0Gar3O72I"]),
    ("1234567", "1F66", False, ["kIpTBzx0m3s10JDR"]),
    ("1234567", "6FF1", False, ["Rzn1wGe555H5bM2r"]),
    ("1234567", "1F5A", False, ["2ls2b8GiP9H032kx"]),
    ("1234567", "BF97", False, ["2r09GZhU[r0kW2zr"]),
    ("1234567890A", "595B", True, ["nyoap4lq"]),
    ("1234567890A", "A95B", True, ["qr0s6x4n"]),
    ("1234567890A", "1F66", True, ["vP0M31x066Z7Rq9p"]),
    ("234567890AB", "BF97", True, ["h2RDrReN37I1NLmr"]),
]


@pytest.mark.parametrize("serial,suffix,hdd,expected", _CASES)
def test_published_dell_vectors(serial, suffix, hdd, expected):
    assert dell_password(serial, suffix, hdd) == expected


def test_e7a8_returns_both_published_passwords():
    assert sorted(dell_password("1234567", "E7A8")) == ["Qk3LkU22kPeyq2jd", "rLIqjUy59IG2JU2R"]
    assert "J2yR66N1kdn2N17m" in dell_password("9M2JTG2", "E7A8")


def test_same_input_forms_as_the_other_project():
    assert dell_from_code("1234567-595B") == ["46rg65ky"]
    assert dell_from_code("123456a-1f66") == ["5sS11TUKBmBOQKRS"]
    assert dell_from_code("12345678901") == ["yyyyyhnn"]
    assert dell_from_code("1234567-BAD1") == []


def test_gui_generator_uses_the_same_form():
    assert generate("dell", "1234567-595B") == [("password", "46rg65ky")]


def test_unrecognised_suffix_is_not_a_guess():
    assert PasswordRemover().generate_dell_master_password("1234567", "NOPE") == []
