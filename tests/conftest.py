import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixture_builder import write_fixtures


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    return write_fixtures(str(tmp_path_factory.mktemp("fixtures")))


@pytest.fixture(scope="session")
def intel_ifd(fixtures):
    return fixtures["intel_ifd.bin"]


@pytest.fixture(scope="session")
def dell_pfs(fixtures):
    return fixtures["dell_pfs.bin"]


@pytest.fixture(scope="session")
def ec_firmware(fixtures):
    return fixtures["ec_firmware.bin"]


@pytest.fixture(scope="session")
def ec_dump(fixtures):
    return fixtures["ec_dump.bin"]