import os
import json
import pytest

from aioresponses import aioresponses
from configparser import ConfigParser

HOME_PATH = os.path.dirname(os.path.abspath(__file__))

TEST_CONFIG_PATH = os.path.join(HOME_PATH, "tmp_config.ini")
FAKE_CONFIG_PATH = os.path.join(HOME_PATH, "fake_config.ini")
TEST_DATA_PATH = os.path.join(HOME_PATH, "data.json")
TEST_URL_VALUES = os.path.join(HOME_PATH, "urls.txt")
TEST_SUB_RESULT = os.path.join(HOME_PATH, "submission_result.json")

TEST_APIKEY = "fakeapikey"

TEST_CONFIG = ConfigParser()
TEST_CONFIG.read(FAKE_CONFIG_PATH)
if not TEST_CONFIG.has_section("default"):
    TEST_CONFIG.add_section("default")


@pytest.fixture(scope="function", autouse=True)
def cleanup(request):
    """Cleanup test config items, files, and folders."""

    def _delete_local_config():
        if os.path.exists(TEST_CONFIG_PATH):
            os.remove(TEST_CONFIG_PATH)

    request.addfinalizer(_delete_local_config)


@pytest.fixture
def mock_response():
    with aioresponses() as m:
        yield m


@pytest.fixture
def test_ioc_data():
    data = []
    with open(TEST_DATA_PATH, "r") as fp:
        data = json.load(fp)
    return data


@pytest.fixture
def test_ioc_values():
    data = []
    with open(TEST_URL_VALUES, "r") as fp:
        data = [line.split() for line in fp.readlines()]
    return data


@pytest.fixture
def fake_submission_result():
    data = []
    with open(TEST_SUB_RESULT, "r") as fp:
        data = json.load(fp)
    return data
