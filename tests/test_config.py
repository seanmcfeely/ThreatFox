import os

from tests import *


def test_save_configuration():
    from threatfox.config import save_configuration

    assert save_configuration(TEST_CONFIG, save_path=TEST_CONFIG_PATH) is True
    assert os.path.exists(TEST_CONFIG_PATH) is True


def test_save_api_key():
    from threatfox.config import save_api_key

    assert save_api_key(TEST_APIKEY, save_path=TEST_CONFIG_PATH) is True
    assert TEST_CONFIG.get("default", "api_key") == TEST_APIKEY


def test_set_and_get_api_key():
    from threatfox.config import set_api_key, get_api_key

    assert set_api_key(TEST_APIKEY) is True
    assert os.environ["THREATFOX_API_KEY"] == TEST_APIKEY
    assert get_api_key() == TEST_APIKEY
    # test from fake config
    assert TEST_CONFIG.get("default", "api_key") == TEST_APIKEY


def test_get_api_url():
    from threatfox.config import get_api_url

    assert get_api_url() == "https://threatfox-api.abuse.ch/api/v1/"


def test_get_max_result_constraint():
    from threatfox.config import get_max_result_contraint

    assert get_max_result_contraint(config=TEST_CONFIG) == 10


def test_get_proxy():
    from threatfox.config import get_configured_proxy

    assert get_configured_proxy(TEST_CONFIG) == "http://user:pass@proxy_address:proxy_port"
