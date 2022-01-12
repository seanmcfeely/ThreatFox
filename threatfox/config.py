"""Configuration related items.
"""

import os
import logging

from configparser import ConfigParser

LOGGER = logging.getLogger("threatfox.config")

HOME_PATH = os.path.dirname(os.path.abspath(__file__))

user_config_path = os.path.join(os.path.expanduser("~"), ".threatfox", "config.ini")
CONFIG_SEARCH_PATHS = [
    "/etc/threatfox/config.ini",
    user_config_path,
]

CONFIG = ConfigParser()
CONFIG.read(CONFIG_SEARCH_PATHS)

if not CONFIG.has_section("default"):
    CONFIG.add_section("default")


def save_configuration(config: ConfigParser = CONFIG, save_path=user_config_path):
    """Write config to save_path."""
    if save_path == user_config_path:
        try:
            if not os.path.exists(user_config_path):
                os.mkdir(os.path.join(os.path.expanduser("~"), ".threatfox"))
        except FileExistsError:
            pass
    try:
        with open(save_path, "w") as fp:
            config.write(fp)
        return True
    except FileNotFoundError:
        LOGGER.error(f"part of path does not exist: {save_path}")
    if os.path.exists(save_path):
        LOGGER.info(f"saved configuration to: {save_path}")


def save_api_key(api_key: str, config=CONFIG, save_path=user_config_path):
    config.set("default", "api_key", api_key)
    save_configuration(save_path=save_path)
    return True


def set_api_key(api_key: str):
    os.environ["THREATFOX_API_KEY"] = api_key
    return True


def get_api_key():
    if "THREATFOX_API_KEY" not in os.environ:
        api_key = CONFIG.get("default", "api_key", fallback=None)
        if api_key:
            set_api_key(api_key)
    return os.environ.get("THREATFOX_API_KEY", None)


def save_api_url(url: str, config=CONFIG, save_path=user_config_path):
    config.set("default", "api_url", url)
    save_configuration(save_path=save_path)
    return True


def set_api_url(url: str):
    os.environ["THREATFOX_API_URL"] = url
    return True


def get_api_url():
    return os.environ.get("THREATFOX_API_URL", "https://threatfox-api.abuse.ch/api/v1/")


def get_configured_proxy(config=CONFIG):
    return config.get("default", "proxy", fallback=None)


# This constraint allows for an optional safe guard to be enforced that will prevent
# `threatfox` CLI from accidentally pulling ALL events at once.
def get_max_result_contraint(config=CONFIG):
    return config.getint("default", "max_result_constraint", fallback=None)
