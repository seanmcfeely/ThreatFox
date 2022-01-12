import aiohttp
import asyncio

from tests import *


def test_version():
    from threatfox import __version__

    assert __version__ == "0.0.1"


@pytest.mark.asyncio
async def test_client_construction():
    from threatfox import ThreatFoxClient

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:
        assert isinstance(tfc, ThreatFoxClient)
        assert tfc.api_key == TEST_APIKEY


@pytest.mark.asyncio
async def test_client_construction():
    from threatfox import ThreatFoxClient

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:
        assert isinstance(tfc, ThreatFoxClient)
        assert tfc.api_key == TEST_APIKEY


