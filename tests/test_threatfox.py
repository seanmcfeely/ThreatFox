import aiohttp
import asyncio

from tests import *


def test_version():
    from threatfox import __version__

    assert __version__ == "0.0.2"


@pytest.mark.asyncio
async def test_client_construction():
    from threatfox import ThreatFoxClient

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:
        assert isinstance(tfc, ThreatFoxClient)
        assert tfc.api_key == TEST_APIKEY


@pytest.mark.asyncio
async def test_client_execution(mock_response):
    from threatfox import ThreatFoxClient

    mock_response.post("http://test", status=200, body="test")

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:
        status, result = await tfc.execute("POST", "http://test")

        assert status == 200
        assert result.decode("utf-8") == "test"


@pytest.mark.asyncio
async def test_execute_and_return_object(mock_response, test_data):
    from threatfox import ThreatFoxClient

    mock_response.post("https://threatfox-api.abuse.ch/api/v1/", status=200, payload=test_data)

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:

        results = await tfc.execute_and_return_object("POST")
        assert isinstance(results, dict)
        assert isinstance(results["data"], list)
        assert results["query_status"] == "ok"
        assert len(results["data"]) == 2
        assert isinstance(results["data"][0], dict)
