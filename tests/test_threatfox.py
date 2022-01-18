import aiohttp
import asyncio

from tests import *


def test_version():
    from threatfox import __version__

    assert __version__ == "1.0.0"


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
async def test_execute_and_return_object(mock_response, test_ioc_data):
    from threatfox import ThreatFoxClient

    mock_response.post("https://threatfox-api.abuse.ch/api/v1/", status=200, payload=test_ioc_data)

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:

        results = await tfc.execute_and_return_object("POST")
        assert isinstance(results, dict)
        assert isinstance(results["data"], list)
        assert results["query_status"] == "ok"
        assert len(results["data"]) == 2
        assert isinstance(results["data"][0], dict)


@pytest.mark.asyncio
async def test_submission(mock_response, test_ioc_values, fake_submission_result):
    from threatfox import ThreatFoxClient

    mock_response.post("https://threatfox-api.abuse.ch/api/v1/", status=200, payload=fake_submission_result)

    async with ThreatFoxClient(api_key=TEST_APIKEY) as tfc:

        results = await tfc.submit_iocs(
            threat_type="payload_delivery",
            ioc_type="url",
            malware="win.emotet",
            iocs=test_ioc_values,
            confidence_level=90,
            reference="testing",
            tags=["Emotet"],
            comment="Testing",
            anonymous=1,
        )
        assert isinstance(results, dict)
        assert isinstance(results["data"], dict)
        assert results["query_status"] == "ok"
        assert isinstance(results["data"]["ok"], list)
        assert len(results["data"]["ok"]) == 3
