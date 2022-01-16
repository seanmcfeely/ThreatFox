"""ThreatFox API Client.
"""

import aiohttp
import asyncio
import json
import logging

from typing import List

from threatfox.config import get_api_url, get_api_key, get_configured_proxy

__version__ = "0.0.2"


class ThreatFoxClient:
    """ThreatFox API Client.

    Attributes:
        api_key: A valid API key. If None, will attempt to get an API key from
          configuration/environment variable.
        url: The ThreatFox API URL. If None, default value is used from config.
    """

    def __init__(self, api_key=None, url=None, **kwargs):
        self.logger = logging.getLogger("threatfox.ThreatFoxClient")

        self.api_key = get_api_key() if api_key is None else api_key
        self.headers = {}
        if self.api_key is not None:
            self.headers = {"api-key": self.api_key, "content-type": "application/json"}
        self.kwargs = kwargs
        if "proxy" not in self.kwargs:
            # check the config for proxy settings
            self.kwargs["proxy"] = get_configured_proxy()

        self.url = get_api_url() if url is None else url
        self.session = aiohttp.ClientSession()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *excinfo):
        await self.session.close()

    async def execute(self, method, url=None, headers=None, payload=None, **kwargs):
        """Executes a single API request.

        Args:
            method: The HTTP method to use.
            url: The url to connect to.
            headers: Request headers.
            payload: The payload to send
        Returns:
            A tuple like: response status code, response data
        """
        kwargs = {**self.kwargs, **kwargs}
        if url is None:
            url = self.url
        if headers is None:
            headers = self.headers
        if "api-key" not in headers and self.api_key is not None:
            self.logger.debug(f"injecting api key into headers.")
            headers["API-KEY"] = self.api_key

        async with self.session.request(
            method=method, url=url, headers=headers, data=json.dumps(payload), ssl=True, **kwargs
        ) as response:
            self.logger.debug(f"{method} request made to {url} with {response.status} response code")
            return response.status, await response.read()

    async def execute_and_return_object(self, method, url=None, headers=None, payload=None, **kwargs):
        """Execute request and return any valid json response.

        Args:
            method: The HTTP method to use.
            url: The url to connect to.
            headers: Request headers.
            payload: The payload to send
        Returns:
            A tuple like: response status code, response data
        """
        status, response = await self.execute(method, url=url, headers=headers, payload=payload, **kwargs)

        if status != 200:
            self.logger.error(f"got {status} status code: {response}")
            return False

        if not isinstance(response, bytes):
            self.logger.error(f"got unexpected response of type {type(response)}")
            return False

        return json.loads(response.decode("utf-8"))

    async def get_iocs(self, days: int = None, **kwargs):
        """Get ThreatFox IOCs.

        Args:
            days: optional number of days to filter IOCs based on when an IOC
              was first_seen. Min: 1, Max: 90. Default: 90
        Returns:
            A list of dictionaries corresponding to ThreatFox IOC results.
        """

        payload = {"query": "get_iocs"}
        if days is not None:
            assert isinstance(days, int)
            payload["days"] = days

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def get_ioc_by_id(self, ioc_id: int, **kwargs):
        """Get ThreatFox IOC by ID.

        Args:
            ioc_id: ThreatFox IOC ID of the IOC you would like to query.
        Returns:
            The ThreatFox IOC if it exists.
        """

        payload = {
            "query": "ioc",
            "id": ioc_id,
        }

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def search_ioc(self, search_term: str, **kwargs):
        """Search ThreatFox for an IOC.

        NOTE: there is a separete endpoint for searching for hash IOCs.
        # XXX use regex to make hash determination and have one search function?

        Args:
            search_term: A string representation of any IOC.
        Returns:
            A list of dictionaries corresponding to ThreatFox IOC results.
        """

        payload = {
            "query": "search_ioc",
            "search_term": search_term,
        }

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def search_hash(self, hash: str, **kwargs):
        """Search ThreatFox for IOCs associated with a file hash.

        You can search for IOCs associated with a certain file hash (MD5 hash or SHA256 hash)

        Args:
            hash: A MD5 or SHA256 hash.
        Returns:
            A list of dictionaries corresponding to ThreatFox IOC results.
        """

        payload = {
            "query": "search_hash",
            "hash": hash,
        }

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def query_tag(self, tag: str, limit=100, **kwargs):
        """Search ThreatFox for IOCs associated with a tag.

        Args:
            tag: a tag.
            limit: Max number of results (default: 100, max: 1000)
        Returns:
            A list of dictionaries corresponding to ThreatFox IOC results.
        """

        payload = {"query": "taginfo", "tag": tag, "limit": limit}

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def query_malware_iocs(self, malware: str, limit=100, **kwargs):
        """Search ThreatFox for IOCs associated with a malware family.

        Args:
            malware: name of a malware family.
            limit: Max number of results (default: 100, max: 1000)
        Returns:
            A list of dictionaries corresponding to ThreatFox IOC results.
        """

        payload = {"query": "malwareinfo", "malware": malware, "limit": limit}

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def submit_iocs(
        self,
        threat_type: str,
        ioc_type: str,
        malware: str,
        iocs: List[str],
        confidence_level: int = 50,
        reference: str = None,
        tags: List[str] = [],
        comment: str = None,
        anonymous: int = 0,
        **kwargs,
    ):
        """Submit IOCs to ThreatFox.

        Args:
            threat_type: Threat type.
            ioc_type: IOC type.
            malware: malpedia malware name
            iocs: list of IOCs values for the IOC type.
            confidence_level: Confidence level 0-100. Default: 50
            reference: Reference (url).
            tags: List of tags.
            comment: Your comment on the IOCs.
            anonymous: If set to 1, your submission will be anonymous. Default: 0
        Returns:
            A result dictionary.
        """

        payload = {
            "query": "submit_ioc",
            "threat_type": threat_type,
            "ioc_type": ioc_type,
            "malware": malware,
            "confidence_level": confidence_level,
            "reference": reference,
            "comment": comment,
            "anonymous": anonymous,
            "tags": tags,
            "iocs": iocs,
        }

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def search_malware_families(self, malware: str, platform: str = None, **kwargs):
        """Lookup the correct malware family name.

        ThreatFox uses the malware labels from Malpedia. You can use this API call to search
        for the correct malware family name given a malware alias.

        Args:
            malware: A malware name/label/alias you want to look for.
            platform: OS Platform (win, osx, apk, jar or elf).
        Returns:
            A list of dictionaries corresponding to ThreatFox IOC results.
        """

        # XXX
        # supported_platforms = ['win', 'osx', 'apk', 'jar', 'elf']

        payload = {"query": "get_label", "malware": malware, "patform": platform}

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def get_malware_list(self, **kwargs):
        """Get the list of supported malware families.

        ThreatFox uses the malware labels from Malpedia.

        Args:
        Returns:
            List of Malpedia/ThreatFox malware families.
        """

        payload = {"query": "malware_list"}

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def get_ioc_threat_types(self, **kwargs):
        """Get the supported IOC / threat types from ThreatFox.

        ThreatFox uses the malware labels from Malpedia.

        Args:
        Returns:
            List of supported IOC / threat types.
        """

        payload = {"query": "types"}

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results

    async def get_tag_list(self, **kwargs):
        """Get the list of tags known to ThreatFox.

        Args:
        Returns:
            List of supported IOC / threat types.
        """

        payload = {"query": "tag_list"}

        results = await self.execute_and_return_object("POST", payload=payload, **kwargs)
        return results
