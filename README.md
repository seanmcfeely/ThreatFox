# ThreatFox API

Python library and CLI tool for interacting with the [ThreatFox](https://threatfox.abuse.ch/) API.

Massive thanks to abuse.ch for all the work they do!

## Install

This python library requires python3.7 or greater. Ideally, python3.9 or greater.

```
pip install threatfox
```

## Configure

You can supply your API Key to the CLI tool with the `--api-key` option. For repeated use by the current user, you can save the API key with `threatfox --save-api-key`. This will store the key at `~/.threatfox/config.ini`. If you want all users on a system to share an API key, you can add your API Key to a config like the following at `/etc/threatfox/config.ini`:

```
[default]
api_key = 
```

Proxy settings can be configured for current user or system wide with the following option supplied to the `default` section.

```
proxy = http://user:pass@proxy_address:proxy_port
```

User configurations override system configurations.

## CLI Tool

Note that the CLI tool returns human readable JSON for convenient parsing, scripting, and data manipulation. If you're an analyst and not acquainted with [jq](https://stedolan.github.io/jq/), it's a powerful friend.

```console
$ threatfox -h
usage: threatfox [-h] [-d] [--api-key API_KEY] [--save-api-key SAVE_API_KEY] {ioc,i,malware,m,tag,t,submit,s} ...

Tool for interacting with the ThreatFox API.

positional arguments:
  {ioc,i,malware,m,tag,t,submit,s}
    ioc (i)             ThreatFox IOC API interface.
    malware (m)         Interact with ThreatFox Malware APIs.
    tag (t)             ThreatFox tag operations.
    submit (s)          Submit IOCs to ThreatFox.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Turn on debug logging.
  --api-key API_KEY     An ThreatFox API key to use.
  --save-api-key SAVE_API_KEY
                        Save an ThreatFox API key to use as the default.
```

### Example: Search for an IOC

Here is an example of searching for an IOC by value with the command line tool:

```console
$ threatfox ioc -s 'http://auto.lambolero.com/f1nygync/J18Keqh/'
{
  "query_status": "ok",
  "data": [
    {
      "id": "294783",
      "ioc": "http://auto.lambolero.com/f1nygync/J18Keqh/",
      "threat_type": "payload_delivery",
      "threat_type_desc": "Indicator that identifies a malware distribution server (payload delivery)",
      "ioc_type": "url",
      "ioc_type_desc": "URL that delivers a malware payload",
      "malware": "win.emotet",
      "malware_printable": "Emotet",
      "malware_alias": "Geodo,Heodo",
      "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet",
      "confidence_level": 90,
      "first_seen": "2022-01-13 20:16:02 UTC",
      "last_seen": null,
      "reference": null,
      "reporter": "Cryptolaemus1",
      "tags": null,
      "malware_samples": []
    }
  ]
}
```

### Example: Submit an IOC

You can submit one or more IOCs via the command line too:

```console
$ threatfox submit -tt payload -it sha256_hash -m win.ave_maria -i db0b1dbcb819306bbeab5de5dc5cddf3861cd96bb142e4feacd425b064f0ef33 -cl 75 -r 'https://app.any.run/tasks/f6ab3692-5bcf-46e9-af21-f3bb6a1dd586/' -t "Ave Maria"
{
  "query_status": "ok",
  "data": {
    "ok": [
      "db0b1dbcb819306bbeab5de5dc5cddf3861cd96bb142e4feacd425b064f0ef33"
    ],
    "ignored": [],
    "duplicated": [],
    "reward": 5
  }
}
```

## Questions

If you have any questions at all or run into a bug, please let me know by [opening an issue](https://github.com/seanmcfeely/ThreatFox/issues).

Also, if there is interest I can document all of the various ways you could use this tool via the CLI and as a python library.