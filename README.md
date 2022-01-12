# ThreatFox API

Python library and CLI tool for interacting with the [ThreatFox](https://threatfox.abuse.ch/) API.

Massive thanks to abuse.ch for all the work they do!

## Example Usage


### Via CLI


### Via library


## Install

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

The `max_result_constraint` variable can be set to limit the number of results the `threatfox` CLI tool will return for any given instruction. Otherwise, as many results as ThreatFox has for any given query will be returned. This only applies to API calls with a limit parameter.

```
max_result_constraint = 1000
```

## CLI Tool

```console
$ threatfox -h
usage: threatfox [-h] [-d] [--api-key API_KEY] [--save-api-key SAVE_API_KEY] {ioc,i,malware,m,tag,submit} ...

Tool for interacting with the ThreatFox API.

positional arguments:
  {ioc,i,malware,m,tag,submit}
    ioc (i)             ThreatFox IOC API interface.
    malware (m)         Interact with ThreatFox Malware APIs.
    tag                 ThreatFox tag operations.
    submit              Submit IOCs to ThreatFox.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Turn on debug logging.
  --api-key API_KEY     An ThreatFox API key to use.
  --save-api-key SAVE_API_KEY
                        Save an ThreatFox API key to use as the default. WARNING: not securely stored.
```