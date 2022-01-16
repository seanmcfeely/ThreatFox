"""CLI functions.
"""

import asyncio
import argparse
import coloredlogs
import logging
import sys
import json

from threatfox import ThreatFoxClient
from threatfox.config import save_api_key, get_api_key, get_max_result_contraint

LOGGER = logging.getLogger("threatfox.cli")


def build_parser(parser: argparse.ArgumentParser):
    """Build the CLI Argument parser."""

    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Turn on debug logging.")
    parser.add_argument(
        "--api-key",
        action="store",
        help="An ThreatFox API key to use.",
        default=None,
    )
    parser.add_argument(
        "--save-api-key",
        action="store",
        help="Save an ThreatFox API key to use as the default.",
    )

    subparsers = parser.add_subparsers(dest="command")

    ioc_parser = subparsers.add_parser("ioc", aliases=["i"], help="ThreatFox IOC API interface.")
    ioc_parser.add_argument(
        "-i",
        "--ioc-id",
        action="store",
        help="Get and IOC with this ID.",
        default=None,
    )
    ioc_parser.add_argument(
        "-s",
        "--search-ioc",
        action="store",
        help="Search for an IOC with this value.",
        default=None,
    )
    ioc_parser.add_argument(
        "-sh",
        "--search-hash",
        action="store",
        help="Search for IOCs with an association to this SHA256 or MD5 hash.",
        default=None,
    )
    ioc_parser.add_argument(
        "-t",
        "--get-ioc-types",
        action="store_true",
        help="Get the supported IOC / threat types from ThreatFox.",
        default=None,
    )
    ioc_parser.add_argument(
        "-b",
        "--bulk-day-filter-iocs",
        action="store",
        type=int,
        help="Number of days to filter ThreatFox IOCs for. Based on ThreatFox's first_seen time.",
        default=None,
    )
    ioc_parser.add_argument(
        "--get-all-available-iocs",
        action="store_true",
        help="Get the entire IOC dataset currently available from ThreatFox.",
        default=None,
    )

    # malware APIs
    malware_parser = subparsers.add_parser("malware", aliases=["m"], help="Interact with ThreatFox Malware APIs.")
    malware_parser.add_argument(
        "-q",
        "--query-malware",
        action="store",
        help="Search for ThreatFox IOCs associated with a certain malware family.",
        default=None,
    )
    malware_parser.add_argument(
        "-s",
        "--search-malware-families",
        action="store",
        help="Search for malware names by name/alias/label",
        default=None,
    )
    malware_parser.add_argument(
        "-g",
        "--get-malware-list",
        action="store_true",
        help="Get the list of supported malware families.",
        default=None,
    )

    # Tags
    tag_parser = subparsers.add_parser("tag", aliases=["t"], help="ThreatFox tag operations.")
    tag_parser.add_argument(
        "-t",
        "--query-tag",
        action="store",
        help="Search ThreatFox for IOCs associated with this tag.",
        default=None,
    )
    tag_parser.add_argument(
        "-l",
        "--get-tag-list",
        action="store_true",
        help="Get the list of tags known to ThreatFox.",
        default=None,
    )

    # Submit IOCs
    submit_parser = subparsers.add_parser("submit", aliases=["s"], help="Submit IOCs to ThreatFox.")
    submit_parser.add_argument(
        "-tt",
        "--threat-type",
        required=True,
        action="store",
        help="Threat type.",
        default=None,
    )
    submit_parser.add_argument(
        "-it",
        "--ioc-type",
        required=True,
        action="store",
        help="IOC type.",
        default=None,
    )
    submit_parser.add_argument(
        "-m",
        "--malware",
        required=True,
        action="store",
        help="Correctly mapped Malpedia malware name.",
        default=None,
    )
    submit_parser.add_argument(
        "-i",
        "--ioc-value",
        dest="iocs",
        required=True,
        action="append",
        help="IOC values. Use as many times as you need.",
        default=[],
    )
    submit_parser.add_argument(
        "-cl",
        "--confidence-level",
        action="store",
        default=50,
        type=int,
        help="Confidence level 0-100. Default: 50",
    )
    submit_parser.add_argument(
        "-r",
        "--reference",
        action="store",
        default=None,
        help="A reference (url).",
    )
    submit_parser.add_argument(
        "-t",
        "--tag",
        dest="tags",
        action="append",
        help="Tags. Use as many times as you need.",
        default=[],
    )
    submit_parser.add_argument(
        "-c",
        "--comment",
        action="store",
        default=None,
        help="Your comment on the IOCs.",
    )
    submit_parser.add_argument(
        "-ma",
        "--make-anonymous",
        dest="anonymous",
        action="store_true",
        default=False,
        help="Use this flag if you want to make your submission anonymous.",
    )


async def execute(args: argparse.Namespace):
    """Execute arguments."""

    if args.debug:
        coloredlogs.install(level="DEBUG", logger=LOGGER)

    if args.save_api_key:
        return save_api_key(args.save_api_key)

    async with ThreatFoxClient(api_key=args.api_key) as tfc:

        if args.command == "malware":
            if args.query_malware:
                results = await tfc.query_malware_iocs(malware=args.query_malware, limit=1000)
                print(json.dumps(results, indent=2))
                return

            if args.search_malware_families:
                results = await tfc.search_malware_families(malware=args.search_malware_families)
                print(json.dumps(results, indent=2))
                return

            if args.get_malware_list:
                results = await tfc.get_malware_list()
                print(json.dumps(results, indent=2))
                return

        if args.command == "ioc":
            if args.ioc_id:
                results = await tfc.get_ioc_by_id(ioc_id=args.ioc_id)
                print(json.dumps(results, indent=2))
                return
            if args.search_ioc:
                results = await tfc.search_ioc(search_term=args.search_ioc)
                print(json.dumps(results, indent=2))
                return
            if args.search_hash:
                results = await tfc.search_hash(hash=args.search_hash)
                print(json.dumps(results, indent=2))
                return
            if args.get_ioc_types:
                results = await tfc.get_ioc_threat_types()
                print(json.dumps(results, indent=2))
                return
            if args.bulk_day_filter_iocs:
                results = await tfc.get_iocs(days=args.bulk_day_filter_iocs)
                print(json.dumps(results, indent=2))
                return
            if args.get_all_available_iocs:
                results = await tfc.get_iocs(s)
                print(json.dumps(results, indent=2))
                return
            if args.query_malware:
                results = await tfc.query_malware_iocs(malware=args.query_malware_iocs, limit=1000)
                print(json.dumps(results, indent=2))
                return

        if args.command == "tag":
            if args.query_tag:
                results = await tfc.query_tag(tag=args.query_tag, limit=1000)
                print(json.dumps(results, indent=2))
                return
            if args.get_tag_list:
                results = await tfc.get_tag_list()
                print(json.dumps(results, indent=2))
                return

        if args.command == "submit":
            results = await tfc.submit_iocs(
                threat_type=args.threat_type,
                ioc_type=args.ioc_type,
                malware=args.malware,
                iocs=args.iocs,
                confidence_level=args.confidence_level,
                reference=args.reference,
                tags=args.tags,
                comment=args.comment,
                anonymous=1 if args.anonymous else 0,
            )
            print(json.dumps(results, indent=2))
            return

    return


def main(args=None):
    """The main CLI entry point."""

    # configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - [%(levelname)s] %(message)s")
    coloredlogs.install(level="INFO", logger=LOGGER)

    if not args:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Tool for interacting with the ThreatFox API.")
    build_parser(parser)
    args = parser.parse_args(args)

    asyncio.run(execute(args))
