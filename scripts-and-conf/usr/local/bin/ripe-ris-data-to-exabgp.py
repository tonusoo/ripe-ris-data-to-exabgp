#!/usr/bin/env python3

"""Dynamic BGP feed from RIPE RIS MRT files and RIS Live API.

Script subscribes to a BGP feed from a BGP neighbor of the
RIS(Routing Information Service) RRC(Remote Route Collector).
It also reads the entries for that BGP neighbor from the RIS
dump and BGP messages from updates files. Entries from the
dump file are used to build the ExaBGP configuration file.
Running the ExaBGP daemon is orchestrated by the script.
BGP messages from the updates files are pushed to ExaBGP
using its API. Finally, both queued and new real-time
messages from the RIPE RIS Live API are pushed to ExaBGP via
the API.

Script is meant to be run as a systemd "Type=simple" service.

Script has several expectations like:

    * /usr/sbin/exabgp binary installed and
      bgpkit-parser version 0.11.0 or newer in PATH

    * BIRD version 3.x running in the same host

    * Scapy module with https://github.com/secdev/scapy/pull/4745
      patch installed

    * Python 3.13 or newer

"""

import asyncio
import configparser
import json
import logging
import os
import re
import shutil
import signal
import sys
import tempfile
from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from json import JSONDecodeError
from logging.handlers import SysLogHandler
from textwrap import dedent
from types import FrameType
from typing import Any, NotRequired, Optional, TypedDict, cast

import aiofiles
import aiohttp
import websockets
from lxml.html import fromstring
from websockets import ConnectionClosedError

from scapy.config import conf

logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.contrib.bgp import BGPHeader, BGPUpdate

# Type aliases.
type Qdata = asyncio.Queue[dict[str, Any]]


class RouteEntry(TypedDict):
    """Describes a MRT file entry converted to ExaBGP static route syntax."""

    timestamp: float | None
    type: str
    data: list[str]


class Announcement(TypedDict):
    """Describes announced prefixes and their associated next hop."""

    next_hop: str
    prefixes: list[str]


# Based on RIPE RIS Live manual(https://ris-live.ripe.net/manual/).
class RISMessage(TypedDict):
    """Describes a BGP update message from RIPE RIS Live."""

    timestamp: float
    peer: str
    peer_asn: str
    id: str
    host: str
    type: str
    path: NotRequired[list[int | list[int]]]
    community: NotRequired[list[tuple[int, int]]]
    announcements: NotRequired[list[Announcement]]
    withdrawals: NotRequired[list[str]]
    origin: NotRequired[str]
    med: NotRequired[int]
    aggregator: NotRequired[str]
    raw: str


@dataclass
class Config:
    """Configuration variables."""

    rrc_name: str
    rrc_peer_ip: str
    asn: int
    listening_port: int
    replace_asn: int | None = None
    replace_nh: str | None = None

    def validate(self) -> None:
        """Validates and normalizes configuration values.

        Raises:
            ValueError: Configuration option has an invalid value.
        """

        if re.match(r"rrc[0-9]{2}$", self.rrc_name, re.IGNORECASE):
            self.rrc_name = self.rrc_name.lower()
        else:
            logging.error(
                f'"{self.rrc_name}" is an invalid route collector name.'
            )
            raise ValueError

        try:
            self.rrc_peer_ip = ip_address(self.rrc_peer_ip).compressed
        except ValueError:
            logging.error(
                f'"rrc_peer_ip" value of "{self.rrc_peer_ip}" is '
                "not a valid IP address."
            )
            raise

        if self.asn < 1 or self.asn > (2**32 - 1):

            logging.error(
                f'"asn" value of "{self.asn}" is not a valid AS number.'
            )
            raise ValueError

        if self.listening_port < 1 or self.listening_port > (2**16 - 1):

            logging.error(
                f'"listening_port" value of "{self.listening_port}" is '
                "not a valid TCP port number."
            )
            raise ValueError

        if self.replace_asn is not None:

            if self.replace_asn < 1 or self.replace_asn > (2**32 - 1):
                logging.error(
                    f'"replace_asn" value of "{self.replace_asn}" is '
                    "not a valid AS number."
                )
                raise ValueError

        if self.replace_nh is not None:

            try:
                self.replace_nh = ip_address(self.replace_nh).compressed
            except ValueError:
                logging.error(
                    f'"replace_nh" value of "{self.replace_nh}" is '
                    "not a valid IP address."
                )
                raise

            if type(ip_address(self.replace_nh)) is not type(
                ip_address(self.rrc_peer_ip)
            ):
                logging.error(
                    '"replace_nh" and "rrc_peer_ip" have different IP '
                    f"versions: {self.replace_nh} vs {self.rrc_peer_ip}"
                )
                raise ValueError


def process_config(conf_file: str) -> Config:
    """Processes configuration options.

    Args:
        conf_file: Path to the configuration file.

    Returns:
        Config object.

    Raises:
        OSError: Error opening the conf file.

        configparser.Error: Error parsing the conf file.

        KeyError: Mandatory configuration option is missing.

        ValueError: Configuration option has an invalid value.
    """

    config = configparser.ConfigParser()

    try:
        with open(conf_file, encoding="utf-8") as conf_f:
            try:
                config.read_file(conf_f)
            except configparser.Error as err:
                logging.error(f'Error parsing "{conf_file}": {err.message!r}')
                raise
    except OSError as err:
        logging.error(f'Unable to open config file "{conf_file}": {err!r}')
        raise

    logging.info(f'Processing the conf file named "{conf_file}"')

    try:
        rrc_name = config["ris"]["rrc_name"]
    except KeyError:
        logging.error(
            '"rrc_name" configuration option under "ris" section '
            "is missing."
        )
        raise

    try:
        rrc_peer_ip = config["ris"]["rrc_peer_ip"]
    except KeyError:
        logging.error(
            '"rrc_peer_ip" configuration option under "ris" section '
            "is missing."
        )
        raise

    if config.has_option("exabgp", "asn"):
        try:
            asn = config.getint("exabgp", "asn")
        except ValueError:
            logging.error(
                '"asn" configuration option under "exabgp" '
                "must be an integer."
            )
            raise
    else:
        logging.error(
            '"asn" configuration option under "exabgp" section is missing."'
        )
        raise KeyError

    if config.has_option("exabgp", "listening_port"):
        try:
            listening_port = config.getint("exabgp", "listening_port")
        except ValueError:
            logging.error(
                '"listening_port" configuration option under "exabgp" '
                "must be an integer."
            )
            raise
    else:
        logging.error(
            '"listening_port" configuration option under "exabgp" section '
            "is missing."
        )
        raise KeyError

    if config.has_option("exabgp", "replace_asn"):
        try:
            replace_asn = config.getint("exabgp", "replace_asn")
        except ValueError:
            logging.error(
                '"replace_asn" configuration option under "exabgp" '
                "must be an integer."
            )
            raise
    else:
        logging.info(
            '"replace_asn" configuration option under "exabgp" section '
            "is missing. Do not overwrite the leftmost ASN or ASNs in AS "
            "path and do not modify the communities."
        )
        replace_asn = None

    try:
        replace_nh = config["exabgp"]["replace_nh"]
    except KeyError:
        logging.info(
            '"replace_nh" configuration option under "exabgp" section '
            "is missing. Do not overwrite next-hop."
        )
        replace_nh = None

    return Config(
        rrc_name=rrc_name,
        rrc_peer_ip=rrc_peer_ip,
        asn=asn,
        listening_port=listening_port,
        replace_asn=replace_asn,
        replace_nh=replace_nh,
    )


async def ris_live_listener(
    script_name: str, rrc_name: str, rrc_peer_ip: str, queue: Qdata
) -> None:
    """Endless loop receiving and queueing RIS Live BGP messages.

    Subscribes to RIS Live API BGP UPDATE messages feed and
    queues parsed JSON messages. Any exception causes
    coroutine to reconnect to RIS Live API.

    Args:
        script_name: Identifier of the application for the
            RIPE RIS Live API.

        rrc_name: Selects messages from the given RIS route
            collector.

        rrc_peer_ip: Selects messages from the given RIS
            route collector peer.

        queue: Asyncio FIFO queue for storing the received
            RIS Live BGP messages.
    """

    url = f"wss://ris-live.ripe.net/v1/ws/?client={script_name}"

    while True:
        try:
            logging.info(
                f"Subscribing to stream from {rrc_peer_ip} on {rrc_name}"
            )
            async with websockets.connect(url) as ws:

                params = {
                    "type": "UPDATE",
                    "host": rrc_name,
                    "peer": rrc_peer_ip,
                    "socketOptions": {"includeRaw": True, "acknowledge": True},
                }

                await ws.send(
                    json.dumps({"type": "ris_subscribe", "data": params})
                )

                ack_message = await asyncio.wait_for(ws.recv(), timeout=5)
                parsed_ack = json.loads(ack_message)

                if parsed_ack.get("type") != "ris_subscribe_ok":
                    raise RuntimeError(
                        'Subscription failed. "ris_subscribe_ok" message '
                        "from server not received."
                    )

                logging.info("Server acknowledged subscription.")

                async for message in ws:
                    parsed = json.loads(message)

                    if parsed.get("type") == "ris_error":
                        error_msg = parsed.get("data", {}).get("message", "")
                        raise RuntimeError(
                            f'Server sent "ris_error" message: {error_msg}'
                        )

                    if parsed.get("type") == "ris_message":
                        await queue.put(parsed)

        except ConnectionClosedError as err:
            logging.error(
                "WebSocket connection terminated with an error. "
                f"Status code: {err.code}"
            )

            # Based on websockets exceptions.py.
            logging.debug(
                f"ConnectionClosedError: code={err.code}, "
                f"rcvd.code={getattr(err.rcvd, "code", None)}, "
                f"rcvd.reason={getattr(err.rcvd, "reason", None)}, "
                f"sent.code={getattr(err.sent, "code", None)}, "
                f"sent.reason={getattr(err.sent, "reason", None)}, "
                f"rcvd_then_sent={err.rcvd_then_sent}"
            )

        # pylint: disable-next=broad-except
        except Exception as err:
            logging.error(f"{err!r}")

        logging.info("Sleeping for 10 seconds")
        await asyncio.sleep(10)


async def shutdown_wrapper[T](
    awaitable: Coroutine[None, None, T], stop_event: asyncio.Event
) -> T:
    """Runs a coroutine with support for external shutdown signaling.

    Waits for either the coroutine to complete or for the stop_event
    to be set. If the stop_event is set first, the coroutine is cancelled
    and the cancellation is propagated.

    Args:
        awaitable: A coroutine to be run and monitored.

        stop_event: An asyncio.Event that signals when the coroutine
            should be cancelled.

    Returns:
        The result of the awaitable if it completes before the stop_event.

    Raises:
        asyncio.CancelledError: stop_event was triggered before the
            awaitable completed.
    """

    main_task = asyncio.create_task(awaitable)
    stop_task = asyncio.create_task(stop_event.wait())

    finished, _unfinished = await asyncio.wait(
        [main_task, stop_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    if stop_task in finished:
        # stop_task finished first.
        # Signal and wait the main_task to cancel.
        main_task.cancel()
        try:
            await main_task
        # Propagate the cancellation explicitly.
        # pylint: disable=try-except-raise
        except asyncio.CancelledError:
            raise

    # It was the main_task which finished first.
    # Cancel the stop_task.
    stop_task.cancel()
    return await main_task


async def download_files(temp_dir: str, base_url: str, files: str | list[str]):
    """Downloads one or more files and saves them to a temp directory.

    Establishes a persistent HTTP session to efficiently download
    files and writes them in chunks to the specified directory.

    Args:
        temp_dir: Path to the directory where the downloaded
            files will be saved.

        base_url: Base URL to prepend to each filename when
            constructing download URLs.

        files: A single filename or a list of filenames to download.

    Raises:
        aiohttp.ClientError: General client-side HTTP exception.

        OSError: Writing a file to disk failed.
    """

    if isinstance(files, str):
        files = [files]

    # Establish a HTTP persistent connection, that is, reuse the
    # same TCP and TLS session for all the requests.
    async with aiohttp.ClientSession() as session:

        for file in files:

            url = f"{base_url}{file}"
            logging.info(f"Downloading {url}")

            try:
                async with session.get(url) as resp:

                    if resp.status != 200:
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                        )

                    file_path = os.path.join(temp_dir, file)
                    logging.info(f"Writing to {file_path}")

                    # Write in chunks.
                    try:
                        with open(file_path, "wb") as file_object:
                            async for chunk in resp.content.iter_chunked(
                                2**20
                            ):
                                file_object.write(chunk)

                    except OSError as err:
                        logging.error(f'File "{file}" write error: {err!r}')
                        raise

            except aiohttp.ClientError as err:
                logging.error(f"Client error: {err!r}")
                raise


def process_as_path(
    as_path: list[dict | int | list[int]], replace_asn: int | None
) -> tuple[int | None, str]:
    """Normalizes and formats an AS path for use in ExaBGP route definitions.

    Processes a BGP AS path returned by bgpkit-parser or RIS
    Live API, performs optional substitution of the leftmost
    ASN with a replacement value, and returns the BGP AS path
    in ExaBGP-compatible syntax.

    Args:
        as_path: A list representing the AS path, possibly containing
            integers, lists of integers (AS_SETs), or dictionaries
            indicating AS path segments in verbose format.

        replace_asn: ASN to substitute for the leftmost ASN in the
            AS path. If None, no replacement is applied.

    Returns:
        A tuple consisting of the leftmost ASN in the original
        path (or None if not found) and a string representation
        of the AS path in ExaBGP-compatible syntax, with AS_SETs
        enclosed in parentheses.
    """

    # "normalized_as_path" list will contain either integers
    # or lists of integers which represent AS_SETs.
    # Multiple AS_SETs, non-contiguous AS number repetition, etc
    # are allowed, that is, be liberal in what you accept.
    normalized_as_path: list[int | list[int]] = []

    for item in as_path:

        if isinstance(item, dict):

            # On rare occasions, the bgpkit-parser is not able to
            # serialize the AS_PATH in simplified format and
            # uses verbose format. According to source code of
            # the bgpkit-parser, this happens when confederation
            # segments are present, or multiple sequences occur
            # back to back. In verbose format, segments are explicitly
            # separated and labeled.
            # "AS_CONFED_SEQUENCE" and "AS_CONFED_SET" should never
            # be received by the RIS route collectors and can be ignored.
            # RFC 5065: "A BGP speaker MUST NOT transmit updates
            # containing AS_CONFED_SET or AS_CONFED_SEQUENCE attributes
            # to peers that are not members of the local confederation."
            match item.get("ty"):
                case "AS_SEQUENCE":
                    normalized_as_path.extend(item.get("values", []))
                case "AS_SET":
                    normalized_as_path.append(item.get("values", []))

        elif isinstance(item, (list, int)):

            normalized_as_path.append(item)

    # First AS path segment should always be AS_SEQUENCE in case of
    # eBGP with at least one AS number, but sanity check. RFC 4271 5.1.2.
    leftmost_asn = (
        normalized_as_path[0]
        if normalized_as_path and isinstance(normalized_as_path[0], int)
        else None
    )

    updated_as_path: list[int | list[int]] = []

    if leftmost_asn is not None and replace_asn is not None:

        for item in normalized_as_path:

            if isinstance(item, int):

                item = replace_asn if item == leftmost_asn else item
                updated_as_path.append(item)

            elif isinstance(item, list):
                item = [
                    replace_asn if set_member == leftmost_asn else set_member
                    for set_member in item
                ]
                updated_as_path.append(item)

    else:

        updated_as_path = normalized_as_path

    formatted_as_path = []
    for item in updated_as_path:

        if isinstance(item, list):
            # https://github.com/Exa-Networks/exabgp/issues/1032
            formatted_as_path.append(f"( {" ".join(map(str, item))} )")

        elif isinstance(item, int):
            formatted_as_path.append(str(item))

    return leftmost_asn, f"[{" ".join(formatted_as_path)}]"


def format_sc(
    communities: list[str | dict],
    leftmost_asn: int | None,
    replace_asn: int | None,
) -> str:
    """Formats BGP standard communities into ExaBGP-compatible syntax.

    Processes a list of BGP standard communities into ExaBGP syntax.
    Optionally replaces the global administrator portion of communities
    if it matches the leftmost ASN and the replacement ASN is specified.

    Args:
        communities: A list of BGP community values, either as strings
            (well-known) or dictionaries.

        leftmost_asn: ASN to match for optional substitution.

        replace_asn: ASN to use as replacement for global_admin.

    Returns:
        A string in ExaBGP-compatible format, such as "community
        [13537:666 23815:0 65535:666 no-export]" or an empty string
        if no valid communities are found.
    """

    sc_list = []

    # RFC 1997 "Well-known Communities"
    well_known_communities = {
        "NoExport": "no-export",
        "NoAdvertise": "no-advertise",
        "NoExportSubConfed": "no-export-sub-confed",
    }

    for community in communities:

        # Only the well-known communities defined in
        # RFC 1997 are represented as strings by
        # bgpkit-parser. For example GRACEFUL_SHUTDOWN
        # (RFC 8326) or BLACKHOLE(RFC 7999) well-
        # known communities are not represented as strings.
        if isinstance(community, str):

            if community in well_known_communities:
                sc_list.append(well_known_communities[community])

        elif isinstance(community, dict):

            if "Custom" in community:

                global_admin, local_data = community["Custom"]

                if global_admin == leftmost_asn:
                    if replace_asn is not None and replace_asn < 2**16:
                        global_admin = replace_asn

                sc_list.append(":".join(map(str, [global_admin, local_data])))

    return f"community [{" ".join(sc_list)}]" if sc_list else ""


def format_ec(
    communities: list[str | dict],
    leftmost_asn: int | None,
    replace_asn: int | None,
) -> str:
    """Formats BGP extended communities into ExaBGP-compatible syntax.

    Processes a list of BGP extended communities into ExaBGP syntax.
    Optionally replaces the global administrator portion of communities
    for certain extended community types if the global administrator
    field matches the leftmost ASN and the replacement ASN is specified.

    Args:
        communities: A list of BGP extended community values.

        leftmost_asn: ASN to match for optional substitution.

        replace_asn: ASN to use as replacement.

    Returns:
        A string in ExaBGP-compatible format, such as
        "extended-community [0x0005000056370200 0x8000000000000500]"
        or an empty string if no valid communities are found.
    """

    ec_list = []

    # RFC 4360 "Two-Octet AS Specific Extended Community"
    ecas2 = {
        "TransitiveTwoOctetAs": "0x00",
        "NonTransitiveTwoOctetAs": "0x40",
    }

    # RFC 5668 "4-Octet AS Specific Extended Community"
    ecas4 = {
        "TransitiveFourOctetAs": "0x02",
        "NonTransitiveFourOctetAs": "0x42",
    }

    # RFC 4360 "IPv4 Address Specific Extended Community"
    ecv4 = {
        "TransitiveIpv4Addr": "0x01",
        "NonTransitiveIpv4Addr": "0x41",
    }

    # RFC 4360 "Opaque Extended Community"
    ecop = {
        "TransitiveOpaque": "0x03",
        "NonTransitiveOpaque": "0x43",
    }

    for community in communities:

        if not isinstance(community, dict):
            continue

        for community_type, community_value in community.items():

            if community_type == "community_type" and community_value in ecas2:
                # RFC 5701 "IPv6 Address Specific Extended Community"
                #
                # bgpkit-parser displays those in JSON output as:
                #
                # {
                #   "community_type": "TransitiveTwoOctetAs",
                #   "global_admin": "2001:db8:1234:5678:1234:5678:8888:9999",
                #   "local_admin": [
                #     17,
                #     103
                #   ],
                #   "subtype": 3
                # }
                #
                # "IPv6 Address Specific Extended Community"
                # shares the same 0x00 or 0x40 first high-order octet
                # as "Two-Octet AS Specific Extended Community".
                #
                # As ExaBGP does not support IPv6 Address Specific extended
                # communities for static routes, then ignore those.

                local_admin = "".join(
                    f"{num:02x}" for num in community["local_admin"]
                )

                # Display the Local Administrator value as an int similarly
                # to Junos.
                logging.warning(
                    f"Ignoring IPv6 Address Specific Extended community: "
                    f"{ecas2.get(community_value)}:"
                    f"0x{community["subtype"]:02x}:"
                    f"<{community["global_admin"]}>:"
                    f"{int(local_admin, 16)}"
                )
                continue

            if community_type in ecas2:

                if community_value["global_admin"] == leftmost_asn:
                    if replace_asn is not None and replace_asn < 2**16:
                        community_value["global_admin"] = replace_asn

                ec_list.append(
                    f"{ecas2[community_type]}"
                    f"{community_value["subtype"]:02x}"
                    f"{community_value["global_admin"]:04x}"
                    f"{"".join(
                        f"{num:02x}"
                        for num in community_value["local_admin"]
                    )}"
                )

            elif community_type in ecas4:

                if community_value["global_admin"] == leftmost_asn:
                    if replace_asn is not None:
                        community_value["global_admin"] = replace_asn

                ec_list.append(
                    f"{ecas4[community_type]}"
                    f"{community_value["subtype"]:02x}"
                    f"{community_value["global_admin"]:08x}"
                    f"{"".join(
                        f"{num:02x}"
                        for num in community_value["local_admin"]
                    )}"
                )

            elif community_type in ecv4:
                ec_list.append(
                    f"{ecv4[community_type]}"
                    f"{community_value["subtype"]:02x}"
                    f"{IPv4Address(community_value["global_admin"]):x}"
                    f"{"".join(
                        f"{num:02x}"
                        for num in community_value["local_admin"]
                    )}"
                )

            elif community_type in ecop:
                ec_list.append(
                    f"{ecop[community_type]}"
                    f"{community_value["subtype"]:02x}"
                    f"{"".join(
                        f"{num:02x}" for num in community_value["value"]
                    )}"
                )

            elif community_type == "Raw":
                # Unknown extended community.
                ec_list.append(
                    f"0x{"".join(
                        f"{num:02x}" for num in community_value
                    )}"
                )

    return f"extended-community [{" ".join(ec_list)}]" if ec_list else ""


def format_lc(
    communities: list[str | dict],
    leftmost_asn: int | None,
    replace_asn: int | None,
) -> str:
    """Formats BGP large communities into ExaBGP-compatible syntax.

    Processes a list of BGP large communities into ExaBGP syntax.
    Optionally replaces the global administrator field if it matches
    the leftmost ASN and the replacement ASN is specified.

    Args:
        communities: List of BGP large communities.

        leftmost_asn: ASN to match for optional substitution.

        replace_asn: ASN to use as replacement for global_admin.

    Returns:
        A string in ExaBGP-compatible format, such as
        "large-community [215304:3000:0 215304:28521:0]"
        or an empty string if no valid communities are found.
    """

    lc_list = []

    for community in communities:

        # Sanity check.
        if not isinstance(community, dict):
            continue

        if "global_admin" in community and "local_data" in community:

            if community["global_admin"] == leftmost_asn:
                if replace_asn is not None:
                    community["global_admin"] = replace_asn

            lc_list.append(
                f"{community["global_admin"]}:"
                f"{":".join(map(str, community["local_data"]))}"
            )

    return f"large-community [{" ".join(lc_list)}]" if lc_list else ""


def process_record(
    entry: dict[str, Any], replace_asn: int | None, replace_nh: str | None
) -> RouteEntry:
    """Converts a parsed MRT entry into an ExaBGP static route definition.

    Parses a single BGP record (JSON object extracted from a MRT file)
    and constructs a static route statement compatible with ExaBGP.
    Supports optional replacement of the leftmost ASN and the next-hop
    IP address.

    Args:
        entry: A dictionary representing a BGP message entry, parsed
            from a MRT file.

        replace_asn: ASN to substitute for the leftmost ASN in the AS
            path. If None, no replacement is applied.

        replace_nh: IP address to override the original next-hop value.
            If None, uses the next_hop from the MRT entry.

    Returns: A dict containing the original timestamp of the BGP
        message, message type and a list of strings forming the
        ExaBGP static route syntax.
    """

    route_entry: RouteEntry = {
        "timestamp": None,
        "type": "",
        "data": [],
    }
    leftmost_asn = None

    route_entry["timestamp"] = entry.get("timestamp") or None
    route_entry["type"] = entry.get("type") or ""

    route_entry["data"].append(f"route {entry.get("prefix")}")

    if entry.get("type") == "WITHDRAW":
        # Prefix is enough for withdrawing the route.
        return route_entry

    # Well-known mandatory ORIGIN attribute should always exist,
    # but even if it's missing, then it's automatically set by ExaBGP.
    if entry.get("origin"):
        route_entry["data"].append(f"origin {entry.get("origin")}")

    as_path = entry.get("as_path")

    # The AS-path field should never be empty, but there are
    # at least few historical records where this is true. For
    # example, an entry for 84.205.82.0/24 in bview.20081001.2359.gz
    # of RRC02. If the AS-path field is empty, then ignore the empty
    # list returned by bgpkit-parser.
    if isinstance(as_path, list) and as_path:
        leftmost_asn, as_path_str = process_as_path(as_path, replace_asn)
        route_entry["data"].append(f"as-path {as_path_str}")

    # "local_pref" attribute is ignored. All the RIPE RIS peers
    # connect to route collectors via eBGP session and thus none
    # of the entries have the LOCAL_PREF set.

    route_entry["data"].append(
        f"med {entry.get("med")}" if entry.get("med") else "med 0"
    )

    if entry.get("atomic"):
        route_entry["data"].append("atomic-aggregate")

    if entry.get("aggr_asn") and entry.get("aggr_ip"):
        route_entry["data"].append(
            f"aggregator ({entry.get("aggr_asn")}:{entry.get("aggr_ip")})"
        )

    communities = entry.get("communities")

    if isinstance(communities, list) and communities:
        route_entry["data"].append(
            f"{format_sc(communities, leftmost_asn, replace_asn)}"
        )
        route_entry["data"].append(
            f"{format_ec(communities, leftmost_asn, replace_asn)}"
        )
        route_entry["data"].append(
            f"{format_lc(communities, leftmost_asn, replace_asn)}"
        )

    if entry.get("only_to_customer"):
        # OTC is not supported by ExaBGP for static routes.
        logging.warning(
            f"Ignoring OTC attribute {entry.get("only_to_customer")} "
            f"for prefix {entry.get("prefix")}"
        )

    if replace_nh is not None:
        route_entry["data"].append(f"next-hop {replace_nh}")

    elif entry.get("next_hop"):
        route_entry["data"].append(f"next-hop {entry.get("next_hop")}")

    else:
        # "next_hop" should never be missing, but since it's a
        # mandatory attribute for ExaBGP static routes, handle this
        # condition just in case by returning an empty "route_entry"
        # data list instead of an incomplete one.
        logging.error(f"Record is missing the next-hop attribute: {entry!r}")
        route_entry["data"] = []

    return route_entry


async def build_exabgp_conf(
    temp_dir: str,
    dump_file: str,
    rrc_peer_ip: str,
    replace_asn: int | None,
    replace_nh: str | None,
    exabgp_asn: int,
) -> tuple[str, float | None]:
    """Builds an ExaBGP configuration file from a MRT dump.

    Runs bgpkit-parser as a subprocess, processes its JSON
    output, and writes an ExaBGP configuration file containing
    static route definitions. It determines the earliest BGP
    message timestamp seen, which is used later for update
    filtering.

    Args:
        temp_dir: Path to the directory where the config
            file will be written.

        dump_file: Name of the MRT dump file to process.

        rrc_peer_ip: IP address of the BGP peer used
            for filtering the entries of the MRT file.

        replace_asn: ASN to substitute for the leftmost ASN in the AS
            path. If None, no replacement is applied.

        replace_nh: IP address to override the original next-hop value.
            If None, uses the next_hop from the MRT entry.

        exabgp_asn: Local and peer ASN used in the ExaBGP configuration
            to establish an iBGP session with BIRD.

    Returns:
        A tuple containing the local address used in the ExaBGP
        config(127.0.0.1 or ::1) and the earliest BGP message
        timestamp found.

    Raises:
        FileNotFoundError: bgpkit-parser is not installed or
            not found in PATH.

        RuntimeError: Execution of the bgpkit-parser failed.
    """

    filter_type = (
        "--ipv4-only"
        if isinstance(ip_address(rrc_peer_ip), IPv4Address)
        else "--ipv6-only"
    )

    # bgpkit-parser version 0.11.0 or newer is expected.
    cmd = [
        "bgpkit-parser",
        "--json",
        filter_type,
        "--peer-ip",
        rrc_peer_ip,
        os.path.join(temp_dir, dump_file),
    ]

    exabgp_conf_file = os.path.join(temp_dir, "exabgp.conf")
    timestamp = None

    logging.info(f"Starting to build ExaBGP conf file to {exabgp_conf_file}")

    # Run bgpkit-parser and process the JSON output line by line.
    async with aiofiles.open(
        exabgp_conf_file, "w", encoding="utf-8"
    ) as file_object:

        addr = (
            "127.0.0.1"
            if isinstance(ip_address(rrc_peer_ip), IPv4Address)
            else "::1"
        )

        config = dedent(
            f"""
                neighbor {addr} {{
                    router-id 192.0.2.0;
                    local-address {addr};
                    local-as {exabgp_asn};
                    peer-as {exabgp_asn};
                    passive;

                    static {{

        """
        ).strip("\n")
        await file_object.write(config)

        await file_object.write("\n")

        logging.info(f"Executing command: {" ".join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            logging.error(f"Failed to start command: {" ".join(cmd)}")
            raise

        if proc.stdout is None:
            logging.error("Subprocess stdout is unexpectedly None")
            raise RuntimeError

        try:

            async for line in proc.stdout:

                try:

                    entry = json.loads(line.strip())

                    # While the process_record() is called thousands
                    # of times per second, then the function is
                    # short-lived(usually < 0.05 ms) and does not become
                    # blocking.
                    exabgp_route = process_record(
                        entry, replace_asn, replace_nh
                    )

                    # Sanity check.
                    if exabgp_route["type"] != "ANNOUNCE":
                        continue

                    # Sanity check.
                    if not exabgp_route["data"]:
                        continue

                    # Timestamp determines which updates files
                    # are later downloaded and which updates are
                    # converted to ExaBGP API calls.
                    #
                    # 'exabgp_route["timestamp"] < timestamp' check
                    # should be unnecessary as the timestamp of
                    # the first entry should always be the lowest.
                    #
                    # At least in the past in theory the entries
                    # in dump files could have different timestamps
                    # because RIPE RIS project used Quagga for BGP
                    # table dumps and Quagga calls gettimeofday()
                    # in bgp_dump_header() in bgp_dump.c for each
                    # route in case of RIB dump(dump bgp routes-mrt
                    # <file>). The same holds true for FRRouting.
                    if timestamp is None or (
                        exabgp_route["timestamp"] is not None
                        and exabgp_route["timestamp"] < timestamp
                    ):
                        timestamp = exabgp_route["timestamp"]

                    # Remove possible empty elements.
                    exabgp_route_data = [
                        item for item in exabgp_route["data"] if item
                    ]

                    await file_object.write(
                        f"        {" ".join(exabgp_route_data)};\n"
                    )

                except JSONDecodeError:
                    logging.warning(f"Not a valid JSON: {line!r}")
                    continue

            config = dedent(
                """
                        }
                    }
            """
            )
            await file_object.write(config)

        except asyncio.CancelledError:

            try:
                proc.terminate()
            except ProcessLookupError:
                pass

            # https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.subprocess.Process.wait
            await proc.communicate()
            raise

    return addr, timestamp


async def run_exabgp(
    temp_dir: str,
    listening_addr: str,
    listening_port: int,
    event: asyncio.Event,
) -> None:
    """Starts an ExaBGP subprocess.

    Sets up required directories and named pipes, configures environment
    variables, and launches ExaBGP in a subprocess. Signals readiness
    via the provided asyncio event.

    Args:
        temp_dir: Temporary directory for ExaBGP runtime files.

        listening_addr: IP address ExaBGP should bind to.

        listening_port: TCP port ExaBGP should listen on.

        event: Async event to signal when ExaBGP is ready.

    Raises:
        OSError: Failed to create ExaBGP named pipes or directory
            for the named pipes.

        FileNotFoundError: exabgp is not installed.

        RuntimeError: Execution of the exabgp failed.
    """

    # ExaBGP looks for named pipes(ExaBGP stdin/stdout API)
    # from a list of fixed locations. One of those locations
    # is the "run" directory under the directory specified
    # with the "--root" argument.
    # If there had been a need to keep multiple named pipes
    # associated with multiple ExaBGP processes in a single
    # directory, a unique pipe name could have been used:
    #
    # pipename = f"exabgp-{listening_port}"
    # os.putenv("exabgp_api_pipename", pipename)
    # os.mkfifo(f"/run/exabgp/{pipename}.in")
    # os.mkfifo(f"/run/exabgp/{pipename}.out")
    #
    # Default pipename is "exabgp".

    try:
        os.mkdir(os.path.join(temp_dir, "run"))
    except OSError as err:
        logging.error(f'Failed to create the ExaBGP "run" directory: {err!r}')
        event.set()
        raise

    try:
        os.mkfifo(os.path.join(temp_dir, "run/exabgp.in"))
        os.mkfifo(os.path.join(temp_dir, "run/exabgp.out"))
    except OSError as err:
        logging.error(f"Failed to create the ExaBGP named pipe: {err!r}")
        event.set()
        raise

    env_vars = {
        "exabgp_tcp_bind": listening_addr,
        "exabgp_tcp_port": listening_port,
        "exabgp_daemon_drop": "false",
    }

    for key, value in env_vars.items():
        os.putenv(key, str(value))

    # If the script was started in the non-default VRF,
    # then start the ExaBGP in the default VRF so that it
    # can communicate with BIRD, which is also running in
    # the default VRF.
    cmd = [
        "/usr/bin/ip",
        "vrf",
        "exec",
        "default",
        "/usr/sbin/exabgp",
        "--root",
        temp_dir,
        os.path.join(temp_dir, "exabgp.conf"),
    ]

    logging.info(f"Executing command: {" ".join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as err:
        logging.error(f"Failed to start command: {" ".join(cmd)}")
        event.set()
        raise

    if proc.stdout is None:
        logging.error("Subprocess stdout is unexpectedly None")
        event.set()
        raise RuntimeError

    try:
        async for line in proc.stdout:

            decoded_line = line.decode().strip()

            if decoded_line.endswith("loaded new configuration successfully"):
                logging.info(
                    "ExaBGP has successfully loaded its configuration"
                )
                event.set()

    except asyncio.CancelledError:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass

        await proc.communicate()


async def get_updates_file_names(
    rrc: str, timestamp: float
) -> tuple[str, list[str]]:
    """Finds the names of the updates files.

    Finds the names of the updates files from the index of the
    RIPE RIS archive. Exclude the updates files names which are
    older than the given timestamp.

    Args:
        rrc: Route collector identifier (for example, "rrc06").

        timestamp: UNIX timestamp to filter files.

    Returns:
        A tuple containing the base URL and a list of matching
        updates file names.

    Raises:
        aiohttp.ClientError: General client-side HTTP exception.
    """

    # The updates file names may not be in 5-minute increments.
    # For example:
    # https://data.ris.ripe.net/rrc01/2017.11/updates.20171120.1616.gz
    # https://data.ris.ripe.net/rrc13/2018.02/updates.20180227.0137.gz
    #
    # Therefore, fetch the files index for the month and download all
    # updates*.gz files that are newer than the given timestamp.

    file_names: list[str] = []
    dt = datetime.fromtimestamp(timestamp, UTC)
    base_file_name = dt.strftime("updates.%Y%m%d.%H%M.gz")
    month = dt.strftime("%Y.%m")

    url = f"https://data.ris.ripe.net/{rrc}/{month}/"
    logging.info(f"Downloading {url}")

    async with aiohttp.ClientSession() as session:

        try:
            async with session.get(url) as resp:

                if resp.status != 200:
                    raise aiohttp.ClientResponseError(
                        request_info=resp.request_info,
                        history=resp.history,
                        status=resp.status,
                    )

                html_content = await resp.text()

        except aiohttp.ClientError as err:
            logging.error(f"HTTP error: {err!r}")
            raise

    parsed_html = fromstring(html_content)

    # Fetch all the href attributes of anchor elements
    # starting with "updates." string.
    # cast() helps mypy to understand that xpath() will
    # return a list of strings.
    file_names = cast(
        list[str],
        parsed_html.xpath('//a[starts-with(@href, "updates.")]/@href'),
    )
    file_names = [
        file_name for file_name in file_names if file_name >= base_file_name
    ]

    return url, file_names


async def get_updates(
    temp_dir: str, update_files: list[str], rrc_peer_ip: str
) -> dict[str, dict[str, Any]]:
    """Processes BGP update files and returns the latest entry per prefix.

    Uses bgpkit-parser to process update files for a specific peer IP
    and keeping only the most recent update for each prefix.

    Args:
        temp_dir: Directory containing downloaded update files.

        update_files: List of BGP update file names to process.

        rrc_peer_ip: IP address of the peer to filter updates by.

    Returns:
        A dictionary mapping prefixes to their most recent BGP entry.

    Raises:
        RuntimeError: Execution of the bgpkit-parser failed.
    """

    # Updates often have multiple entries for the
    # same prefix. For example, the prefix is withdrawn,
    # announced, again withdrawn and reannounced.
    # Process the messages in a way that only the
    # last message is converted into ExaBGP API call.
    unique_entries: dict[str, dict[str, Any]] = {}

    filter_type = (
        "--ipv4-only"
        if isinstance(ip_address(rrc_peer_ip), IPv4Address)
        else "--ipv6-only"
    )

    for update_file in update_files:

        cmd = [
            "bgpkit-parser",
            "--json",
            filter_type,
            "--peer-ip",
            rrc_peer_ip,
            os.path.join(temp_dir, update_file),
        ]

        logging.info(f"Executing command: {" ".join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        if proc.stdout is None:
            logging.error("Subprocess stdout is unexpectedly None")
            raise RuntimeError

        try:

            async for line in proc.stdout:

                try:

                    entry = json.loads(line.strip())
                    prefix = entry.get("prefix")
                    timestamp = entry.get("timestamp")

                    if (
                        prefix not in unique_entries
                        or timestamp >= unique_entries[prefix]["timestamp"]
                    ):
                        unique_entries[prefix] = entry

                except JSONDecodeError:
                    logging.warning(f"Not a valid JSON: {line!r}")
                    continue

        except asyncio.CancelledError:

            try:
                proc.terminate()
            except ProcessLookupError:
                pass

            await proc.communicate()
            raise

    return unique_entries


async def write_to_api(
    entries: dict[str, dict[str, Any]],
    replace_asn: int | None,
    replace_nh: str | None,
    api_file: str,
) -> None:
    """Writes ExaBGP route commands to a named pipe.

    Processes BGP entries from MRT files and writes
    announce/withdraw statements to the given ExaBGP
    API file.

    Args:
        entries: Mapping of prefixes to BGP entries.

        replace_asn: ASN to substitute for the leftmost ASN in the AS
            path. If None, no replacement is applied.

        replace_nh: IP address to override the original next-hop value.
            If None, uses the next_hop from the MRT entry.

        api_file: Path to the ExaBGP API.

    Raises:
        BrokenPipeError: ExaBGP has closed its named pipe.
    """

    try:
        async with aiofiles.open(
            api_file, "w", encoding="utf-8"
        ) as file_object:

            for entry in list(entries.values()):

                exabgp_route = process_record(entry, replace_asn, replace_nh)

                # Sanity check.
                if not exabgp_route["data"]:
                    continue

                # Remove possible empty elements.
                exabgp_route_data = [
                    item for item in exabgp_route["data"] if item
                ]

                logging.debug(
                    f"Writing to {api_file}: {exabgp_route["type"].lower()} "
                    f"{" ".join(exabgp_route_data)}"
                )

                if exabgp_route["type"] == "ANNOUNCE":
                    await file_object.write(
                        f"announce {" ".join(exabgp_route_data)};\n"
                    )
                    await file_object.flush()

                elif exabgp_route["type"] == "WITHDRAW":
                    await file_object.write(
                        f"withdraw {' '.join(exabgp_route_data)};\n"
                    )
                    await file_object.flush()

    except BrokenPipeError:
        logging.error(f"ExaBGP has closed its named pipe {api_file}")
        raise


def has_atomic_aggregate(bgp_update_msg: BGPUpdate) -> bool:
    """Checks if the BGP update message contains the ATOMIC_AGGREGATE attr.

    Args:
        bgp_update_msg: A decoded BGP UPDATE message.

    Returns:
        True if the ATOMIC_AGGREGATE attribute is present, False otherwise.
    """

    atomic_aggregate = False

    for attr in bgp_update_msg.path_attr:

        # ATOMIC_AGGREGATE attribute.
        if attr.type_code == 6:
            atomic_aggregate = True

    return atomic_aggregate


def get_bgp_sc(
    bgp_update_msg: BGPUpdate,
    leftmost_asn: int | None,
    replace_asn: int | None,
) -> str:
    """Formats BGP standard communities into ExaBGP-compatible syntax.

    Processes BGP standard communities into ExaBGP syntax and optionally
    replaces the global administrator portion of communities if it matches
    the leftmost ASN and the replacement ASN is specified.

    Args:
        bgp_update_msg: A decoded BGP UPDATE message.

        leftmost_asn: ASN to match for optional substitution.

        replace_asn: ASN to use as replacement for global_admin.

    Returns:
        A string in ExaBGP-compatible format, such as "community
        [13537:666 23815:0 65535:666 no-export]" or an empty
        string if no valid communities are found.
    """

    updated_sc_list = []

    for attr in bgp_update_msg.path_attr:

        # Process only standard communities.
        if attr.type_code != 8:
            continue

        # Scapy is able to decode the first community
        # to "attribute.community" and dumps the rest
        # to "attribute.load" as a byte string. Instead
        # of processing the "attribute.community" and
        # "attribute.load" separately, simply read the
        # attribute value from the path attribute, that
        # is, read the "length" or "extended length"
        # number of bytes from the end of the path
        # attribute.

        # Scapy uses "attr_len" if the fourth high-order
        # bit of the attribute flags octet is 0 or
        # "attr_ext_len" if this bit is set. RFC 4271 4.3.
        length = (
            attr.attr_len if attr.attr_len is not None else attr.attr_ext_len
        )
        data = bytes(attr)[-length:]

        # Split the byte string into four byte chunks.
        sc_bytes_list = [data[i : i + 4] for i in range(0, len(data), 4)]

        sc_list = [
            (
                int.from_bytes(comm[:2], "big"),
                int.from_bytes(comm[2:], "big"),
            )
            for comm in sc_bytes_list
        ]

        for comm in sc_list:

            global_admin, local_data = comm

            if global_admin == leftmost_asn:
                if replace_asn is not None and replace_asn < 2**16:
                    global_admin = replace_asn

            updated_sc_list.append(
                ":".join(map(str, [global_admin, local_data]))
            )

            # Convert to RFC 1997 well-known communities
            # names in order to keep the output identical
            # to format_sc().
            well_known_communities = {
                "65535:65281": "no-export",
                "65535:65282": "no-advertise",
                "65535:65283": "no-export-sub-confed",
            }
            updated_sc_list = [
                well_known_communities.get(comm, comm)
                for comm in updated_sc_list
            ]

    return (
        f"community [{" ".join(updated_sc_list)}]" if updated_sc_list else ""
    )


def get_bgp_ec(
    bgp_update_msg: BGPUpdate,
    leftmost_asn: int | None,
    replace_asn: int | None,
) -> str:
    """Formats BGP extended communities into ExaBGP-compatible syntax.

    Processes BGP extended communities into ExaBGP syntax and optionally
    replaces the global administrator portion of communities for certain
    extended community types if the global administrator field matches
    the leftmost ASN and the replacement ASN is specified.

    Args:
        bgp_update_msg: A decoded BGP UPDATE message.

        leftmost_asn: ASN to match for optional substitution.

        replace_asn: ASN to use as replacement.

    Returns:
        A string in ExaBGP-compatible format, such as
        "extended-community [0x0005000056370200 0x8000000000000500]"
        or an empty string if no valid communities are found.
    """

    ec_list = []

    # RFC 4360 "Two-Octet AS Specific Extended Community"
    ecas2 = {
        "00": "TransitiveTwoOctetAs",
        "40": "NonTransitiveTwoOctetAs",
    }

    # RFC 5668 "4-Octet AS Specific Extended Community"
    ecas4 = {
        "02": "TransitiveFourOctetAs",
        "42": "NonTransitiveFourOctetAs",
    }

    for attr in bgp_update_msg.path_attr:

        # Process only extended communities.
        if attr.type_code != 16:
            continue

        for ext_comm in attr.attribute.extended_communities:

            ext_comm_in_hex = bytes(ext_comm).hex()

            if ext_comm_in_hex[:2] in ecas2:
                # 3rd and 4th octet of the "Two-Octet AS Specific
                # Extended Community" contain the 16-bit ASN.
                if int(ext_comm_in_hex[4:8], 16) == leftmost_asn:
                    if replace_asn is not None and replace_asn < 2**16:
                        ext_comm_in_hex = (
                            f"{ext_comm_in_hex[:4]}"
                            f"{replace_asn:04x}"
                            f"{ext_comm_in_hex[8:]}"
                        )

            elif ext_comm_in_hex[:2] in ecas4:
                # 3rd, 4th, 5th and 6th octet of the "4-Octet
                # AS Specific Extended Community" contain the
                # 32-bit ASN.
                if int(ext_comm_in_hex[4:12], 16) == leftmost_asn:
                    if replace_asn is not None:
                        ext_comm_in_hex = (
                            f"{ext_comm_in_hex[:4]}"
                            f"{replace_asn:08x}"
                            f"{ext_comm_in_hex[12:]}"
                        )

            ec_list.append(f"0x{ext_comm_in_hex}")

    return f"extended-community [{" ".join(ec_list)}]" if ec_list else ""


def get_bgp_lc(
    bgp_update_msg: BGPUpdate,
    leftmost_asn: int | None,
    replace_asn: int | None,
) -> str:
    """Formats BGP large communities into ExaBGP-compatible syntax.

    Processes BGP large communities into ExaBGP syntax and optionally
    replaces the global administrator portion of communities if it matches
    the leftmost ASN and the replacement ASN is specified.

    Args:
        bgp_update_msg: A decoded BGP UPDATE message.

        leftmost_asn: ASN to match for optional substitution.

        replace_asn: ASN to use as replacement.

    Returns:
        A string in ExaBGP-compatible format, such as
        "large-community [215304:3000:0 215304:28521:0]"
        or an empty string if no valid communities are found.
    """

    updated_lc_list = []

    for attr in bgp_update_msg.path_attr:

        # Process only large communities.
        if attr.type_code != 32:
            continue

        length = (
            attr.attr_len if attr.attr_len is not None else attr.attr_ext_len
        )
        data = bytes(attr)[-length:]

        # Split the byte string into 12-byte chunks.
        lc_bytes_list = [data[i : i + 12] for i in range(0, len(data), 12)]

        # Each 12-byte large community consists of 4-byte
        # "Global Administrator", 4-byte "Local Data Part 1"
        # field and 4-byte "Local Data Part 2" field.
        lc_list = [
            (
                int.from_bytes(comm[:4], "big"),
                int.from_bytes(comm[4:8], "big"),
                int.from_bytes(comm[8:], "big"),
            )
            for comm in lc_bytes_list
        ]

        for comm in lc_list:

            global_admin, local_data_1, local_data_2 = comm

            if global_admin == leftmost_asn:
                if replace_asn is not None:
                    global_admin = replace_asn

            updated_lc_list.append(
                ":".join(map(str, [global_admin, local_data_1, local_data_2]))
            )

    return (
        f"large-community [{" ".join(updated_lc_list)}]"
        if updated_lc_list
        else ""
    )


def process_live_record(
    entry: RISMessage, replace_asn: int | None, replace_nh: str | None
) -> list[dict[str, Any]]:
    """Converts a RIS Live BGP message into ExaBGP static route format.

    Parses and normalizes a single RIS Live message, handling optional ASN
    and next-hop replacements. Supports both announcement and withdrawal
    types.

    Args:
        entry: A RIS Live BGP UPDATE message.

        replace_asn: ASN to substitute for the leftmost ASN in the AS
            path. If None, no replacement is applied.

        replace_nh: IP address to override the original next-hop value.
            If None, uses the next_hop from the RIS Live BGP message.

    Returns:
        A list of route entries in ExaBGP-compatible format.

    Raises:
        ValueError: Message decoding failed or required field was missing.
    """

    route_entries = []

    raw_msg = entry.get("raw")

    # Sanity check.
    if not isinstance(raw_msg, str):
        raise ValueError(f'Expected "raw" to be a string: {entry}')

    # Parse BGP Message
    bgp_msg = BGPHeader(bytes.fromhex(raw_msg))

    # Sanity check.
    if not isinstance(bgp_msg.payload, BGPUpdate):
        raise ValueError("Unable to decode the BGP UPDATE message.")

    # Extract BGP Update message payload.
    bgp_update_msg = bgp_msg.payload

    timestamp = entry.get("timestamp")
    origin = f"origin {entry.get("origin")}" if entry.get("origin") else ""

    path = cast(list[int | list[int] | dict[Any, Any]], entry.get("path"))
    leftmost_asn, as_path_str = process_as_path(path, replace_asn)
    as_path = f"as-path {as_path_str}"

    med = f"med {entry.get("med")}" if entry.get("med") else "med 0"

    atomic_aggregate = (
        "atomic-aggregate" if has_atomic_aggregate(bgp_update_msg) else ""
    )

    aggregator = (
        f"aggregator ({entry.get("aggregator")})"
        if entry.get("aggregator")
        else ""
    )

    sc = get_bgp_sc(bgp_update_msg, leftmost_asn, replace_asn)
    ec = get_bgp_ec(bgp_update_msg, leftmost_asn, replace_asn)
    lc = get_bgp_lc(bgp_update_msg, leftmost_asn, replace_asn)

    # Process Withdrawals
    for prefix in entry["withdrawals"]:
        route_entries.append(
            {
                "timestamp": timestamp,
                "type": "WITHDRAW",
                "data": [f"route {prefix}"],
            }
        )

    # Process Announcements
    for announcement in entry["announcements"]:

        if replace_nh is not None:
            next_hop = f"next-hop {replace_nh}"

        elif announcement.get("next_hop"):

            # In case of non-multihop collectors, the v6 announcements
            # often have both the global and link-local address listed
            # as next-hop. According to RFC 2545 the global v6 address
            # should always precede the link-local address and the RIS
            # Live API seems to keep this order, but be safe.
            # Set the v6 next-hop to first global address or fallback to
            # last address regardless of its scope. ExaBGP API accepts
            # the route with next-hop of link-local address.
            # IPv4 prefixes have a single next-hop address.
            next_hops = announcement.get("next_hop", "").split(",")

            next_hop = None

            for nh in next_hops:
                ip = ip_address(nh)
                if isinstance(ip, IPv6Address) and not ip.is_link_local:
                    next_hop = nh
                    break

            next_hop = f"next-hop {next_hop}" if next_hop is not None else ""

        else:
            # "next_hop" should never be missing or empty.
            logging.error(
                f"Record is missing the next-hop attribute: {announcement!r}"
            )
            continue

        for prefix in announcement["prefixes"]:

            raw_data = [
                f"route {prefix}",
                origin,
                as_path,
                med,
                atomic_aggregate,
                aggregator,
                sc,
                ec,
                lc,
                next_hop,
            ]

            cleaned_data = [
                item for item in raw_data if item is not None and item != ""
            ]

            route_entries.append(
                {
                    "timestamp": timestamp,
                    "type": "ANNOUNCE",
                    "data": cleaned_data,
                }
            )

    return route_entries


async def process_messages(
    queue: Qdata,
    replace_asn: int | None,
    replace_nh: str | None,
    api_file: str,
) -> None:
    """Endless loop writing RIS Live BGP messages to ExaBGP API.

    Processes BGP messages received from RIS Live API
    and writes announce/withdraw statements to the given
    ExaBGP API file.

    Args:
        queue: Asyncio FIFO queue containing the received
            RIS Live BGP messages.

        replace_asn: ASN to substitute for the leftmost ASN in the AS
            path. If None, no replacement is applied.

        replace_nh: IP address to override the original next-hop value.
            If None, uses the next_hop from the RIS Live BGP message.

        api_file: Path to the ExaBGP API.

    Raises:
        BrokenPipeError: ExaBGP has closed its named pipe.
    """

    # Occasionally, the RIS Live messages can contain
    # hundreds of NLRIs, and by default, Scapy refuses
    # to decode such messages. Increase the max_list_count
    # from 100 to 2000.
    conf.max_list_count = 2000

    try:
        async with aiofiles.open(
            api_file, "w", encoding="utf-8"
        ) as file_object:

            while True:

                parsed_msg = await queue.get()
                ris_message = parsed_msg.get("data")

                # Sanity check.
                if ris_message is None or ris_message.get("type") != "UPDATE":
                    logging.error(f"Not an UPDATE message: {parsed_msg}")
                    continue

                # process_live_record() should not become blocking.
                # Based on tests, the RIS Live messages with few
                # prefixes take around 0.001 seconds to process
                # and messages with even over thousand prefixes,
                # reaching the max message size of 4096 octets,
                # still spend less than 0.1 seconds in
                # process_live_record().
                try:
                    exabgp_routes = process_live_record(
                        ris_message, replace_asn, replace_nh
                    )
                except ValueError as err:
                    logging.warning(
                        f"Failed to decode RIPE RIS Live message: {err!r}"
                    )
                    continue

                for exabgp_route in exabgp_routes:

                    if exabgp_route["type"] == "ANNOUNCE":

                        await file_object.write(
                            f"announce {" ".join(exabgp_route["data"])};\n"
                        )
                        await file_object.flush()

                    elif exabgp_route["type"] == "WITHDRAW":

                        await file_object.write(
                            f"withdraw {" ".join(exabgp_route["data"])};\n"
                        )
                        await file_object.flush()

    except BrokenPipeError:
        logging.error(f"ExaBGP has closed its named pipe {api_file}")


async def main() -> None:
    """Main coroutine of the script.

    Calls functions and coroutines, handles possible
    exceptions and defines variables which are often
    used as arguments for the functions and coroutines.
    """

    # Script logs to syslog in order to preserve the journalctl
    # capability to filter and color the messages based on the
    # severity level.
    syslog = SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_USER)

    logging.basicConfig(
        #level=logging.DEBUG,
        level=logging.INFO,
        format="[{funcName}] - {levelname} - {message}",
        style="{",
        handlers=[syslog],
    )

    if len(sys.argv) != 2:
        logging.error(f"Usage: {sys.argv[0]} <conf_file>")
        sys.exit(1)

    try:
        cfg = process_config(sys.argv[1])
        cfg.validate()
    except (OSError, configparser.Error, ValueError, KeyError):
        sys.exit(1)

    stop_event = asyncio.Event()
    run_exabgp_signal = asyncio.Event()

    def signal_handler(sig: int, _frame: FrameType | None) -> None:
        logging.warning(f"Received signal {sig}. Initiating shutdown.")
        stop_event.set()
        run_exabgp_signal.set()

    signal.signal(signal.SIGTERM, signal_handler)

    # Systemd service for ripe-ris-data-to-exabgp.py should use
    # SIGINT as "KillSignal" because SIGTERM does not terminate
    # the ExaBGP when ExaBGP is reading in its configuration.
    signal.signal(signal.SIGINT, signal_handler)

    script_name = os.path.basename(__file__)

    try:
        temp_dir = tempfile.mkdtemp(dir="/tmp", prefix=f"{script_name}_")
    except OSError as err:
        logging.error(f"Failed to create the temporay directory: {err!r}")
        sys.exit(1)

    logging.info(f"Created temporary directory {temp_dir}")

    try:

        try:

            background_tasks = []
            queue: Qdata = asyncio.Queue()

            websocket_task = asyncio.create_task(
                ris_live_listener(
                    script_name, cfg.rrc_name, cfg.rrc_peer_ip, queue
                )
            )
            # Create a strong reference in order to avoid
            # possible garbage collection:
            # https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task
            background_tasks.append(websocket_task)

            base_url = f"https://data.ris.ripe.net/{cfg.rrc_name}/"
            dump_file = "latest-bview.gz"
            file_names: list[str] = []

            try:
                await shutdown_wrapper(
                    download_files(temp_dir, base_url, dump_file), stop_event
                )
            except (aiohttp.ClientError, OSError) as err:
                raise asyncio.CancelledError from err

            # ExaBGP supports calling an external script specified in
            # its configuration file which injects the routes through
            # its API. Example:
            #
            #     neighbor 127.0.0.1 {
            #         router-id 192.0.2.0;
            #         local-address 127.0.0.1;
            #         local-as 2914;
            #         peer-as 2914;
            #         passive;
            #         api {
            #             processes [announce-routes];
            #         }
            #     }
            #
            #     process announce-routes {
            #         # exabgp-full-table-generator.py was generated
            #         # with mrt2exabgp -P <MRT-file>
            #         run exabgp-full-table-generator.py;
            #         encoder text;
            #     }
            #
            # exabgp-full-table-generator.py seen above is a Python
            # script which reads the "announce route ..." statements
            # from a list and writes those to stdout. However, this
            # approach is extremely slow compared to building the
            # ExaBGP configuration file with static route statements
            # beforehand and then starting the ExaBGP process.

            timestamp = None

            try:
                listening_addr, timestamp = await shutdown_wrapper(
                    build_exabgp_conf(
                        temp_dir,
                        dump_file,
                        cfg.rrc_peer_ip,
                        cfg.replace_asn,
                        cfg.replace_nh,
                        cfg.asn,
                    ),
                    stop_event,
                )
            except (FileNotFoundError, RuntimeError) as err:
                raise asyncio.CancelledError from err

            if timestamp is None:
                # Log a warning and allow the script to continue as it
                # is possible that the peer has simply announced no prefixes.
                logging.warning(
                    f"It's likely that {cfg.rrc_name.upper()} does not have "
                    f"a peer {cfg.rrc_peer_ip}."
                )

            exabgp_task = asyncio.create_task(
                run_exabgp(
                    temp_dir,
                    listening_addr,
                    cfg.listening_port,
                    run_exabgp_signal,
                )
            )
            background_tasks.append(exabgp_task)

            # Wait for run_exabgp() to signal that during the
            # preparation works for executing the ExaBGP daemon
            # an exception was raised or that the ExaBGP daemon
            # has successfully finished loading its configuration.
            await run_exabgp_signal.wait()

            if exabgp_task.done() and exabgp_task.exception() is not None:
                raise asyncio.CancelledError

            if timestamp is not None:

                try:
                    base_url, file_names = await shutdown_wrapper(
                        get_updates_file_names(cfg.rrc_name, timestamp),
                        stop_event,
                    )
                except aiohttp.ClientError as err:
                    raise asyncio.CancelledError from err

                try:
                    await shutdown_wrapper(
                        download_files(temp_dir, base_url, file_names),
                        stop_event,
                    )
                except (aiohttp.ClientError, OSError) as err:
                    raise asyncio.CancelledError from err

                logging.info(
                    "Updates files downloaded. "
                    "Starting to build ExaBGP API calls."
                )

                unique_updates = {}

                try:
                    unique_updates = await shutdown_wrapper(
                        get_updates(
                            temp_dir,
                            file_names,
                            cfg.rrc_peer_ip,
                        ),
                        stop_event,
                    )
                except RuntimeError as err:
                    raise asyncio.CancelledError from err

                logging.info(
                    "Starting to write ExaBGP API calls from updates files."
                )

                try:
                    await shutdown_wrapper(
                        write_to_api(
                            unique_updates,
                            cfg.replace_asn,
                            cfg.replace_nh,
                            os.path.join(temp_dir, "run/exabgp.in"),
                        ),
                        stop_event,
                    )
                except BrokenPipeError as err:
                    raise asyncio.CancelledError from err

            logging.info(
                "Starting to write ExaBGP API calls from RIS Live messages"
            )

            process_messages_task = asyncio.create_task(
                process_messages(
                    queue,
                    cfg.replace_asn,
                    cfg.replace_nh,
                    os.path.join(temp_dir, "run/exabgp.in"),
                )
            )
            background_tasks.append(process_messages_task)

            await stop_event.wait()

        except asyncio.CancelledError:
            pass

        for background_task in background_tasks:
            if (coro := background_task.get_coro()) is not None:
                logging.info(f"Cancelling background task {coro.__name__}")
            background_task.cancel()

        await asyncio.gather(*background_tasks, return_exceptions=True)

    finally:

        logging.info(f"Cleaning up temp dir: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
