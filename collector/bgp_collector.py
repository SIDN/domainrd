# Copyright (c) 2024 SIDN Labs
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from ipaddress import (
    IPv4Address,
    IPv6Address,
    ip_network,
)
import re
import subprocess
from shutil import which
import dns.message
import dns.query
import dns.name
import pandas as pd
import requests

from tools.bgp_tools import AnycastChecker
from tools.logger import logger
from tools.argparser import parser

resolver = parser.parse_args().resolver

anycast_checker = AnycastChecker()


def get_bgp_info(ip: IPv4Address | IPv6Address) -> dict:
    """
    Get a dictionary with the BGP information of an IP address:
    asn: AS number it's announced from
    prefix: IP prefix that's announced
    :param ip: IP address to get BGP information for.
    :return: A dictionary with the BGP information of an IP address (asn, ip_prefix)
    """
    # Get ASN and prefix
    name = (
            ".".join(ip.reverse_pointer.split(".")[:-2])
            + f".origin{'6' if ip.version == 6 else ''}.asn.cymru.com"
    )
    qname = dns.name.from_text(name)
    q = dns.message.make_query(qname, dns.rdatatype.TXT)
    r = dns.query.udp(q, resolver, timeout=5)

    try:
        rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.TXT)
        answer = rrset[0]
    except (KeyError, IndexError):
        raise ValueError(f"get_announcing_as: Got no results for {ip}.")

    try:
        asn, prefix = re.findall(r"(\d+)[\s|]+([\da-f:./]+)", str(answer))[0]
        asn = int(asn)
        prefix = ip_network(prefix)
    except IndexError:
        raise ValueError(f"get_announcing_as: Got an unexpected result format for {ip}")

    # Get ASN description
    qname = dns.name.from_text(f"AS{asn}.asn.cymru.com")
    q = dns.message.make_query(qname, dns.rdatatype.TXT)
    r = dns.query.udp(q, resolver, timeout=5)
    try:
        rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.TXT)
        answer = rrset[0]
    except (KeyError, IndexError):
        raise ValueError(f"get_announcing_as: Found no ASN description for AS{asn}.")
    as_description = answer.split("|")[-1].strip()

    is_anycasted = anycast_checker.is_anycast_prefix(prefix)

    results = {
        "ip_address": str(ip),
        "asn": asn,
        "as_description": as_description,
        "prefix": prefix,
        "is_anycasted": is_anycasted,
    }

    return results


def get_bulk_bgp_info(
        ip_addresses: list[str | IPv6Address | IPv4Address],
) -> list[dict]:
    """
    Use Team Cymru's netcat bulk API to find IP prefixes and announcing ASNs given a list of IP addresses
    :param ip_addresses: list of IP addresses to gather corresponding announced prefix and ASN for
    :return: DataFrame with index: ip_address and columns: ip_prefix, asn, as_description
    """
    assert which("netcat"), "GNU's netcat must be installed."

    df = pd.DataFrame(index=ip_addresses)
    results = []

    # Send request per 10k IP addresses
    for i in range(0, len(ip_addresses), 10_000):
        logger.debug(
            f"Sending whois request for ip addresses {i + 1} - {min(len(ip_addresses), i + 10_000)}"
        )
        data_chunk = ip_addresses[i: i + 10_000]

        # whois request for cymru API
        data_to_send = "start\nprefix\nnoheader\n" + "\n".join(data_chunk) + "\nend"
        assert (
                "EOF" not in data_to_send
        ), "EOF should not be in the list of IP Addresses"  # don't break the cat :X

        command = f"cat <<EOF | netcat whois.cymru.com 43\n{data_to_send}\nEOF\n"
        response = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        ).stdout

        results.extend(
            re.findall(
                r"^(\d+)[\s|]+([\da-f.:]+)[\s|]+([\da-f.:/]+)[\s|]+(.+)$",
                response,
                re.MULTILINE,
            )
        )

    results_df = pd.DataFrame(
        results, columns=["asn", "ip_address", "prefix", "as_description"]
    ).set_index("ip_address")
    df = df.join(results_df)
    df["is_anycasted"] = df["prefix"].apply(
        lambda pfx: (
            anycast_checker.is_anycast_prefix(ip_network(pfx))
            if type(pfx) is str
            else None
        )
    )

    df["roa_state"] = df.apply(
        lambda pfx: (get_roa_state(pfx["asn"], pfx["prefix"])
                     if type(pfx["prefix"]) is str
                     else None), axis=1)

    df = df.reset_index().rename(columns={"index": "ip_address"})
    if df.isna().any().any():
        logger.warning("get_bulk_asn_prefix: result contains missing values.")

    return df.to_dict(orient="records")


def get_ip_infos(domainninfo: dict) -> dict[str, list[dict]]:
    """
    Collects IP related information
    :param domainninfo: Dictionary containing domain name information
    :return: Dictionary, containing for each record type and IP the collected information
    """
    bgp_infos_by_record_type = {}

    # Collect all distinct IP associated with this domain name
    for ip_collection in ["nameservers", "mailservers"]:
        if ip_collection in domainninfo:
            _ips = []
            for server in domainninfo[ip_collection]:
                for a_record in server.get("a", []):
                    _ips.append(a_record)
                for aaaa_record in server.get("aaaa", []):
                    _ips.append(aaaa_record)
            bgp_infos_by_record_type[ip_collection] = get_bulk_bgp_info(_ips)

    for ip_collection in ["a_aaaa_apex", "a_aaaa_www"]:
        if ip_collection in domainninfo:
            _ips = []
            for a_record in domainninfo[ip_collection].get("a", []):
                _ips.append(a_record)
            for aaaa_record in domainninfo[ip_collection].get("aaaa", []):
                _ips.append(aaaa_record)
            bgp_infos_by_record_type[ip_collection] = get_bulk_bgp_info(_ips)

    return bgp_infos_by_record_type


def get_roa_state(asn: int, prefix: str) -> str:
    """
    Looks up if the prefix has a ROA in the RPKI and whether the ROA matches the given AS number
    :param asn: AS number
    :param prefix: IP prefix
    :return: RPKI valiation state
    """
    url = f'https://rpki-validator.ripe.net/api/v1/validity/{asn}/{prefix}'
    try:
        r = requests.get(url)
        routinator_response = r.json()
        if 'validated_route' in routinator_response:
            return routinator_response['validated_route']['validity']['state']
        else:
            return 'unknown'

    except Exception as e:
        logger.error(f'Could not fetch roa state for {asn}, {prefix}: {e}')
