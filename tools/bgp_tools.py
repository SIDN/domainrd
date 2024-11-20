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

import ipaddress
import requests
from tools.logger import logger

def get_anycast_ip_addresses(
    ipv: int,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Loads list of IP prefixes that are distributed with anycast from the BGP tools repository on github
    :param ipv: IP version. 4 or 6
    :return: List of IP prefixes that are distributed with anycast
    """
    logger.info(f"Collecting IPv{ipv} anycast addresses from bgptools repository")
    anycast_ips = []

    r = requests.get(
        f"https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v{ipv}-prefixes.txt"
    )
    if r.ok:
        for r in r.text.split():
            try:
                anycast_ips.append(ipaddress.ip_network(r.strip()))
            except ValueError as e:
                logger.error(e)
                pass
        if len(anycast_ips) == 0:
            raise Exception(f"No IPv{ipv} anycast addresses found")
    else:
        raise Exception(f"Could not get IPv{ipv} addresses from bgptools repository")

    return anycast_ips


class AnycastChecker:
    """
    Class that enables us to check if an IP prefix is distributed using anycast
    """
    def __init__(self):
        logger.debug("Creating AncastChecker")

        self.anycast_ips_v4 = get_anycast_ip_addresses(4)
        self.anycast_ips_v6 = get_anycast_ip_addresses(6)

    def is_anycast_prefix(
        self, prefix: [ipaddress.IPv4Network | ipaddress.IPv6Network]
    ) -> bool:
        """
        Checks if an IP prefix is distributed using anycast
        :param prefix: IP prefix. IPv4 or IPv6
        :return: True if distributed with anycast, False otherwise
        """
        if prefix.version == 4:
            for network in self.anycast_ips_v4:
                if prefix == network:
                    return True
        elif prefix.version == 6:
            for network in self.anycast_ips_v6:
                if prefix == network:
                    return True
        return False
