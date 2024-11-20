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

import re
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rcode

from tools.logger import logger
from tools.argparser import parser

resolver = parser.parse_args().resolver
def get_name_server(domainname: str, recursion_counter=0) -> list:
    """
    Looks up the name server for the given domain name
    :param domainname: Domain name to look up the name server for
    :param recursion_counter: Make sure that look up does not run forever
    :return: List of name servers
    """
    try:
        qname = dns.name.from_text(domainname.strip())
    except:
        logger.error(f"Invalid domain name: {domainname}")
        raise

    q = dns.message.make_query(qname, dns.rdatatype.NS)
    try:

        r = dns.query.udp(q, resolver, timeout=5)
    except dns.exception.Timeout:
        logger.warning(f"Resolve NS for {domainname} timed out")
        ns_set = []
        return ns_set

    if r.rcode() == dns.rcode.NXDOMAIN:
        logger.error(f"Could not find NS records for {domainname}")
        ns_set = []

    elif r.rcode() == dns.rcode.NOERROR:
        ns_set = []

        try:
            ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
            for rr in ns_rrset:
                a_records = resolve_a_aaaa(rr.target, "a")
                aaaa_records = resolve_a_aaaa(rr.target, "aaaa")
                ns_set.append({"ns": str(rr.target), "a": a_records, "aaaa": aaaa_records})
        except KeyError:
            domainname = '.'.join(domainname.split('.')[1:-1]) + '.'
            if recursion_counter > 10 or len(domainname) == 1:
                logger.warning(f"Encountered recursion limit, stopped resolving")
                pass
            # If recursion counter as not reached max try to look for NS one level up
            return get_name_server(domainname, recursion_counter+1)
    else:
        ns_set = []

    return ns_set


def resolve_a_aaaa(domainname: str, qtype="a", recursion_counter=0) -> list:
    """
    Looks up the A or AAAA record for a given domain name
    :param domainname: Domain name to look up the record for
    :param qtype: A or AAAA
    :param recursion_counter: Make sure that look up does not run forever
    :return: List of A or AAAA records
    """

    logger.info(f"Resolve {qtype.upper()} record for {domainname}")

    qname = dns.name.from_text(str(domainname))
    a_aaaa_records = []

    rdatatype = dns.rdatatype.A
    if qtype == "a":
        rdatatype = dns.rdatatype.A
    elif qtype == "aaaa":
        rdatatype = dns.rdatatype.AAAA

    if recursion_counter > 10:
        logger.warning(f"Encountered recursion limit, stopped resolving")
        return a_aaaa_records
    else:
        q = dns.message.make_query(qname, rdatatype)
        try:
            r = dns.query.udp(q, resolver, timeout=5)
        except dns.exception.Timeout:
            logger.warning(f"Resolve {qtype.upper()} record for {domainname} timed out")
            return a_aaaa_records
        try:
            # If query returns CNAME, retry recursively
            rrset = r.find_rrset(
                r.answer, qname, dns.rdataclass.IN, dns.rdatatype.CNAME
            )
            for rr in rrset:
                return resolve_a_aaaa(str(rr), qtype, recursion_counter + 1)
        except KeyError:
            # If query does not return CNAME, try to extract A/AAAA record from rrset
            try:
                rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, rdatatype)
                for rr in rrset:
                    a_aaaa_records.append(str(rr))
                return a_aaaa_records
            except KeyError:
                logger.info(f"Resolve {qtype.upper()} record for {domainname} failed")
                return a_aaaa_records


def resolve_mx(domainname: str) -> list:
    """
    Looks up the MX record for a given domain name
    :param domainname: Domain name to look up the record for
    :return: List of MX records
    """
    logger.info(f"Resolve MX record for {domainname}")

    qname = dns.name.from_text(str(domainname))
    q = dns.message.make_query(qname, dns.rdatatype.MX)
    mx_records = []

    try:
        r = dns.query.udp(q, resolver, timeout=5)
    except dns.exception.Timeout:
        logger.warning(f"Resolve MX for {domainname} timed out")
        return mx_records

    try:
        rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.MX)
        for rr in rrset:
            if re.match("^[0-9]+ [a-zA-Z0-9-_.]+$", str(rr)):
                mx_records.append([str(rr).split()[1], int(str(rr).split()[0])])
    except KeyError:
        logger.info(f"Resolve MX record for {domainname} failed")
        pass

    return mx_records


def get_domain_infos(domainname: str) -> dict:
    """
    Collects all the relevant DNS records for a domain name
    :param domainname: Domain name to look up the record for
    :return: Dictionary containing the collected information
    """

    # Collects all information from the DNS
    domain_info = {"name": domainname}
    logger.info(f"Starting Domain Resilience & Dependence Analyzer for domain {domainname}")

    try:
        domain_info["nameservers"] = get_name_server(domainname)
    except:
        raise

    if len(domain_info["nameservers"]) == 0:
        logger.warning(f"Domain {domainname} does not exist or NS cannot be found.")

    else:
        # Only if NS query is successful
        domain_info["a_aaaa_apex"] = {}
        domain_info["a_aaaa_apex"]["a"] = resolve_a_aaaa(domainname, "a")
        domain_info["a_aaaa_apex"]["aaaa"] = resolve_a_aaaa(domainname, "aaaa")

        domain_info["a_aaaa_www"] = {}
        domain_info["a_aaaa_www"]["a"] = resolve_a_aaaa("www." + domainname, "a")
        domain_info["a_aaaa_www"]["aaaa"] = resolve_a_aaaa("www." + domainname, "aaaa")

        domain_info["mailservers"] = []
        mx_rr = resolve_mx(domainname)
        if len(mx_rr) > 0:
            # Only if MX record is present
            for mx_domainname, prio in mx_rr:
                domain_info["mailservers"].append(
                    {
                        "mx": mx_domainname,
                        "priority": prio,
                        "a": resolve_a_aaaa(mx_domainname, "a"),
                        "aaaa": resolve_a_aaaa(mx_domainname, "aaaa"),
                    }
                )

    return domain_info
