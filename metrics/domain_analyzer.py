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

import pandas as pd
from tools.logger import logger
from tools.argparser import parser

args = parser.parse_args()


def has_different_origins(domaininfo: dict, attribute: str) -> ((bool, int), (bool, int)):
    """
    Checks if domain name has sufficient unique origin ASes on IPv4 and IPv6.
    :param domaininfo: Dictionary containing the information about a domain name
    :param attribute: Attribute for which the check should be performed (nameservers, mailservers).
    :return: Returns 2 tuples, one for IPv4 one for IPv6. The first entry is True or False, depending on whether two
    or more ASes are found. The second entry is the number of unique ASes found.
    """

    logger.info(f"Check for distinct origin ASes of {attribute}")
    assert attribute in (
        "nameservers",
        "mailservers",
    ), "has_different_origins is only applicable to nameservers and mailservers"

    origins_a, origins_aaaa = set(), set()

    for bgp_info in domaininfo["ip_info"][attribute]:
        if ":" in bgp_info["ip_address"]:
            origins_aaaa.add(bgp_info["asn"])
        else:
            origins_a.add(bgp_info["asn"])

    return (len(origins_a) > 1, len(origins_a)), (
        len(origins_aaaa) > 1,
        len(origins_aaaa),
    )


def has_different_tlds(domaininfo: dict) -> (bool, int):
    """
    Checks if domain name has name servers in different TLDs
    :param domaininfo: Dictionary containing the information about a domain name
    :return: Returns 2 tuples, one for IPv4 one for IPv6. The first entry is True or False, depending on whether two
    or more ASes are found. The second entry is the number of unique ASes found.
    """
    #
    # Returns true if this is the case or if TLD of name server is the same as TLD of tested domain name
    logger.info(f"Check for at least two different TLDs for name servers")

    tlds = set()

    for ns_info in domaininfo["nameservers"]:
        tlds.add(ns_info["ns"].split('.')[-2])

    if list(tlds)[0] == domaininfo["name"].split('.')[-2] or len(tlds) > 1:
        return True, len(tlds)
    else:
        return False, len(tlds)


def has_anycast_ns(domaininfo: dict) -> ((bool, int), (bool, int)):
    """
    Checks if domain name has at least one name servers relying on anycast
    :param domaininfo: Dictionary containing the information about a domain name
    :return: Returns 2 tuples, one for IPv4 one for IPv6. The first entry is True or False, depending on whether
    at least one NS is found that is using anycast. The second entry is the number of anycasted NSes.
    """
    # Checks if domain name has at least one anycasted nameserver address on IPv4 and IPv6.
    # Returns 2 tuples, one for IPv4 one for IPv6.
    # Each tuple consists out of boolean indicating whether test has passed and the number of tested IPs.
    logger.debug(f"Running has_anycast_ns")

    anycast_a, anycast_aaaa = set(), set()

    for bgp_info in domaininfo["ip_info"]["nameservers"]:
        if ":" in bgp_info["ip_address"]:
            anycast_aaaa.add(bgp_info["is_anycasted"])
        else:
            anycast_a.add(bgp_info["is_anycasted"])

    return (True in anycast_a, len(anycast_a)), (
        True in anycast_aaaa,
        len(anycast_aaaa),
    )


def has_different_prefixes(domaininfo: dict, attribute: str):
    """
    Checks if domain name has sufficient unique prefixes on IPv4 and IPv6.
    :param domaininfo: Dictionary containing the information about a domain name
    :param attribute: Attribute for which the check should be performed (nameservers, mailservers).
    :return: Returns 2 tuples, one for IPv4 one for IPv6. The first entry is True or False, depending on whether
    two or more unique  prefixes are found. The second one contains the number of unique prefixes.
    """
    # Returns 2 tuples, one for IPv4 one for IPv6.
    # Each tuple consists out of boolean indicating whether test has passed and the number of unique prefixes.
    logger.info(f"Check for distinct prefixes for {attribute}")
    assert attribute in (
        "nameservers",
        "mailservers",
    ), "has_different_prefixes is only applicable to nameservers and mailservers"

    prefix_a, prefix_aaaa = set(), set()

    for bgp_info in domaininfo["ip_info"][attribute]:
        if ":" in bgp_info["ip_address"]:
            prefix_aaaa.add(bgp_info["prefix"])
        else:
            prefix_a.add(bgp_info["prefix"])

    return (len(prefix_a) > 1, len(prefix_a)), (
        len(prefix_aaaa) > 1,
        len(prefix_aaaa),
    )


def has_valid_roa(domaininfo: dict, attribute: str):
    """
    Checks if domain name has prefix with valid ROA.
    :param domaininfo: Dictionary containing the information about a domain name
    :param attribute: Attribute for which the check should be performed.
    :return: Returns 2 tuples, one for IPv4 one for IPv6. The first entry is True or False, depending on whether
    at least one prefix with a valid ROA was found. The second one contains the number of prefixes with a valid ROA.
    """
    logger.info(f"Check if prefix has valid ROA")

    prefix_a, prefix_aaaa = set(), set()

    for bgp_info in domaininfo["ip_info"][attribute]:
        if ":" in bgp_info["ip_address"]:
            if bgp_info["roa_state"] == 'valid':
                prefix_aaaa.add(bgp_info["prefix"])
        else:
            if bgp_info["roa_state"] == 'valid':
                prefix_a.add(bgp_info["prefix"])

    return (len(prefix_a) > 0, len(prefix_a)), (
        len(prefix_aaaa) > 0,
        len(prefix_aaaa),
    )


def get_score(domain_info) -> None:
    """
    Calculates score for domain name.
    :param domaininfo: Dictionary containing the information about a domain name
    :return: Returns a list containing the domain name, the caluclated score, and which checks have passed.
    """
    # Calculates score for domain name
    # Returns scored points and maximum number of points achievable for this domain name
    logger.info(f"calculate domain score")

    score = 0
    max_score = 0
    results = []

    ipv4, ipv6 = has_different_origins(domain_info, "nameservers")
    logger.info(f"Different origins (NS): {ipv4}, {ipv6}")

    if ipv4[1] == 0 and ipv6[1] == 0:
        logger.warning("No nameserver, will not calculate score")
        return None
    max_score += 2
    if ipv4[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers NOT in different autonomous systems (IPv4).')
        results.append(False)
    if ipv6[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers NOT in different autonomous systems (IPv6).')
        results.append(False)

    ipv4, ipv6 = has_different_prefixes(domain_info, "nameservers")
    logger.info(f"Different prefixes (NS): {ipv4}, {ipv6}")
    max_score += 2
    if ipv4[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers are NOT reachable via different subnets(IPv4).')
        results.append(False)
    if ipv6[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers are NOT reachable via different subnets (IPv6).')
        results.append(False)

    ipv4, ipv6 = has_anycast_ns(domain_info)
    logger.info(f"Has anycast NS: {ipv4}, {ipv6}")
    max_score += 2
    if ipv4[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers NOT distributed using anycast (IPv4).')
        results.append(False)
    if ipv6[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers NOT distributed using anycast (IPv6).')
        results.append(False)

    ipv4, ipv6 = has_valid_roa(domain_info, "nameservers")
    logger.info(f"Has valid ROA: {ipv4}, {ipv6}")
    max_score += 2
    if ipv4[0]:
        score += 1
        results.append(True)
    else:
        results.append(False)
    if ipv6[0]:
        score += 1
        results.append(True)
    else:
        results.append(False)

    tlds = has_different_tlds(domain_info)
    logger.info(f"Has NSes in different TLDs: {tlds}")
    max_score += 1
    if tlds[0]:
        score += 1
        results.append(True)
    else:
        # print('No points: Name servers NOT distributed using anycast (IPv4).')
        results.append(False)

    ipv4, ipv6 = has_different_origins(domain_info, "mailservers")
    logger.info(f"Different origins (MX): {ipv4}, {ipv6}")
    if ipv4[1] > 0 or ipv6[1] > 0:
        max_score += 2
        if ipv4[0]:
            score += 1
            results.append(True)
        else:
            # print('No points: Mail servers NOT in different autonomous systems (IPv4).')
            results.append(False)
        if ipv6[0]:
            score += 1
            results.append(True)
        else:
            # print('No points: Mail servers NOT in different autonomous systems (IPv6).')
            results.append(False)

        ipv4, ipv6 = has_different_prefixes(domain_info, "mailservers")
        logger.info(f"Different prefixes (MX): {ipv4}, {ipv6}")
        max_score += 2
        if ipv4[0]:
            score += 1
            results.append(True)
        else:
            results.append(False)
            # print('No points: Mail servers are NOT reachable via different subnets (IPv4).')
        if ipv6[0]:
            results.append(True)
            score += 1
        else:
            results.append(False)
            # print('No points: Mail servers are NOT reachable via different subnets (IPv6).')

        ipv4, ipv6 = has_valid_roa(domain_info, "mailservers")
        logger.info(f"Has valid ROA: {ipv4}, {ipv6}")
        if ipv4[1] > 0 or ipv6[1] > 0:
            max_score += 2
            if ipv4[0]:
                score += 1
                results.append(True)
            else:
                results.append(False)
            if ipv6[0]:
                results.append(True)
                score += 1
            else:
                results.append(False)

    else:
        results += [None, None, None, None, None, None]

    return [domain_info['name'], round(score / max_score * 10, 1)] + results


def print_domain_results_long(domain_results: list) -> None:
    """
    Prints a table with the scores for each domain name. Extended version, currently not used.
    :param domain_results: List of domain infos.
    """
    print('''
    # Legend
    - NS orig:\t\tName servers are located in different autonomous systems.
    - NS prefixes:\tName servers are located in different network prefixes.
    - NS any:\t\tAt least one name server is distributed using anycast.
    - NS ROAs:\t\tAt least one name server is protected against basic route hijacking (with ROAs). 
    - NS tld:\t\tName server names rely on at least two different TLDs.
    - MX orig:\t\tMail servers are located in different autonomous systems.
    - MX prefixes:\tMail servers are located in different network prefixes.
    - MX ROAs:\t\tAt least one mail server is protected against basic route hijacking (with ROAs). 

    ''')

    columns = ['Domain Name', 'Score (out of 10)',
               'NS orig (v4)', 'NS orig (v6)', 'NS prefixes (v4)', 'NS prefixes (v6)', 'NS any (v4)', 'NS any (v6)',
               'NS ROAs (v4)', 'NS ROAs (v6)', 'NS tld',
               'MX orig (v4)', 'MX orig (v6)', 'MX prefixes (v4)', 'MX prefixes (v6)', 'MX ROAs (v4)', 'MX ROAs (v6)']

    df_domain_results = (pd.DataFrame(domain_results, columns=columns)
                         .replace([True, False], ['Yes', 'No']))

    print(df_domain_results.to_markdown(index=False))

    if not args.nooutput:
        path = ''
        if args.datadir is not None:
            path = args.datadir
        else:
            path = '.'
        if path[-1] != '/':
            path += '/'

        try:
            df_domain_results.to_csv(f"{path}domainrd_single_results.csv", index=False)
        except FileNotFoundError:
            print(f'Cannot write output to {path}')

def print_domain_results(domain_results: list):
    """
    Prints a table with the scores for each domain name. Short version.
    :param domain_results: List of domain infos.
    """

    print('''
    # Legend
    - NS orig:\t\tName servers are located in different autonomous systems.
    - NS prefixes:\tName servers are located in different network prefixes.
    - NS any:\t\tAt least one name server is distributed using anycast.
    - MX orig:\t\tMail servers are located in different autonomous systems.
    - MX prefixes:\tMail servers are located in different network prefixes.

    ''')

    columns = ['Domain Name', 'Score\n(out of 10)',
               'NS orig\n(v4)', 'NS orig\n(v6)', 'NS prefixes\n(v4)', 'NS prefixes\n(v6)', 'NS any\n(v4)', 'NS any\n(v6)',
               'NS ROAs\n(v4)', 'NS ROAs\n(v6)', 'NS tld',
               'MX orig\n(v4)', 'MX orig\n(v6)', 'MX prefixes\n(v4)', 'MX prefixes\n(v6)', 'MX ROAs\n(v4)', 'MX ROAs\n(v6)']


    df_domain_results = (pd.DataFrame(domain_results, columns=columns)
                         .replace([True, False], ['Yes', 'No']))

    columns_short = ['Domain Name', 'Score\n(out of 10)',
               'NS orig\n(v4)', 'NS prefixes\n(v4)',  'NS any\n(v4)', 'NS orig\n(v6)',  'NS prefixes\n(v6)', 'NS any\n(v6)',
               # 'MX orig\n(v4)', 'MX prefixes\n(v4)', 'MX orig\n(v6)',  'MX prefixes\n(v6)'
                     ]

    df_domain_results = df_domain_results[columns_short].sort_values(['Domain Name'])

    print(df_domain_results.to_markdown(index=False))

    if not args.nooutput:
        path = ''
        if args.datadir is not None:
            path = args.datadir
        else:
            path = '.'
        if path[-1] != '/':
            path += '/'

        try:
            df_domain_results.to_csv(f"{path}domainrd_single_results.csv", index=False)
        except FileNotFoundError:
            print(f'Cannot write output to {path}')
