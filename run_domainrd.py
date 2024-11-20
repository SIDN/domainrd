#!/usr/bin/env python3
#
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

import datetime as dt
import json
import os.path
import concurrent.futures
import pandas as pd

from collector import bgp_collector, dns_collector
from metrics.domain_analyzer import get_score, print_domain_results
from metrics.group_analyzer import calculate_shared_dependencies, print_group_results
from tools.logger import logger
from tools.argparser import parser


def get_all_domain_infos(domainname: str) -> dict:
    """
    Starting point to collect information (NS, A, AAAA, MX) about domain name
    :param domainname: The domain name for which the information is collected
    :return: Dictionary containing all collected information for the domain name
    """
    # dnspython includes the '.' at the end of the domain name. Let's be consistent
    if domainname[-1] != ".":
        domainname += "."

    domain_info = {}
    measurement_date = dt.datetime.now(tz=dt.timezone.utc)

    path = ''
    if args.datadir is not None:
        path = args.datadir
    else:
        path = '.'
    if path[-1] != '/':
        path += '/'

    filepath = f"{path}{domainname[:-1].replace('.', '_')}.json"

    # Check if domain info already exists locally and if measurement is older than 24 hours
    run_measurement = False

    if os.path.exists(filepath):
        logger.info(f"Information for {domainname} exists.")
        with open(
                f"{path}{domainname[:-1].replace('.', '_')}.json",
                "r",
        ) as f:
            domain_info = json.load(f)

            if dt.datetime.strptime(
                    domain_info["measurement_date"], "%Y-%m-%d %H:%M:%S.%f%z"
            ) <= measurement_date - dt.timedelta(hours=24):
                run_measurement = True
    else:
        run_measurement = True

    # If no current measurement exists, run
    if run_measurement:
        logger.info(
            f"Information for {domainname} does not exist or is older than 24 hours - run measurements."
        )

        try:
            domain_info = dns_collector.get_domain_infos(domainname)
        except:
            raise

        domain_info["ip_info"] = bgp_collector.get_ip_infos(domain_info)
        domain_info["measurement_date"] = str(measurement_date)

        if not args.nooutput:
            with open(
                    f"{path}{domainname[:-1].replace('.', '_')}.json",
                    "w",
            ) as f:
                json.dump(domain_info, f)

    return domain_info


def run_domainrd_per_domain(domainname: str) -> list:
    """
    Starting point to calculate score and summarize taken resiliency measures per domain name
    :param domainname: The domain name for which the score and measures are calculated
    :return: List containing the score and the summary of the taken resiliency measures
    """
    logger.info(f"Running Domain Resilience & Dependence Analyzer for 1 domain name: {domainname}")

    domain_info = get_all_domain_infos(domainname)

    results = get_score(domain_info)
    if results is None:
        print(f"Cannot calculate score for {domainname} See logs for details")
    return results


def group_submit_fn(domainname: str) -> list:
    """
    Helper function to run parallel
    :param domainname: Domain name to collect infos for.
    :return: Domain infos as list
    """
    domain_info = get_all_domain_infos(domainname)
    return create_flat_data_structure(domain_info)


def run_domainrd_per_group(domainnames: list) -> None:
    """
    Reports on resources that are shared across domain names and on which the domain names fully depend
    :param domainnames: List of domain names for which the shared resources should be collected
    :return: None
    """
    logger.info(f"Running Domain Resilience & Dependence Analyzer for {len(domainnames)} domain names: {domainnames}")

    entries = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(group_submit_fn, domainnamne): domainnamne for domainnamne in
                            domainnames}
        for future in concurrent.futures.as_completed(future_to_domain):
            entries += future.result()

    columns = ["domain_name", "attribute_name", "attribute", "tld", "record_type", "ip_address", "prefix", "asn",
               "asn_description", "is_anycasted", "roa_state"]

    df_metrics = pd.DataFrame(data=entries, columns=columns)

    df_ips, df_tlds, df_prefix, df_asn = calculate_shared_dependencies(df_metrics)
    print_group_results(df_ips, df_tlds, df_prefix, df_asn, n_domains=len(domainnames))

    # Save data
    if not args.nooutput:
        path = ''
        if args.datadir is not None:
            path = args.datadir
        else:
            path = '.'
        if path[-1] != '/':
            path += '/'

        try:
            df_metrics.to_csv(f"{path}domainrd_group_results.csv", index=False)
        except FileNotFoundError:
            print(f'Cannot write output to {path}')


def create_flat_data_structure(domain_info: dict) -> list:
    """
    Helper function to turn domain info dict into flat list
    :param domain_info: Dictionary containing collected information about domain name.
    :return: Domain infos as list
    """
    entries = []
    domainname = domain_info["name"]

    if "nameservers" in domain_info:
        for nameserver in domain_info["nameservers"]:
            ns_name = nameserver["ns"]
            try:
                for record_type in ("a", "aaaa"):
                    for ip in nameserver[record_type]:
                        entry = [domainname, "name_server", ns_name, ns_name.split('.')[-2], record_type, ip, ]
                        entry += get_ip_info_from_json(domain_info, ip, "nameservers")
                        entries.append(entry)
            except Exception as e:
                print(e)
                pass

    if "a_aaaa_apex" in domain_info:
        try:
            for record_type in ("a", "aaaa"):
                for ip in domain_info["a_aaaa_apex"][record_type]:
                    entry = [domainname, "a_aaaa_apex", ip, None, record_type, ip]
                    entry += get_ip_info_from_json(domain_info, ip, "a_aaaa_apex")
                    entries.append(entry)
        except Exception as e:
            print(e)
            pass

    if "mailservers" in domain_info:
        for mailserver in domain_info["mailservers"]:
            mx_name = mailserver["mx"]
            try:
                for record_type in ("a", "aaaa"):
                    for ip in mailserver[record_type]:
                        entry = [domainname, "mail_servers", mx_name, mx_name.split('.')[-2], record_type, ip]
                        entry += get_ip_info_from_json(domain_info, ip, "mailservers")
                        entries.append(entry)
            except Exception as e:
                print(e)
                pass

    return entries


def get_ip_info_from_json(domain_info, ip, attribute):
    """
    Get a dictionary with the BGP information of an IP address:
    asn: AS number it's announced from
    prefix: IP prefix that's announced
    :param ip: IP address to get BGP information for.
    :return: A dictionary with the BGP information of an IP address (asn, ip_prefix)
    """
    for ip_info in domain_info["ip_info"][attribute]:
        if ip == ip_info["ip_address"]:
            return [ip_info["prefix"], ip_info["asn"], ip_info["as_description"], ip_info["is_anycasted"],
                    ip_info["roa_state"]]


if __name__ == "__main__":
    args = parser.parse_args()

    domainnames = []

    if args.input is None and len(args.domainname) == 0:
        print('Error: Please provide either domain name(s) via the command line or via input file (-i/--input).')

    if len(args.domainname) > 0:
        domainnames += args.domainname

    if args.input is not None:
        try:
            with open(args.input, "r") as input_file:
                domainnames += input_file.read().splitlines()
        except FileNotFoundError as e:
            print('Error: Cannot read input file. Ignored.')

    if len(domainnames) == 0:
        parser.print_help()

    else:
        if args.mode == 'single':
            domain_results = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_domain = {executor.submit(run_domainrd_per_domain, domainnamne): domainnamne for domainnamne in
                                    domainnames}
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain_result = future.result()
                    if domain_result is not None:
                        domain_results.append(domain_result)

            print_domain_results(domain_results)

        elif args.mode == 'group':
            run_domainrd_per_group(domainnames)
