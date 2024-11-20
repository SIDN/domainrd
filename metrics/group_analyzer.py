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

import math
from collections import defaultdict
import pandas as pd
from tools.logger import logger
from tools.argparser import parser

args = parser.parse_args()

def calculate_shared_dependencies(df) -> (pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame):
    """
    Calculates the shared dependencies between domain names
    :param df: Pandas data frame containing all resources used by the domain names.
    :return: Four Pandas data frames, containing the shared IPs, TLDs, prefixes and ASes
    """
    # IP addresses
    df_ips = (df
              .groupby(['ip_address', 'attribute_name'])[['domain_name']]
              .nunique()
              .sort_values(by=['domain_name']))

    df_ips['fully_dependent'] = 0
    df_ips['fully_dependent_domains'] = ''
    df_ips['partially_dependent'] = 0
    df_ips['partially_dependent_domains'] = ''

    df_tmp = df.groupby(['domain_name', 'attribute_name'])['ip_address'].nunique()

    for (domain_name, attribute_name), count in df_tmp.items():
        ip_addresses = (df[(df['domain_name'] == domain_name)
                           & (df['attribute_name'] == attribute_name)]['ip_address'].drop_duplicates())
        for ip_address in ip_addresses:
            if count == 1:
                df_ips.loc[(ip_address, attribute_name), 'fully_dependent'] += 1
                df_ips.loc[(ip_address, attribute_name), 'fully_dependent_domains'] += domain_name + ', '
            else:
                df_ips.loc[(ip_address, attribute_name), 'partially_dependent'] += 1
                df_ips.loc[(ip_address, attribute_name), 'partially_dependent_domains'] += domain_name + ', '

    df_ips = (df_ips[(df_ips['domain_name'] >= 1)]
              .sort_values(['fully_dependent', 'domain_name'], ascending=[False, False]))

    # Top level domain names
    df_tlds = (df
               .dropna(subset=['tld'])
               .groupby(['tld', 'attribute_name'])[['domain_name']]
               .nunique()
               .sort_values(by=['domain_name']))

    df_tlds['fully_dependent'] = 0
    df_tlds['fully_dependent_domains'] = ''
    df_tlds['partially_dependent'] = 0
    df_tlds['partially_dependent_domains'] = ''

    df_tmp = (df
              .dropna(subset=['tld'])
              .groupby(['domain_name', 'attribute_name'])['tld']
              .nunique())

    for (domain_name, attribute_name), count in df_tmp.items():
        tlds = (df[(df['domain_name'] == domain_name)
                   & (df['attribute_name'] == attribute_name)]['tld'].drop_duplicates())
        for tld in tlds:
            if count == 1:
                df_tlds.loc[(tld, attribute_name), 'fully_dependent'] += 1
                df_tlds.loc[(tld, attribute_name), 'fully_dependent_domains'] += domain_name + ', '
            else:
                df_tlds.loc[(tld, attribute_name), 'partially_dependent'] += 1
                df_tlds.loc[(tld, attribute_name), 'partially_dependent_domains'] += domain_name + ', '

    df_tlds = (df_tlds[(df_tlds['domain_name'] >= 1)]
               .sort_values(['fully_dependent', 'domain_name'], ascending=[False, False]))

    # Prefixes

    df_prefix = (df
                 .groupby(['prefix', 'attribute_name'])[['domain_name']]
                 .nunique()
                 .sort_values(by=['domain_name']))

    df_prefix['fully_dependent'] = 0
    df_prefix['fully_dependent_domains'] = ''
    df_prefix['partially_dependent'] = 0
    df_prefix['partially_dependent_domains'] = ''

    df_tmp = (df
              .groupby(['domain_name', 'attribute_name'])['prefix']
              .nunique())

    for (domain_name, attribute_name), count in df_tmp.items():
        prefixes = (df[(df['domain_name'] == domain_name)
                       & (df['attribute_name'] == attribute_name)]['prefix'].drop_duplicates())
        for prefix in prefixes:
            if not pd.isna(prefix):
                if count == 1:
                    df_prefix.loc[(prefix, attribute_name), 'fully_dependent'] += 1
                    df_prefix.loc[(prefix, attribute_name), 'fully_dependent_domains'] += domain_name + ', '
                else:
                    df_prefix.loc[(prefix, attribute_name), 'partially_dependent'] += 1
                    df_prefix.loc[(prefix, attribute_name), 'partially_dependent_domains'] += domain_name + ', '


    df_prefix = (df_prefix[df_prefix['domain_name'] >= 1]
                 .sort_values(['fully_dependent', 'domain_name'], ascending=[False, False]))

    # Autonomous Systems

    df_asn = (df
              .groupby(['asn', 'attribute_name'])[['domain_name']]
              .nunique()
              .sort_values(by=['domain_name']))

    df_asn['fully_dependent'] = 0
    df_asn['fully_dependent_domains'] = ''
    df_asn['partially_dependent'] = 0
    df_asn['partially_dependent_domains'] = ''

    df_tmp = (df
              .groupby(['domain_name', 'attribute_name'])['asn']
              .nunique())

    for (domain_name, attribute_name), count in df_tmp.items():
        asns = (df[(df['domain_name'] == domain_name)
                   & (df['attribute_name'] == attribute_name)]['asn'].drop_duplicates())
        for asn in asns:
            if not pd.isna(asn):
                if count == 1:
                    df_asn.loc[(asn, attribute_name), 'fully_dependent'] += 1
                    df_asn.loc[(asn, attribute_name), 'fully_dependent_domains'] += domain_name + ', '
                else:
                    df_asn.loc[(asn, attribute_name), 'partially_dependent'] += 1
                    df_asn.loc[(asn, attribute_name), 'partially_dependent_domains'] += domain_name + ', '

    df_asn = (pd
              .merge(df_asn[df_asn['domain_name'] >= 1].reset_index(),
                     df[['asn', 'asn_description']].drop_duplicates(),
                     left_on=['asn'],
                     right_on=['asn'],
                     how='left')
              .set_index(['asn', 'attribute_name'])
              .sort_values(['fully_dependent', 'domain_name'], ascending=[False, False])
              )

    return df_ips, df_tlds, df_prefix, df_asn


def print_group_results(df_ips, df_tlds, df_prefix, df_asn, n_domains) -> None:
    """
    Prints the resources shared by the domain names
    :param df_ips: Pandas data frame containing shared IPs.
    :param df_tlds: Pandas data frame containing shared TLDs. Currently not used.
    :param df_prefix: Pandas data frame containing shared prefixes.
    :param df_asn: Pandas data frame containing shared ASes.
    :param n_domains: Number of compared domain names.
    :return: Four Pandas data frames, containing the shared IPs, TLDs, prefixes and ASes
    """
    also_partial = args.partial

    # metrics = [['autonomous systems', df_asn], ['network prefixes', df_prefix], ['IP addresses', df_ips],
    #            ['Top Level Domain Names', df_tlds]]

    metrics = [['autonomous systems', df_asn], ['network prefixes', df_prefix], ['IP addresses', df_ips]]

    attributes_dict = {'name_server': 'Name Server', 'a_aaaa_apex': 'IPv4 and IPv6 address',
                       'mail_servers': 'Mail server'}
    group_results = []

    for attribute_name in attributes_dict.keys():

        for metric in metrics:
            df_metric = metric[1]

            try:
                df_tmp = df_metric.loc[(slice(None), attribute_name),]

                for (ip_address, attribute_name), values in df_tmp[df_tmp['fully_dependent'] >= 1].iterrows():
                    if metric[0] == 'autonomous systems':
                        group_results.append(
                            [attributes_dict[attribute_name], 'full', f'{ip_address} (AS{values["asn_description"]})',
                             f'{values['fully_dependent']}/{n_domains}',
                             values["fully_dependent_domains"][:-2]])
                    else:
                        group_results.append([attributes_dict[attribute_name], 'full', f'{ip_address}',
                                              f'{values['fully_dependent']}/{n_domains}',
                                              values["fully_dependent_domains"][:-2]])

                if also_partial:

                    for (ip_address, attribute_name), values in df_tmp[
                        df_tmp['partially_dependent'] >= 1].iterrows():
                        if metric[0] == 'autonomous systems':
                            group_results.append(
                                [attributes_dict[attribute_name], 'partial',
                                 f'{ip_address} (AS{values["asn_description"]})',
                                 f'{values['partially_dependent']}/{n_domains}',
                                 values["partially_dependent_domains"][:-2]])
                        else:
                            group_results.append([attributes_dict[attribute_name], 'partial', f'{ip_address}',
                                                  f'{values['partially_dependent']}/{n_domains}',
                                                  values["partially_dependent_domains"][:-2]])

            except KeyError as e:
                pass

    if not also_partial:
        print('\n# Domain names fully dependent on the following resources\n')

        print(pd.DataFrame(group_results, columns=['Type', 'Dependency', 'Resource', 'Count', 'Domain names'])
              .drop('Dependency', axis=1)
              .to_markdown(index=False)
              )
    else:
        print('\n# Domain names fully and partially dependent on the following resources\n')

        print(pd.DataFrame(group_results, columns=['Type', 'Dependency', 'Resource', 'Count', 'Domain names'])
              .to_markdown(index=False)
              )
