# Measure domain name resilience and dependence


## Overview

This tool measures different aspects of domain name resilience and dependence. It has been published to enable organizations to investigate and improve their own infrastructure.

It takes one or multiple domain names as input and performs a number of different measurements, namely:

- Resilience ("single" mode): 
  - Number of autonomous systems (ASes) in which the name servers of a domain name are located.
  - Number of IP prefixes in which the name servers of a domain name are located.
  - Whether at least one of the name servers relies on BGP anycast.
  - Number of autonomous systems (ASes) in which the mail servers of a domain name are located.
  - Number of IP prefixes in which the mail servers of a domain name are located.
  - On IPv4 and IPv6.
- Concentration ("group" mode):
  - The AS for which the domain names are fully dependent on.
  - The IP prefix for which the domain names are fully dependent on.
  - The IP for which the domain names are fully dependent on.
  - The AS for which the web servers of the domain names are fully dependent on.
  - The IP prefix for the web servers of the domain names are fully dependent on.
  - The IP for which the web servers of the domain names are fully dependent on.
  - The AS for which the mail servers of the domain names are fully dependent on.
  - The IP prefix for the mail servers of the domain names are fully dependent on.
  - The IP for which the mail servers of the domain names are fully dependent on.

## Requirements

- Additional python libraries. See `requirements.txt`.
- GNU's netcat must be installed for bulk IP to AS mapping. See also Section `Third-party sources`.


## Third-party sources

The software relies on a number of third party sources.

- Quad9: The DNS resolvers of Quad9 are used to collect DNS related information. This can be changed using the `-r` option.
- https://www.team-cymru.com/ip-asn-mapping: Tool to map IPs to AS-numbers and prefixes.
- https://rpki-validator.ripe.net: API to check if a prefix has a valid ROA (tested but not part of the output).

With the above services the tested domain names, IP addresses or IP prefixes associated with the tested domain names are shared.

Additionally, the tool fetches a list of prefixes, known to be announced using anycast: 
- https://github.com/bgptools/anycast-prefixes/blob/master/anycatch-v4-prefixes.txt
- https://github.com/bgptools/anycast-prefixes/blob/master/anycatch-v6-prefixes.txt




