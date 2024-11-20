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

import argparse

parser = argparse.ArgumentParser(
    prog='Resilliency Analyzer',
    description='Tests the resilience of Internet infrastructure against outages and attacks',
)

parser.add_argument('domainname', nargs='*', help='Add one more more domain name or define input file (-i|--input).')
parser.add_argument('-m', '--mode', choices=['single', 'group'], default='single', help='Default "single". Whether the '
                                                                                        'resiliency of individual domain '
                                                                                        'names should be analyzed or whether '
                                                                                        'the dependencies of the domain names '
                                                                                        'as a group should be analyzed.')

parser.add_argument('--partial', action='store_true', help='When in group mode, also analyze partial dependencies. '
                                                           'Default off.')

parser.add_argument('-i', '--input', help='Path to file with domain names. Each domain name on a new line. Can be '
                                          'combined with domain names passed as arguments.')

parser.add_argument('-d', '--datadir', help='Path where to look for and save the output files. Defaults to current '
                                            'working directory.')

parser.add_argument('--nooutput', action='store_true', help='Do not save the output.')

parser.add_argument('-r', '--resolver', default='9.9.9.9', help='Define the recursive resolver. Default is 9.9.9.9.')
