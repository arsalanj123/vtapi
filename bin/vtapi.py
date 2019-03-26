#!/usr/bin/env python3

project = 'vtapi'
version = '25.03.19'
author  = 'decoxviii'
license = 'MIT'

usage = """{}: {}\n
Usage:
    vtapi.py report RESOURCE [--url | --domain | --ip] [-o FILENAME]
    vtapi.py rescan RESOURCE [-o FILENAME]
    vtapi.py scan   TARGET   [--url] [-o FILENAME]

    vtapi.py (-h | --help)
    vtapi.py --version

Arguments:
    RESOURCE            The md5, sha1, sha256 of a file for which you want to retrieve the report.
    RESOURCE [option]   The URL, domain, IP for which you want to retrieve the report.
    TARGET              File that you want to scan.
    TARGET   [option]   URL that you want to scan.

Options:
    -o --output     Save output in json format.
    -h --help       Show this screen.
    --version       Show version.
""".format(project, version)

# colors:
RED, GREEN, RESET = '\033[1;91m', '\033[92m', '\033[0m'

from os import path
import json
import time
import sys


try:
    sys.path.insert(0, path.abspath(path.join(path.dirname(__file__), '..')))
    from texttable import Texttable
    from docopt import docopt
    from vtapi import banner
    from vtapi import core
except Exception as e:
    raise e


def print_result(result):
    
    table = Texttable()
    table.set_deco(Texttable.BORDER)
    table.set_cols_width([21, 40])

    sha1 = result.get('sha1', None)
    data = {
        'SHA-1:':sha1,
        'Resource:':result['resource'],
        'Detection ratio:':'{}/{}'.format(result['positives'], result['total'])
    }

    for item in data.items():
        table.add_row(item)
    print(table.draw())


    print('\n\033[1;30;47m{:26}{:32}{:10}\033[0m'.format('Antivirus', 'Result', 'Update'))
    for item in result['scans'].items():
        antivirus = item[0]
        detected  = 'malicious' if item[1]['detected'] else 'Undetected'
        update    = item[1].get('update', '00000000')
        if detected == 'malicious':
            row = '{}{:26.24}{:32.30}{:10}{}'.format(
                    RED, antivirus, item[1]['result'], update, RESET)
        else:
            row = '{:26.24}{:32}{:10}'.format(antivirus, detected, update)

        print(row)

def print_domain_result(result):
    
    table = Texttable()
    table.set_deco(Texttable.BORDER)
    table.set_cols_width([30, 31])
    
    
    categories = result.get('caexpressiontegories', None)
    drs = result.get('detected_referrer_samples', None)
    detected_urls = result.get('detected_urls', None)
    resolutions = result.get('resolutions', None)
    subdomains = result.get('subdomains', None)
    whois = result.get('whois', None)

    data = {
        'Passive DNS Replication:':len(resolutions) if resolutions else '0',
        'URLs:':len(detected_urls) if detected_urls else '0',
        'Subdomains:':len(subdomains) if subdomains else '0',
        'Files Referring:':len(drs) if drs else '0'
    }

    for item in data.items():
        table.add_row(item)
    print(table.draw())

    # URLs
    if detected_urls:
        # header
        print('\n\033[1;30;47m{:68}\033[0m'.format('URLs'))
        print('\033[1m{:22}{:12}{}\033[0m'.format('Scanned', 'Detections', 'URL'))
        # content
        for item in detected_urls:
            detection = '{}{}{}/{}'.format(RED, item['positives'], RESET, item['total'])
            print('{:22}{:23}{}'.format(
                str(item['scan_date']), 
                str(detection), 
                str(item['url'])
            ))
    
    # Files Referring
    if drs:
        # header
        print('\n\033[1;30;47m{:68}\033[0m'.format('Files Referring'))
        print('\033[1m{:15}{}\033[0m'.format('Detections', 'Sha256'))
        # content
        for item in drs:
            detection = '{}{}{}/{}'.format(RED, item['positives'], RESET, item['total'])
            print('{:26}{}'.format(str(detection), str(item['sha256'])))
    
    # Passive DNS Replication
    if resolutions:
        # header
        print('\n\033[1;30;47m{:68}\033[0m'.format('Passive DNS Replication'))
        print('\033[1m{:22}{}\033[0m'.format('Date resolved', 'IP/Hostname'))
        # content
        for item in resolutions:
            ip_or_hostname = item.get('ip_address', item.get('hostname', None))
            last_resolved  = item.get('last_resolved', None)
            print('{:22}{}'.format(str(last_resolved), str(ip_or_hostname)))

    #subdomains
    if subdomains:
        # header
        print('\n\033[1;30;47m{:68}\033[0m'.format('Subdomains'))
        # content
        print('\n'.join(subdomains))
    
    #whois
    if whois:
        # header
        print('\n\033[1;30;47m{:68}\033[0m'.format('Whois Lookup'))
        # content
        print(whois)

    # categories
    if categories:
        # header
        print('\n\033[1;30;47m{:68}\033[0m'.format('Categories'))
        # content
        print('\n'.join(categories))

def generate_json_file(result, filename):
    
    if not filename:
        filename = time.strftime('%d%m%y-%H%M%S')
    output = json.dumps(result, indent=2)
    f = open('%s.json' % filename, 'w')
    f.write(output)
    f.close()

def main():
    args  = docopt(usage, version=version)                  # get arguments
    vtapi = core.VirusTotal(args)                           # load class VirusTotal
    banner.print_banner(project, version, author)           # print sexy banner
    
    result = vtapi.get_result()
    if result['response_code']:
        if args['--domain'] or args['--ip']:
            print_domain_result(result)
        else:
            print_result(result)
    
    if args['--output']:
        filename = args['FILENAME']
        generate_json_file(result, filename)

if __name__ == "__main__":
    main()
